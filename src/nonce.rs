//! Nonce generation and commitment for MuSig1.
//!
//! This module implements both random and deterministic nonce creation (RFC6979-style),
//! commitment and reveal message structures for the two-round nonce exchange,
//! verification of commitments, and aggregation of public nonces with even‑Y normalization.

use crypto_rs::schnorr::tagged_hash;
use crypto_rs::secp256k1::{Secp256k1Point, Secp256k1Scalar};
use hmac::{Hmac, Mac};
use rand::TryRngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use thiserror::Error;

/// Errors for nonce operations
#[derive(Debug, Error, PartialEq)]
pub enum NonceError {
    /// Scalar reduced to zero (after retries)
    #[error("nonce scalar is zero")]
    ZeroScalar,
    /// Empty nonce list
    #[error("Empty nonce list")]
    NoNonces,
    /// Input point bytes were invalid or correspond to identity
    #[error("invalid public nonce point")]
    InvalidPoint,
    /// Input point bytes were of wrong length
    #[error("wrong length")]
    WrongLength,
}

/// Round-1 commit message to broadcast: `t_i = H_com(R_i_bytes)`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Commit(pub [u8; 32]);

/// Round-2 reveal message to broadcast: compresed `R_i = k_i * G`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reveal(pub Vec<u8>);

impl Reveal {
    /// Create a new reveal from exactly 33 or 66 bytes.
    pub fn new(bytes: Vec<u8>) -> Result<Self, NonceError> {
        match bytes.len() {
            33 | 66 => Ok(Reveal(bytes)),
            _ => Err(NonceError::WrongLength),
        }
    }

    /// Helper to “decode” a Reveal into a single Secp256k1Point:
    ///  • If it’s 33 bytes, treat it as a single compressed point.
    ///  • If it’s 66 bytes, split into two 33-byte chunks, parse both, and return their sum.
    pub fn decode_reveal(r: &Reveal) -> Secp256k1Point {
        let bytes = &r.0;
        match bytes.len() {
            33 => {
                // MuSig 1 style: exactly one 33‐byte compressed point
                let arr: [u8; 33] = bytes[..33]
                    .try_into()
                    .expect("Reveal must be exactly 33 bytes");
                Secp256k1Point::from_bytes_compressed(&arr).expect("Invalid 33-byte reveal point")
            }
            66 => {
                // MuSig 2 style: two concatenated 33‐byte compressed points
                let arr1: [u8; 33] = bytes[0..33]
                    .try_into()
                    .expect("First half must be 33 bytes");
                let arr2: [u8; 33] = bytes[33..66]
                    .try_into()
                    .expect("Second half must be 33 bytes");

                // Decompress the first half—if that fails, panic (unexpected).
                let p1 = Secp256k1Point::from_bytes_compressed(&arr1)
                    .expect("Invalid first 33-byte half");

                // For the second half, we allow either:
                //  • All zeros (identity), or
                //  • A valid compressed point, or
                //  • Anything else ⇒ treat as identity (no panic).
                let p2 = if arr2 == [0u8; 33] {
                    Secp256k1Point::identity()
                } else {
                    Secp256k1Point::from_bytes_compressed(&arr2)
                        .unwrap_or_else(|| Secp256k1Point::identity())
                };

                p1 + &p2
            }
            _ => panic!("Reveal must be length 33 or 66"),
        }
    }
}

/// Holds a single signer’s nonce state (secret, public, and commitment).
#[derive(Clone)]
pub struct NonceCommitment {
    /// Secret scalar `k_i`.
    pub secret: Secp256k1Scalar,
    /// Public nonce point `R_i = k_i * G`.
    pub pub_nonce: Secp256k1Point,
    /// Commitment `t_i = H_com(R_i_bytes)`.
    pub commitment: [u8; 32],
}

impl NonceCommitment {
    /// Internal constructor: compute public point and its commitment.
    fn from_secret(k: Secp256k1Scalar) -> Self {
        let pub_nonce = &Secp256k1Point::generator() * &k;
        let bytes = pub_nonce.to_bytes_compressed();
        let commitment = tagged_hash("MuSig/nonce_commit", &bytes);
        NonceCommitment {
            secret: k,
            pub_nonce,
            commitment,
        }
    }

    /// Produce a fresh random nonce. Retries up to 5 times to avoid zero scalar.
    pub fn random() -> Result<Self, NonceError> {
        for _ in 0..5 {
            let mut buf = [0u8; 32];
            OsRng.try_fill_bytes(&mut buf).unwrap();
            let k = Secp256k1Scalar::from_bytes_be(&buf);
            if k.is_zero() {
                continue;
            }
            return Ok(Self::from_secret(k));
        }
        Err(NonceError::ZeroScalar)
    }

    /// Derive a deterministic nonce via HMAC-SHA256(sk, msg), with fallback to avoid zero.
    pub fn deterministic(sk: &Secp256k1Scalar, msg: &[u8]) -> Result<Self, NonceError> {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(&sk.to_bytes_be())
            .expect("HMAC can accept key of any length");
        mac.update(msg);
        let out = mac.finalize().into_bytes();
        // Map to scalar and avoid zero
        let mut k = Secp256k1Scalar::from_bytes_be(&out);
        if k.is_zero() {
            k = Secp256k1Scalar::one();
        }
        Ok(Self::from_secret(k))
    }

    /// flip both secret and public if aggregate `R_agg` was negated.
    pub fn apply_flip(&mut self, flip: bool) {
        if flip {
            self.secret = -self.secret.clone();
            self.pub_nonce = -self.pub_nonce.clone();
        }
    }

    /// Extract round-1 commit message.
    pub fn commit(&self) -> Commit {
        Commit(self.commitment)
    }

    /// Extract round-2 reveal message.
    pub fn reveal(&self) -> Reveal {
        Reveal(self.pub_nonce.to_bytes_compressed().to_vec())
    }

    /// Verify that the commitment matches the given public nonce.
    pub fn verify(&self) -> bool {
        let bytes = self.pub_nonce.to_bytes_compressed();
        tagged_hash("MuSig/nonce_commit", &bytes) == self.commitment
    }
}

/// Aggregate a slice of round-2 `Reveal`s into a single nonce `R_agg`.
///
/// - If *all* reveals are 33 bytes long (MuSig 1 mode),
///   sum each 33-byte point into `agg1`, normalize it (flip if odd-Y),
///   and return a *33-byte* `Reveal(compressed(agg1))`.
///
/// - Otherwise (if any reveal is 66 bytes, MuSig 2 mode),
///   interpret each 66-byte `Reveal` as two 33-byte halves `(R1_i, R2_i)`,
///   sum all `R1_i → agg1` and all `R2_i → agg2`, normalize both halves if needed,
///   and return a *66-byte* `Reveal = compressed(agg1) ‖ compressed(agg2)`.
///
/// Returns `Ok((Reveal, flipped_flag))` or an appropriate `Err(…)`.
///
pub fn aggregate_nonces(reveals: &[Reveal]) -> Result<(Reveal, bool), NonceError> {
    if reveals.is_empty() {
        return Err(NonceError::NoNonces);
    }

    // Accumulators for the two halves:
    let mut agg1 = Secp256k1Point::identity();
    let mut agg2 = Secp256k1Point::identity();
    // Rename saw_66 → has_double_reveal
    let mut has_double_reveal = false;

    for Reveal(bytes) in reveals {
        match bytes.len() {
            33 => {
                // MuSig 1 style: exactly one compressed point → add to agg1
                let arr: [u8; 33] = bytes[..33]
                    .try_into()
                    .map_err(|_| NonceError::WrongLength)?;
                let R =
                    Secp256k1Point::from_bytes_compressed(&arr).ok_or(NonceError::InvalidPoint)?;
                agg1 = agg1 + &R;
                // agg2 remains identity
            }
            66 => {
                // MuSig 2 style: split into two halves
                has_double_reveal = true;
                let arr1: [u8; 33] = bytes[0..33]
                    .try_into()
                    .map_err(|_| NonceError::WrongLength)?;
                let arr2: [u8; 33] = bytes[33..66]
                    .try_into()
                    .map_err(|_| NonceError::WrongLength)?;
                let R1 =
                    Secp256k1Point::from_bytes_compressed(&arr1).ok_or(NonceError::InvalidPoint)?;
                let R2 =
                    Secp256k1Point::from_bytes_compressed(&arr2).ok_or(NonceError::InvalidPoint)?;
                agg1 = agg1 + &R1;
                agg2 = agg2 + &R2;
            }
            _ => {
                // Wrong length
                return Err(NonceError::WrongLength);
            }
        }
    }

    // If we never saw any 66-byte reveal, we are in MuSig 1 mode.
    if !has_double_reveal {
        // Normalize agg1 to even-Y
        let flip = agg1.y_is_odd();
        if flip {
            agg1 = -agg1;
        }
        // Return a 33-byte reveal = compressed(agg1)
        let out33 = agg1.to_bytes_compressed().to_vec();
        return Ok((Reveal(out33), flip));
    }

    // Otherwise, MuSig 2 mode: both agg1 and agg2 matter.
    // Normalize both halves by checking agg1’s parity.
    let flip = agg1.y_is_odd();
    if flip {
        agg1 = -agg1;
        agg2 = -agg2;
    }
    // Return a 66-byte reveal = compressed(agg1) ‖ compressed(agg2)
    let mut out66 = Vec::with_capacity(66);
    out66.extend_from_slice(&agg1.to_bytes_compressed());
    if agg2 == Secp256k1Point::identity() {
        out66.extend_from_slice(&[0u8; 33]);
    } else {
        out66.extend_from_slice(&agg2.to_bytes_compressed());
    }
    Ok((Reveal(out66), flip))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_rs::secp256k1::{Secp256k1Point, Secp256k1Scalar};

    /// Helper to get the point out of a Reveal.
    fn decode_reveal(r: &Reveal) -> Secp256k1Point {
        let Reveal(bytes) = r.clone();
        let bytes: &[u8; 33] = bytes
            .as_slice()
            .try_into()
            .expect("Reveal must be 33 bytes");
        Secp256k1Point::from_bytes_compressed(bytes).unwrap()
    }

    /// Helper to get the raw commitment bytes.
    #[allow(dead_code)]
    fn decode_commit(c: &Commit) -> [u8; 32] {
        let Commit(bytes) = *c;
        bytes
    }

    #[test]
    fn test_random_nonzero() {
        let n = NonceCommitment::random().unwrap();
        // secret must be non-zero
        assert!(!n.secret.is_zero());
        // public = k·G must not be the identity
        let R = decode_reveal(&n.reveal());
        assert!(R != Secp256k1Point::identity());
    }

    #[test]
    fn random_nonce_roundtrip() {
        let n = NonceCommitment::random().unwrap();
        assert!(n.verify(), "Generated nonce must verify its commitment");
    }

    #[test]
    fn test_nonce_commitment_mismatch() {
        let mut n = NonceCommitment::random().unwrap();
        // tamper with stored commitment
        n.commitment[0] ^= 0xff;
        assert!(!n.verify(), "Tampered commitment should not verify");
    }

    #[test]
    fn test_revealed_pubnonce_mismatch() {
        let mut n = NonceCommitment::random().unwrap();
        // replace public point with something else
        n.pub_nonce = Secp256k1Point::generator();
        assert!(!n.verify(), "Mismatched public nonce must fail verify()");
    }

    #[test]
    fn test_commit_consistency() {
        let n = NonceCommitment::random().unwrap();
        let R = decode_reveal(&n.reveal()).to_bytes_compressed();
        let expected = tagged_hash("MuSig/nonce_commit", &R);
        assert_eq!(n.commitment, expected, "Commitment must be deterministic");
    }

    #[test]
    fn deterministic_nonce_changes_on_msg() {
        let sk = Secp256k1Scalar::one();
        let n1 = NonceCommitment::deterministic(&sk, b"a").unwrap();
        let n2 = NonceCommitment::deterministic(&sk, b"b").unwrap();
        assert_ne!(n1.reveal(), n2.reveal());
    }

    #[test]
    fn aggregate_even_y_two_random() {
        let n1 = NonceCommitment::random().unwrap();
        let n2 = NonceCommitment::random().unwrap();
        let revs = vec![n1.reveal(), n2.reveal()];
        let (agg, flipped) = aggregate_nonces(&revs).unwrap();
        let combined_point = decode_reveal(&agg);
        // should normalize to even-Y
        assert!(!combined_point.y_is_odd());
        // flipped flag matches raw oddness
        let raw = decode_reveal(&revs[0]) + &decode_reveal(&revs[1]);
        assert_eq!(flipped, raw.y_is_odd());
    }

    #[test]
    fn test_aggregate_single() {
        let g = Secp256k1Point::generator();
        let r = Reveal(g.to_bytes_compressed().to_vec());
        let (agg, flipped) = aggregate_nonces(&[r]).unwrap();
        let combined_point = decode_reveal(&agg);
        assert_eq!(combined_point, g);
        assert!(!flipped);
    }

    #[test]
    fn test_apply_flip() {
        let mut nc = NonceCommitment::random().unwrap();
        let orig = nc.pub_nonce.clone();
        nc.apply_flip(true);
        assert_eq!(nc.pub_nonce, -orig);
    }

    #[test]
    fn test_aggregate_flip_case() {
        // Use a single negated generator → should flip back
        let g = Secp256k1Point::generator();
        let neg = -g.clone();
        let r = Reveal(neg.to_bytes_compressed().to_vec());
        let (agg, flipped) = aggregate_nonces(&[r]).unwrap();
        let combined_point = decode_reveal(&agg);
        assert_eq!(combined_point, g);
        assert!(flipped);
    }

    // --- Static test‐vector from secp256k1-zkp musig_nonce_agg_vector ---
    #[test]
    fn test_nonce_agg_known_case_1() {
        let p0: [u8; 33] = [
            0x02, 0x01, 0x51, 0xC8, 0x0F, 0x43, 0x56, 0x48, 0xDF, 0x67, 0xA2, 0x2B, 0x74, 0x9C,
            0xD7, 0x98, 0xCE, 0x54, 0xE0, 0x32, 0x1D, 0x03, 0x4B, 0x92, 0xB7, 0x09, 0xB5, 0x67,
            0xD6, 0x0A, 0x42, 0xE6, 0x66,
        ];
        let p1: [u8; 33] = [
            0x03, 0xFF, 0x40, 0x6F, 0xFD, 0x8A, 0xDB, 0x9C, 0xD2, 0x98, 0x77, 0xE4, 0x98, 0x50,
            0x14, 0xF6, 0x6A, 0x59, 0xF6, 0xCD, 0x01, 0xC0, 0xE8, 0x8C, 0xAA, 0x8E, 0x5F, 0x31,
            0x66, 0xB1, 0xF6, 0x76, 0xA6,
        ];
        let r0 = Reveal(p0.to_vec());
        let r1 = Reveal(p1.to_vec());
        let R0 = decode_reveal(&r0);
        let R1 = decode_reveal(&r1);
        let raw = R0 + &R1;
        let (agg_reveal, flipped) = aggregate_nonces(&[r0.clone(), r1.clone()]).unwrap();

        assert_eq!(flipped, raw.y_is_odd());

        let expected_pt = if raw.y_is_odd() {
            -raw.clone()
        } else {
            raw.clone()
        };

        assert_eq!(agg_reveal.0, expected_pt.to_bytes_compressed().to_vec());

        // Check raw prefix byte
        let raw_bytes = raw.to_bytes_compressed();
        let prefix = if raw.y_is_odd() { 0x03 } else { 0x02 };
        assert_eq!(raw_bytes[0], prefix);

        // Static expected aggregate
        let expected_bytes: [u8; 33] = [
            0x02, 0x5F, 0xE1, 0x87, 0x3B, 0x4F, 0x29, 0x67, 0xF5, 0x2F, 0xEA, 0x4A, 0x06, 0xAD,
            0x5A, 0x8E, 0xCC, 0xBE, 0x9D, 0x0F, 0xD7, 0x30, 0x68, 0x01, 0x2C, 0x89, 0x4E, 0x2E,
            0x87, 0xCC, 0xB5, 0x80, 0x4B,
        ];

        assert_eq!(
            agg_reveal.0,
            expected_bytes.to_vec(),
            "Aggregated Reveal bytes do not match expected static vector"
        );
    }

    #[test]
    fn test_nonce_agg_invalid_prefix() {
        let mut bad = [0u8; 33];
        bad[0] = 0x05;
        assert!(Secp256k1Point::from_bytes_compressed(&bad).is_none());
    }
}
