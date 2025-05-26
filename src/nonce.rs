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
#[derive(Debug, Error)]
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
}

/// Round-1 commit message to broadcast: `t_i = H_com(R_i_bytes)`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Commit(pub [u8; 32]);

/// Round-2 reveal message to broadcast: compresed `R_i = k_i * G`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reveal(pub [u8; 33]);

/// Holds a single signer’s nonce state (secret, public, and commitment).
#[derive(Clone)]
pub struct NonceCommitment {
    /// Secret scalar `k_i`.
    pub nonce: Secp256k1Scalar,
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
            nonce: k,
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
            self.nonce = -self.nonce.clone();
            self.pub_nonce = -self.pub_nonce.clone();
        }
    }

    /// Extract round-1 commit message.
    pub fn commit(&self) -> Commit {
        Commit(self.commitment)
    }

    /// Extract round-2 reveal message.
    pub fn reveal(&self) -> Reveal {
        Reveal(self.pub_nonce.to_bytes_compressed())
    }

    /// Verify that the commitment matches the given public nonce.
    pub fn verify(&self) -> bool {
        let bytes = self.pub_nonce.to_bytes_compressed();
        tagged_hash("MuSig/nonce_commit", &bytes) == self.commitment
    }
}

/// Aggregate a slice of round‑2 reveals into a single nonce `R_agg`, enforcing even‑Y.
/// Returns the normalized `R_agg` and a flag indicating whether a global flip occurred.
pub fn aggregate_nonces(reveals: &[Reveal]) -> Result<(Secp256k1Point, bool), NonceError> {
    if reveals.is_empty() {
        return Err(NonceError::InvalidPoint);
    }
    let mut agg = Secp256k1Point::identity();
    for Reveal(bytes) in reveals {
        let R = Secp256k1Point::from_bytes_compressed(bytes).ok_or(NonceError::InvalidPoint)?;
        agg = agg + &R;
    }
    let flip = agg.y_is_odd();
    if flip {
        agg = -agg;
    }
    Ok((agg, flip))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_rs::secp256k1::{Secp256k1Point, Secp256k1Scalar};

    /// Helper to get the point out of a Reveal.
    fn decode_reveal(r: &Reveal) -> Secp256k1Point {
        let Reveal(bytes) = r.clone();
        Secp256k1Point::from_bytes_compressed(&bytes).unwrap()
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
        assert!(!n.nonce.is_zero());
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
        // should normalize to even-Y
        assert!(!agg.y_is_odd());
        // flipped flag matches raw oddness
        let raw = decode_reveal(&revs[0]) + &decode_reveal(&revs[1]);
        assert_eq!(flipped, raw.y_is_odd());
    }

    #[test]
    fn test_aggregate_single() {
        let g = Secp256k1Point::generator();
        let r = Reveal(g.to_bytes_compressed());
        let (agg, flipped) = aggregate_nonces(&[r]).unwrap();
        assert_eq!(agg, g);
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
        let r = Reveal(neg.to_bytes_compressed());
        let (agg, flipped) = aggregate_nonces(&[r]).unwrap();
        assert_eq!(agg, g);
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
        let r0 = Reveal(p0);
        let r1 = Reveal(p1);
        let R0 = decode_reveal(&r0);
        let R1 = decode_reveal(&r1);
        let raw = R0.clone() + &R1.clone();
        let (agg, flipped) = aggregate_nonces(&[r0.clone(), r1.clone()]).unwrap();

        assert_eq!(flipped, raw.y_is_odd());
        let expected_pt = if raw.y_is_odd() {
            -raw.clone()
        } else {
            raw.clone()
        };
        assert_eq!(agg, expected_pt);

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
        assert_eq!(agg.to_bytes_compressed(), expected_bytes);
    }

    #[test]
    fn test_nonce_agg_invalid_prefix() {
        let mut bad = [0u8; 33];
        bad[0] = 0x05;
        assert!(Secp256k1Point::from_bytes_compressed(&bad).is_none());
    }
}
