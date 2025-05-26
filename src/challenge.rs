//! Challenge computation for MuSig1.
//!
//! This module computes the MuSig1 challenge scalar
//!
//! ```text
//! e = H_tag("MuSig/agg", R.x || X.x || m) mod q
//! ```
//!
//! with a one-time fallback if the scalar reduces to zero.

use crypto_rs::schnorr::tagged_hash;
use crypto_rs::secp256k1::{Secp256k1Point, Secp256k1Scalar};

/// Compute the MuSig1 challenge scalar `e = H_tag("MuSig/agg", R||X||m)`, reduced mod n.
///
/// Performs a tagged hash over the x-coordinates of the aggregate nonce and public key,
/// plus the message, and reduces the digest modulo the curve order.
/// If the resulting scalar is zero, a single 0x00 byte is appended and re-hashed.
///
/// # Parameters
/// - `R_agg`: the aggregate nonce point (already normalized to even-Y).
/// - `X_agg`: the aggregate public key (from key aggregation, even-Y normalized).
/// - `msg`: the message to be signed.
///
/// # Returns
/// A nonzero scalar `e` in the field.
///
/// # Example
/// ```rust
/// # use crypto_rs::secp256k1::{Secp256k1Point, Secp256k1Scalar};
/// # use musig::compute_challenge;
/// let R_agg = Secp256k1Point::generator();
/// let X_agg = Secp256k1Point::generator();
/// let msg = b"hello";
/// let e: Secp256k1Scalar = compute_challenge(&R_agg, &X_agg, msg);
/// assert!(!e.is_zero());
/// ```
pub fn compute_challenge(
    R_agg: &Secp256k1Point,
    X_agg: &Secp256k1Point,
    msg: &[u8],
) -> Secp256k1Scalar {
    // Ensure both inputs use even-Y parity.
    let R = R_agg.normalize_parity();
    let X = X_agg.normalize_parity();

    // Extract x-coordinates (drop 0x02 prefix)
    let r_bytes = &R.to_bytes_compressed()[1..];
    let x_bytes = &X.to_bytes_compressed()[1..];

    // Build hash input: R.x || X.x || msg
    let mut buf = Vec::with_capacity(64 + msg.len());
    buf.extend_from_slice(r_bytes);
    buf.extend_from_slice(x_bytes);
    buf.extend_from_slice(msg);

    // Domain-separation tag for MuSig1
    const TAG: &str = "MuSig/agg";

    // First pass: tagged SHA256
    let digest = tagged_hash(TAG, &buf);
    let mut e = Secp256k1Scalar::from_bytes_be(&digest);

    // Fallback: if zero, append 0x00 and re-hash once
    if e.is_zero() {
        buf.push(0x00);
        let digest2 = tagged_hash(TAG, &buf);
        e = Secp256k1Scalar::from_bytes_be(&digest2);
        // by construction, should now be non-zero
        debug_assert!(!e.is_zero(), "challenge still zero after retry");
    }

    e
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ops::Add;
    use crypto_rs::secp256k1::Secp256k1Point;

    #[test]
    fn challenge_nonzero() {
        let R = Secp256k1Point::generator();
        let X = Secp256k1Point::generator();
        let msg = b"test";
        let e = compute_challenge(&R, &X, msg);
        assert!(!e.is_zero(), "Challenge must be non-zero");
    }

    #[test]
    fn test_challenge_consistency() {
        let R = Secp256k1Point::generator();
        let X = Secp256k1Point::generator();
        let msg = b"MuSig1 challenge test";
        let e1 = compute_challenge(&R, &X, msg);
        let e2 = compute_challenge(&R, &X, msg);
        assert_eq!(e1, e2, "Challenge must be deterministic");
    }

    #[test]
    fn test_challenge_varies_with_message() {
        let R = Secp256k1Point::generator();
        let X = Secp256k1Point::generator();
        let e1 = compute_challenge(&R, &X, b"foo");
        let e2 = compute_challenge(&R, &X, b"bar");
        assert_ne!(e1, e2, "Different messages yield different challenges");
    }

    #[test]
    fn test_challenge_varies_with_X() {
        let R = Secp256k1Point::generator();
        let msg = b"test";
        let X1 = Secp256k1Point::generator();
        let X2 = Secp256k1Point::generator().add(&Secp256k1Point::generator());
        let e1 = compute_challenge(&R, &X1, msg);
        let e2 = compute_challenge(&R, &X2, msg);
        assert_ne!(
            e1, e2,
            "Different aggregate public keys must yield different challenges"
        );
    }

    #[test]
    fn challenge_invariant_under_sign_flip() {
        let X = Secp256k1Point::generator();
        let msg = b"test";
        let R1 = Secp256k1Point::generator();
        let R2 = -R1.clone();
        let e1 = compute_challenge(&R1, &X, msg);
        let e2 = compute_challenge(&R2, &X, msg);
        // BIP-340 uses x-only, so flipping the sign doesn't change the challenge
        assert_eq!(e1, e2, "Sign flip of R does not affect x-only challenge");
    }
}
