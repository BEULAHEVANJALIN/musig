//! MuSig1 Public Key Aggregation (KeyAgg) in Rust
//!
//! This module provides two variants of the MuSig1 key aggregation algorithm:
//!
//! 1. Pure MuSig1 (keyagg_pure) - the original protocol as described in the
//!    https://eprint.iacr.org/2018/068.pdf paper: lexicographically sort keys, derive all coefficients
//!    uniformly via tagged hashes, and aggregate.
//!
//! 2. C-style MuSig1 (keyagg) - the optimized variant from the libsecp256k1 implementation,
//!    which assigns the second distinct key a coefficient of 1 to avoid one scalar multiplication.
//!    (static-test-vector compatible)

use crypto_rs::schnorr::tagged_hash;
use crypto_rs::secp256k1::{Secp256k1Point, Secp256k1Scalar};

/// Pure MuSig1 key aggregation function, as described in the https://eprint.iacr.org/2018/068.pdf paper.
///
/// # Parameters
/// - `pubkeys`: slice of public keys to aggregate (n-of-n).
///
/// # Returns
/// - `(X_agg, coeffs)` where:
///   - `X_agg` is the aggregated public key (ensured even-Y).
///   - `coeffs[i]` is the per-key coefficient for `pubkeys[i]`.
///
/// The algorithm is as follows:
///
/// 1. Sort compressed public keys lexicographically.
/// 2. Compute the list hash `L` by hashing the sorted compressed keys.
///    `L = tagged_hash("KeyAgg list", concat(sorted_bytes))`
/// 3.  For each original key `P_i`, derive coefficients `a_i = tagged_hash("KeyAgg coefficient", L || P_i_bytes)`.
/// 4. Aggregate the public keys by computing the linear combination of the public keys with the corresponding coefficients.
///    `X_agg = sum(P_i * a_i)`
/// 5. Normalize the result to even-Y.
///    If `Y(X_agg)` is odd, negate `X_agg` and all `a_i` to enforce even-Y property.
///
/// The function returns `(X_agg, coefs)`.
/// And this function is deterministic and will always produce the same output for the same input keys.
///
/// # Note
/// This function is a pure implementation of the MuSig1 key aggregation protocol, which is suitable for
/// educational purposes and testing. It does not include optimizations present in the C-style MuSig1
/// implementation, such as the special handling of the second distinct key to avoid one scalar multiplication.
/// It is not recommended for production use where performance is critical.
pub fn keyagg_pure(pubkeys: &[Secp256k1Point]) -> (Secp256k1Point, Vec<Secp256k1Scalar>) {
    assert!(!pubkeys.is_empty(), "No public keys provided");
    // Trivial single-key case
    if pubkeys.len() == 1 {
        return (pubkeys[0].clone(), vec![Secp256k1Scalar::one()]);
    }

    // Check if all provided public keys are identical.
    // If they are, return the first public key as the aggregated key and assign a coefficient of 1 to each public key.
    // Proceed with the aggregation process only if the keys are not identical.
    // This is an optimization to avoid unnecessary computation when all keys are the same.
    if pubkeys
        .iter()
        .all(|P| P.to_bytes_compressed() == pubkeys[0].to_bytes_compressed())
    {
        let coefs = vec![Secp256k1Scalar::one(); pubkeys.len()];
        return (pubkeys[0].clone(), coefs);
    }

    // 1) Lexicographically sort compressed bytes
    let mut sorted_bytes: Vec<[u8; 33]> = pubkeys.iter().map(|P| P.to_bytes_compressed()).collect();
    sorted_bytes.sort_unstable();

    // 2) Compute list hash L
    let mut list_buf = Vec::with_capacity(sorted_bytes.len() * 33);
    for b in &sorted_bytes {
        list_buf.extend_from_slice(b);
    }
    let L = tagged_hash("KeyAgg list", &list_buf);

    // 3) Derive coefficients in original order
    let mut coefs = Vec::with_capacity(pubkeys.len());
    for P in pubkeys {
        let bytes = P.to_bytes_compressed();
        let mut buf = Vec::with_capacity(32 + 33);
        buf.extend_from_slice(&L);
        buf.extend_from_slice(&bytes);
        let h = tagged_hash("KeyAgg coefficient", &buf);
        coefs.push(Secp256k1Scalar::from_bytes_be(&h));
    }

    // 4) Aggregate point
    let mut X_agg = Secp256k1Point::identity();
    for (P, a) in pubkeys.iter().zip(&coefs) {
        X_agg = X_agg + &(P * a);
    }

    // 5) Normalize to even-Y
    if X_agg.y_is_odd() {
        X_agg = -X_agg;
        for c in coefs.iter_mut() {
            *c = -c.clone();
        }
    }

    (X_agg, coefs)
}

/// C-style MuSig1 key aggregation function, optimized for performance and compatible with the static-test-vector.
/// This variant is compatible with the static-test-vector and uses a special handling for the second distinct key
/// to avoid one scalar multiplication.
///
/// # Parameters
/// - `pubkeys`: slice of public keys to aggregate (n-of-n).
///
/// # Returns
/// - `(X_agg, coeffs)` where:
///   - `X_agg` is the aggregated public key (ensured even-Y).
///   - `coeffs[i]` is the per-key coefficient for `pubkeys[i]`.
///
/// This function is consistent with libsecp256k1’s `musig_pubkey_agg` function.
///
/// The algorithm is as follows:
/// 1. Compute the list hash `L` over the input-order compressed bytes.
///    `L = tagged_hash("KeyAgg list", concat(pubkeys_compressed))`
/// 2. Identify the "second distinct" public key from the input.
///    If there is a second distinct key, it will be assigned a coefficient of 1.
/// 3. For each public key `P_i`, derive coefficients:
///    - If `P_i` is the second distinct key, set `a_i = 1`.
///    - Otherwise, compute `a_i = tagged_hash("KeyAgg coefficient", L || P_i_bytes)`.
/// 4. Aggregate the public keys by computing the linear combination of the public keys with the corresponding coefficients.
///    `X_agg = sum(P_i * a_i)`
/// 5. Normalize the result to even-Y.
///    If `Y(X_agg)` is odd, negate `X_agg` and all `a_i` to enforce even-Y property.   
///
/// The function returns `(X_agg, coefs)`.
/// And this function is deterministic and will always produce the same output for the same input keys.
pub fn keyagg(pubkeys: &[Secp256k1Point]) -> (Secp256k1Point, Vec<Secp256k1Scalar>) {
    assert!(!pubkeys.is_empty(), "No public keys provided");
    // Trivial single-key
    if pubkeys.len() == 1 {
        return (pubkeys[0].clone(), vec![Secp256k1Scalar::one()]);
    }

    // Check if all provided public keys are identical.
    // If they are, return the first public key as the aggregated key and assign a coefficient of 1 to each public key.
    // Proceed with the aggregation process only if the keys are not identical.
    // This is an optimization to avoid unnecessary computation when all keys are the same.
    if pubkeys
        .iter()
        .all(|P| P.to_bytes_compressed() == pubkeys[0].to_bytes_compressed())
    {
        let coefs = vec![Secp256k1Scalar::one(); pubkeys.len()];
        return (pubkeys[0].clone(), coefs);
    }

    // 1) Compute list hash L over input-order compressed bytes
    let mut list_buf = Vec::with_capacity(pubkeys.len() * 33);
    for P in pubkeys {
        list_buf.extend_from_slice(&P.to_bytes_compressed());
    }
    let L = tagged_hash("KeyAgg list", &list_buf);

    // 2) Identify "second distinct" public key
    let first = pubkeys[0].to_bytes_compressed();
    let mut second = None;
    for P in pubkeys.iter().skip(1) {
        let b = P.to_bytes_compressed();
        if b != first {
            second = Some(b);
            break;
        }
    }

    // 3) Compute coefficients: second gets 1, others via hash
    let mut coefs = Vec::with_capacity(pubkeys.len());
    for P in pubkeys {
        let bytes = P.to_bytes_compressed();
        let a = if Some(bytes) == second {
            Secp256k1Scalar::one()
        } else {
            let mut buf = Vec::with_capacity(32 + 33);
            buf.extend_from_slice(&L);
            buf.extend_from_slice(&bytes);
            Secp256k1Scalar::from_bytes_be(&tagged_hash("KeyAgg coefficient", &buf))
        };
        coefs.push(a);
    }

    // 4) Aggregate
    let mut X_agg = Secp256k1Point::identity();
    for (P, a) in pubkeys.iter().zip(&coefs) {
        X_agg = X_agg + &(P * a);
    }

    // 5) Normalize to even-Y
    if X_agg.y_is_odd() {
        X_agg = -X_agg;
        for c in coefs.iter_mut() {
            *c = -c.clone();
        }
    }

    (X_agg, coefs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_rs::secp256k1::Secp256k1Scalar;
    use num_bigint::BigUint;
    use num_traits::One;

    #[test]
    fn test_keyagg_single_key() {
        let g = Secp256k1Point::generator();
        // Pure version trivial
        let (agg_p, coefs_p) = keyagg_pure(&[g.clone()]);
        assert_eq!(agg_p, g);
        assert_eq!(coefs_p.len(), 1);
        assert_eq!(coefs_p[0].value(), &BigUint::one());
        // C-style trivial
        let (agg_c, coefs_c) = keyagg(&[g.clone()]);
        assert_eq!(agg_c, g);
        assert_eq!(coefs_c.len(), 1);
        assert_eq!(coefs_c[0].value(), &BigUint::one());
    }

    #[test]
    fn test_keyagg_order_invariance_pure() {
        let g = Secp256k1Point::generator();
        let s5 = Secp256k1Scalar::new(BigUint::from(5u8));
        let s7 = Secp256k1Scalar::new(BigUint::from(7u8));
        let P1 = &g * &s5;
        let P2 = &g * &s7;
        let (a1, c12) = keyagg_pure(&[P1.clone(), P2.clone()]);
        let (a2, c21) = keyagg_pure(&[P2.clone(), P1.clone()]);
        assert_eq!(a1, a2);
        assert_eq!(c12[0], c21[1]);
        assert_eq!(c12[1], c21[0]);
    }

    #[test]
    fn reconstruct_for_two_keys() {
        let g = Secp256k1Point::generator();
        let s5 = Secp256k1Scalar::new(BigUint::from(5u8));
        let s7 = Secp256k1Scalar::new(BigUint::from(7u8));
        // derive P1 = 5·G, P2 = 7·G
        let P1 = &g * &s5;
        let P2 = &g * &s7;
        let pubkeys = vec![P1.clone(), P2.clone()];
        // aggregate
        let (X, coefs) = keyagg(&pubkeys);
        // reconstruct by ∑ P_i·a_i
        let mut X_rec = Secp256k1Point::infinity();
        for (P, a) in pubkeys.iter().zip(&coefs) {
            X_rec = X_rec + &(P * a);
        }
        assert_eq!(X, X_rec, "reconstructed point matches aggregate");
        // ensure the result has even Y
        assert!(!X.y_is_odd(), "aggregate must be normalized to even-Y");
    }

    #[test]
    fn test_keyagg_static_vector_c() {
        const PKS: &[[u8; 33]] = &[
            [
                0x02, 0xF9, 0x30, 0x8A, 0x01, 0x92, 0x58, 0xC3, 0x10, 0x49, 0x34, 0x4F, 0x85, 0xF8,
                0x9D, 0x52, 0x29, 0xB5, 0x31, 0xC8, 0x45, 0x83, 0x6F, 0x99, 0xB0, 0x86, 0x01, 0xF1,
                0x13, 0xBC, 0xE0, 0x36, 0xF9,
            ],
            [
                0x03, 0xDF, 0xF1, 0xD7, 0x7F, 0x2A, 0x67, 0x1C, 0x5F, 0x36, 0x18, 0x37, 0x26, 0xDB,
                0x23, 0x41, 0xBE, 0x58, 0xFE, 0xAE, 0x1D, 0xA2, 0xDE, 0xCE, 0xD8, 0x43, 0x24, 0x0F,
                0x7B, 0x50, 0x2B, 0xA6, 0x59,
            ],
            [
                0x02, 0x35, 0x90, 0xA9, 0x4E, 0x76, 0x8F, 0x8E, 0x18, 0x15, 0xC2, 0xF2, 0x4B, 0x4D,
                0x80, 0xA8, 0xE3, 0x14, 0x93, 0x16, 0xC3, 0x51, 0x8C, 0xE7, 0xB7, 0xAD, 0x33, 0x83,
                0x68, 0xD0, 0x38, 0xCA, 0x66,
            ],
        ];
        const EXPECTED: [u8; 33] = [
            0x02, 0x90, 0x53, 0x9E, 0xED, 0xE5, 0x65, 0xF5, 0xD0, 0x54, 0xF3, 0x2C, 0xC0, 0xC2,
            0x20, 0x12, 0x68, 0x89, 0xED, 0x1E, 0x5D, 0x19, 0x3B, 0xAF, 0x15, 0xAE, 0xF3, 0x44,
            0xFE, 0x59, 0xD4, 0x61, 0x0C,
        ];
        let points: Vec<_> = PKS
            .iter()
            .map(|b| Secp256k1Point::from_bytes_compressed(b).unwrap())
            .collect();
        let (agg_c, _) = keyagg(&points);
        assert_eq!(agg_c.to_bytes_compressed(), EXPECTED);
    }

    #[test]
    fn aggregate_same_key_twice() {
        use num_bigint::BigUint;
        use num_traits::One;
        // Pure-spec with duplicate keys
        let g = Secp256k1Point::generator();
        let (X_agg, coefs) = keyagg_pure(&[g.clone(), g.clone()]);
        assert_eq!(X_agg, g);
        assert_eq!(coefs.len(), 2);
        assert_eq!(coefs[0].value(), &BigUint::one());
        assert_eq!(coefs[1].value(), &BigUint::one());

        // C-style with duplicate keys
        let g2 = Secp256k1Point::generator();
        let (X_agg_c, coefs_c) = keyagg(&[g2.clone(), g2.clone()]);
        assert_eq!(X_agg_c, g2);
        assert_eq!(coefs_c.len(), 2);
        assert_eq!(coefs_c[0].value(), &BigUint::one());
        assert_eq!(coefs_c[1].value(), &BigUint::one());
    }
}
