//! MuSig1 signature verification module.
//!
//! Recomputes the aggregated public key, constructs the Schnorr signature bytes,
//! and checks validity via `crypto_rs::schnorr::schnorr_verify`.

use crate::keyagg::{keyagg, keyagg_pure};
use crypto_rs::schnorr::schnorr_verify;
use crypto_rs::secp256k1::{Secp256k1Point, Secp256k1Scalar};

/// Verify a MuSig1 aggregate signature `(R, s)`.
///
/// # Arguments
/// - `pubkeys`: Slice of all participants' public keys.
///   - When `use_pure = true`, `pubkeys` may be in any order (the code sorts internally).
///   - When `use_pure = false`, `pubkeys` must be in the exact same order used during signing.
/// - `msg`: The original message that was signed.
/// - `R`: The aggregated nonce point (already normalized to even Y).
/// - `s`: The aggregated signature scalar.
/// - `use_pure`: If `true`, use the pure key-aggregation variant; otherwise, use the optimized variant.
///
/// # Returns
/// Returns `true` if the signature is valid, `false` otherwise.
pub fn musig1_verify(
    pubkeys: &[Secp256k1Point],
    msg: &[u8],
    R: Secp256k1Point,
    s: Secp256k1Scalar,
    use_pure: bool,
) -> bool {
    // 1) Recompute the aggregated public key (X_agg) using the chosen key-aggregation method.
    let X_agg = if use_pure {
        keyagg_pure(pubkeys).0
    } else {
        keyagg(pubkeys).0
    };

    // 2) Build a 64-byte Schnorr signature: R.x-only (32 bytes) || s_big_endian (32 bytes).
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&R.x_only_bytes());
    sig[32..].copy_from_slice(&s.to_bytes_be());

    // 3) Serialize X_agg as a 32-byte x-only public key.
    let pk_bytes = X_agg.x_only_bytes();

    // 4) Use the BIP-340 Schnorr verify function.
    schnorr_verify(&pk_bytes, msg, &sig)
}

#[cfg(test)]
mod tests {
    use super::*; // brings musig1_verify into scope
    use crate::session::Musig1Session;
    use crypto_rs::secp256k1::{Secp256k1Point, Secp256k1Scalar};
    use rand::rng;

    /// Generate a random keypair (sk, pk) for testing.
    fn keypair() -> (Secp256k1Scalar, Secp256k1Point) {
        let mut rng = rng();
        let sk = Secp256k1Scalar::random(&mut rng);
        let pk = Secp256k1Point::generator() * &sk;
        (sk, pk)
    }

    #[test]
    fn test_single_party_verify() {
        let (sk, pk) = keypair();
        let msg = b"Hello verify!".to_vec();

        // Single-party MuSig1 (equivalent to Schnorr)
        let mut sess = Musig1Session::new(sk.clone(), vec![pk.clone()], msg.clone(), false);

        // No peers: produce our own reveal as R, finalize, compute challenge, partial
        let r = sess.round2_reveal();
        sess.receive_reveal(0, r.clone());
        sess.finalize_nonces();
        sess.compute_challenge();
        let s = sess.partial_sig(0);
        let R = sess.R_agg.unwrap();

        // Verify against the single public key
        assert!(
            musig1_verify(&[pk.clone()], &msg, R, s, false),
            "Single-party MuSig1 (Schnorr) did NOT verify"
        );
    }

    #[test]
    fn test_two_party_verify() {
        let (sk1, pk1) = keypair();
        let (sk2, pk2) = keypair();
        let pubs = vec![pk1.clone(), pk2.clone()];
        let msg = b"Two party verify".to_vec();

        let mut a = Musig1Session::new(sk1.clone(), pubs.clone(), msg.clone(), false);
        let mut b = Musig1Session::new(sk2.clone(), pubs.clone(), msg.clone(), false);

        // Round 1: exchange commits
        let c1 = a.round1_commit();
        let c2 = b.round1_commit();
        a.receive_commit(1, c2.clone());
        b.receive_commit(0, c1.clone());

        // Round 2: exchange reveals
        let r1 = a.round2_reveal();
        let r2 = b.round2_reveal();
        a.receive_reveal(1, r2.clone());
        b.receive_reveal(0, r1.clone());

        // Finalize nonces & compute challenges
        a.finalize_nonces();
        b.finalize_nonces();
        a.compute_challenge();
        b.compute_challenge();

        // Partials
        let s1 = a.partial_sig(0);
        let s2 = b.partial_sig(1);

        // Aggregate (using party A)
        let (R, s) = a.aggregate_sig(&[s1, s2]);

        // Verify joint signature
        assert!(
            musig1_verify(&pubs, &msg, R, s, false),
            "Two-party MuSig1 did NOT verify"
        );
    }

    #[test]
    fn test_pure_vs_optimized_agg() {
        let (sk1, pk1) = keypair();
        let (sk2, pk2) = keypair();
        let pubs = vec![pk1.clone(), pk2.clone()];
        let msg = b"Pure vs opt verify".to_vec();

        // Optimized (use_pure = false)
        let mut a_opt = Musig1Session::new(sk1.clone(), pubs.clone(), msg.clone(), false);
        let mut b_opt = Musig1Session::new(sk2.clone(), pubs.clone(), msg.clone(), false);
        let c1 = a_opt.round1_commit();
        let c2 = b_opt.round1_commit();
        a_opt.receive_commit(1, c2.clone());
        b_opt.receive_commit(0, c1.clone());
        let r1 = a_opt.round2_reveal();
        let r2 = b_opt.round2_reveal();
        a_opt.receive_reveal(1, r2.clone());
        b_opt.receive_reveal(0, r1.clone());
        a_opt.finalize_nonces();
        b_opt.finalize_nonces();
        a_opt.compute_challenge();
        b_opt.compute_challenge();
        let s1_opt = a_opt.partial_sig(0);
        let s2_opt = b_opt.partial_sig(1);
        let (R_opt, s_opt) = a_opt.aggregate_sig(&[s1_opt, s2_opt]);

        // Pure (use_pure = true)
        let mut a_pure = Musig1Session::new(sk1.clone(), pubs.clone(), msg.clone(), true);
        let mut b_pure = Musig1Session::new(sk2.clone(), pubs.clone(), msg.clone(), true);
        let c1p = a_pure.round1_commit();
        let c2p = b_pure.round1_commit();
        a_pure.receive_commit(1, c2p.clone());
        b_pure.receive_commit(0, c1p.clone());
        let r1p = a_pure.round2_reveal();
        let r2p = b_pure.round2_reveal();
        a_pure.receive_reveal(1, r2p.clone());
        b_pure.receive_reveal(0, r1p.clone());
        a_pure.finalize_nonces();
        b_pure.finalize_nonces();
        a_pure.compute_challenge();
        b_pure.compute_challenge();
        let s1_pure = a_pure.partial_sig(0);
        let s2_pure = b_pure.partial_sig(1);
        let (R_pure, s_pure) = a_pure.aggregate_sig(&[s1_pure, s2_pure]);

        // Both should verify
        assert!(
            musig1_verify(&pubs, &msg, R_opt, s_opt, false),
            "Optimized MuSig1 did NOT verify"
        );
        assert!(
            musig1_verify(&pubs, &msg, R_pure, s_pure, true),
            "Pure MuSig1 did NOT verify"
        );
    }
}
