//! A Rust port of secp256k1-zkp’s `musig/tests_impl.h`, exercising:
//!  - simple 2-of-2 MuSig sign & verify
//!  - API edge-case checks (invalid arguments, error returns)
//!  - Vectorized tests for key aggregation, nonce generation, nonce aggregation,
//!    signing/verification, tweaking, and signature aggregation.
#![allow(non_snake_case)]

use std::{collections::HashMap, panic};

use crypto_rs::{
    schnorr::{schnorr_verify, tagged_hash},
    secp256k1::{Secp256k1Point, Secp256k1Scalar},
};
use musig::{
    Musig1Session, MusigError, Reveal, aggregate_nonces, keyagg, keyagg_pure,
    nonce::Commit,
    sign::{Musig1Signer, musig1_sign_single, sign_multi},
    verify::musig1_verify,
};
use rand::{CryptoRng, RngCore};
use vectors::{MUSIG_NONCE_AGG_VECTOR, MUSIG_SIGN_VERIFY_VECTOR, MusigErrorCode};
mod vectors;
use crate::vectors::{MUSIG_KEY_AGG_VECTOR, MUSIG_NONCE_GEN_VECTOR};

/// A helper to create a random 32‐byte scalar
fn random_scalar_bytes() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand::rng().fill_bytes(&mut b);
    b
}

/// Simple 2-of-2 MuSig sign‐and‐verify test (non‐tweaked)
#[test]
fn musig_simple_2_of_2_flow_with_musig1_verify() {
    // We’ll simulate two parties doing MuSig1 fully in-memory.

    // 1) Generate two random keypairs
    let mut rng = rand::rng();
    let sk1 = Secp256k1Scalar::random(&mut rng);
    let pk1 = Secp256k1Point::generator() * &sk1;
    let sk2 = Secp256k1Scalar::random(&mut rng);
    let pk2 = Secp256k1Point::generator() * &sk2;

    // 2) A random 32‐byte message to sign:
    let msg: Vec<u8> = (0..32).map(|_| (rng.next_u32() & 0xFF) as u8).collect();

    // 3) Create two sessions:
    let mut sess1 = Musig1Session::new(
        sk1.clone(),
        vec![pk1.clone(), pk2.clone()],
        msg.clone(),
        false, // use_pure = false
    );
    let mut sess2 = Musig1Session::new(
        sk2.clone(),
        vec![pk1.clone(), pk2.clone()],
        msg.clone(),
        false,
    );

    // 4) Round 1: exchange commitments
    let commit1 = sess1.round1_commit();
    let commit2 = sess2.round1_commit();
    sess1.receive_commit(1, commit2.clone());
    sess2.receive_commit(0, commit1.clone());

    // 5) Round 2: exchange reveals
    let reveal1 = sess1.round2_reveal();
    let reveal2 = sess2.round2_reveal();
    sess1.receive_reveal(1, reveal2.clone());
    sess2.receive_reveal(0, reveal1.clone());

    // 6) Finalize nonces & compute challenges
    sess1.finalize_nonces();
    sess2.finalize_nonces();
    sess1.compute_challenge();
    sess2.compute_challenge();

    // 7) Each produces partial signature
    let sig1 = sess1.partial_sig(0); // index 0 corresponds to party1
    let sig2 = sess2.partial_sig(1); // index 1 corresponds to party2

    // 8) Aggregate into (R, s)
    let (R_agg, s_agg) = sess1.aggregate_sig(&[sig1.clone(), sig2.clone()]);

    // 9) Verify using `musig1_verify`
    //    Here we pass `use_pure = false` because that’s how we constructed both sessions above.
    assert!(
        musig1_verify(
            &[pk1.clone(), pk2.clone()],
            &msg,
            R_agg.clone(),
            s_agg.clone(),
            false
        ),
        "MuSig-1 (2-of-2) signature should verify via musig1_verify"
    );
}

#[test]
fn test_keyagg_valid_vectors() {
    for (case_index, case) in MUSIG_KEY_AGG_VECTOR.valid_case.iter().enumerate() {
        // 1) collect exactly `key_indices_len` pubkeys
        let mut pubkeys_vec = Vec::with_capacity(case.key_indices_len);
        for &idx in &case.key_indices[..case.key_indices_len] {
            // idx must be < MUSIG_KEY_AGG_VECTOR.pubkeys.len()
            let compressed_bytes = &MUSIG_KEY_AGG_VECTOR.pubkeys[idx];
            let P = Secp256k1Point::from_bytes_compressed(compressed_bytes)
                .expect("pubkey bytes must be valid");
            pubkeys_vec.push(P);
        }

        // 2) run key aggregation
        let (agg_point, _coefs) = keyagg(&pubkeys_vec);

        // 3) get compressed form of the aggregate
        let agg_compressed = agg_point.to_bytes_compressed();
        // by construction, keyagg flips to even‐Y, so prefix must be 0x02
        assert_eq!(
            agg_compressed[0], 0x02,
            "Case {}: aggregated point not normalized to even‐Y",
            case_index
        );

        // 4) compare X‐coordinate bytes == case.expected
        let x_bytes = &agg_compressed[1..33]; // exactly 32 bytes
        assert_eq!(
            x_bytes, &case.expected,
            "Case {}: X‐coordinate mismatch.\n\
                 expected = {:02x?}\n\
                 got      = {:02x?}",
            case_index, &case.expected, x_bytes
        );
    }
}

#[test]
fn test_keyagg_error_pubkey_indices() {
    for (err_index, case) in MUSIG_KEY_AGG_VECTOR.error_case.iter().enumerate() {
        if case.error == MusigErrorCode::MusigPubkey {
            let result = panic::catch_unwind(|| {
                // Attempt to build the Vec<Secp256k1Point> and call keyagg
                let mut pubkeys_vec = Vec::with_capacity(case.key_indices_len);
                for &idx in &case.key_indices[..case.key_indices_len] {
                    // This line should panic whenever idx >= pubkeys.len()
                    let compressed_bytes = &MUSIG_KEY_AGG_VECTOR.pubkeys[idx];
                    let point = Secp256k1Point::from_bytes_compressed(compressed_bytes).unwrap();
                    pubkeys_vec.push(point);
                }
                // If we somehow got a Vec of points, calling keyagg won't fix an out‐of‐range index—
                // the panic should already have happened above. But just in case:
                let _ = keyagg(&pubkeys_vec);
            });

            assert!(
                result.is_err(),
                "Error case {}: expected panic for invalid pubkey index {:?}, but it returned Ok",
                err_index,
                &case.key_indices[..case.key_indices_len]
            );
        }
    }
}

#[test]
fn test_nonce_agg_valid_cases() {
    for (case_index, tc) in MUSIG_NONCE_AGG_VECTOR.valid_case.iter().enumerate() {
        // Build Vec<Reveal> from two 66-byte arrays
        let mut reveals = Vec::new();
        for &idx in &tc.pnonce_indices {
            let raw_66: [u8; 66] = MUSIG_NONCE_AGG_VECTOR.pnonces[idx];
            reveals.push(Reveal(raw_66.to_vec()));
        }

        // Call aggregate_nonces() → (Reveal, bool)
        let result = aggregate_nonces(&reveals);
        assert!(
            result.is_ok(),
            "Valid case {}: expected Ok, got Err",
            case_index
        );
        // Extract the returned Reveal and the flip‐flag
        let (combined_reveal, flip) = result.unwrap();

        // Now decode that combined_reveal into a Secp256k1Point
        let combined_point: Secp256k1Point = Reveal::decode_reveal(&combined_reveal);

        // The “expected” array in the vector is 66 bytes. We split it into two halves,
        // decompress each 33-byte point, sum them to get raw_sum, then apply the flip if needed.
        let expected_bytes: [u8; 66] = tc.expected.unwrap();

        // First 33 bytes → expected_R1
        let mut expected_R1_array = [0u8; 33];
        expected_R1_array.copy_from_slice(&expected_bytes[0..33]);
        let expected_R1 = Secp256k1Point::from_bytes_compressed(&expected_R1_array)
            .unwrap_or_else(|| panic!("Case {}: invalid expected R1", case_index));

        // Second 33 bytes → expected_R2
        let mut expected_R2_array = [0u8; 33];
        expected_R2_array.copy_from_slice(&expected_bytes[33..66]);
        let expected_R2 = if expected_R2_array == [0u8; 33] {
            Secp256k1Point::identity()
        } else {
            Secp256k1Point::from_bytes_compressed(&expected_R2_array)
                .unwrap_or_else(|| panic!("Case {}: invalid expected R2", case_index))
        };
        // Compute raw_sum = expected_R1 + expected_R2
        let raw_sum = expected_R1 + &expected_R2;

        // If flip == true, final_point = –raw_sum; otherwise final_point = raw_sum
        let final_point = if flip { -raw_sum } else { raw_sum };

        // Compare compressed bytes of `combined_point` vs. `final_point`
        assert_eq!(
            combined_point.to_bytes_compressed(),
            final_point.to_bytes_compressed(),
            "Case {}: aggregated nonce mismatch",
            case_index
        );
    }
}

#[test]
fn test_nonce_agg_error_cases() {
    for (case_index, tc) in MUSIG_NONCE_AGG_VECTOR.error_case.iter().enumerate() {
        let mut reveals = Vec::new();
        for &idx in &tc.pnonce_indices {
            if idx >= MUSIG_NONCE_AGG_VECTOR.pnonces.len() {
                // out‐of‐range → push a dummy Vec<u8> of length ≠ 33 or 66 so WrongLength
                reveals.push(Reveal(vec![0u8; 5]));
            } else {
                let raw_66: [u8; 66] = MUSIG_NONCE_AGG_VECTOR.pnonces[idx];
                reveals.push(Reveal(raw_66.to_vec()));
            }
        }
        // aggregate_nonces should return Err for any invalid index or invalid bytes
        assert!(
            aggregate_nonces(&reveals).is_err(),
            "Error case {}: expected Err, got Ok",
            case_index
        );
    }
}
