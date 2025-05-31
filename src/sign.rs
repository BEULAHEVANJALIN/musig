//! High-level MuSig1 signing helpers:
//! - `Musig1Signer`: interactive multi-party signer
//! - `sign_multi`: in-process n-party protocol
//! - `musig1_sign_single`: single-party (Schnorr) convenience

use crate::nonce::{Commit, Reveal};
use crate::session::Musig1Session;
use crypto_rs::secp256k1::{Secp256k1Point, Secp256k1Scalar};
use std::collections::HashMap;

/// Round-1 commitment type for MuSig1.
pub type Musig1Commit = Commit;
/// Round-2 reveal type for MuSig1.
pub type Musig1Reveal = Reveal;
/// Partial-signature scalar type for MuSig1.
pub type Musig1Partial = Secp256k1Scalar;

/// Errors that can occur during the MuSig1 signing process.
#[derive(Debug, PartialEq)]
pub enum MusigError {
    /// Not enough peer commitments collected.
    MissingCommits {
        /// Number of commitments expected (n − 1 for multi-party, or 0 for single-party).
        expected: usize,
        /// Number of commitments actually received.
        got: usize,
    },
    /// Not enough peer reveals collected.
    MissingReveals {
        /// Number of reveals expected (n − 1 for multi-party, or 0 for single-party).
        expected: usize,
        /// Number of reveals actually received.
        got: usize,
    },
    /// Not enough peer partials collected.
    MissingPartials {
        /// Number of partials expected (equal to number of participants).
        expected: usize,
        /// Number of partials actually provided.
        got: usize,
    },
}

/// Interactive MuSig1 signer for multi-party protocols.
pub struct Musig1Signer {
    session: Musig1Session,
}

impl Musig1Signer {
    /// Initialize a new MuSig1Signer.
    ///
    /// # Arguments
    /// - `sk`: this signer's secret key.
    /// - `pubkeys`: public keys of all participants.
    /// - `msg`: message to be signed.
    /// - `use_pure`: whether to use the keyagg_pure (paper-spec) key aggregation.
    pub fn new(
        sk: Secp256k1Scalar,
        pubkeys: Vec<Secp256k1Point>,
        msg: Vec<u8>,
        use_pure: bool,
    ) -> Self {
        Self {
            session: Musig1Session::new(sk, pubkeys, msg, use_pure),
        }
    }

    /// Generate and return this signer's round-1 commit.
    pub fn commit(&self) -> Musig1Commit {
        self.session.round1_commit()
    }

    /// Receive and store peer commitments.
    ///
    /// Returns `Err(MusigError::MissingCommits)` if the number of commits is not exactly (n−1).
    pub fn receive_commits(
        &mut self,
        commits: HashMap<usize, Musig1Commit>,
    ) -> Result<(), MusigError> {
        let n = self.session.pubkeys.len();
        let expected = if n > 1 { n - 1 } else { 0 };
        let got = commits.len();
        if got != expected {
            return Err(MusigError::MissingCommits { expected, got });
        }
        for (i, c) in commits {
            self.session.receive_commit(i, c);
        }
        Ok(())
    }

    /// Generate and return this signer's round-2 reveal.
    pub fn reveal(&self) -> Musig1Reveal {
        self.session.round2_reveal()
    }

    /// Receive and store peer reveals.
    ///
    /// Returns `Err(MusigError::MissingReveals)` if the number of reveals is not exactly (n−1).
    pub fn receive_reveals(
        &mut self,
        reveals: HashMap<usize, Musig1Reveal>,
    ) -> Result<(), MusigError> {
        let n = self.session.pubkeys.len();
        let expected = if n > 1 { n - 1 } else { 0 };
        let got = reveals.len();
        if got != expected {
            return Err(MusigError::MissingReveals { expected, got });
        }
        for (i, r) in reveals {
            self.session.receive_reveal(i, r);
        }
        Ok(())
    }

    /// Compute and return this signer's partial signature `s_i`.
    ///
    /// - Ensures that all n−1 commits and n−1 reveals have been collected,
    ///   then finalizes nonces and computes the challenge.
    /// - `idx` must be this signer's index within `pubkeys` (0 ≤ idx < n).
    ///
    /// Returns `Err(MusigError::MissingCommits)` or `Err(MusigError::MissingReveals)` if preconditions are not met.
    pub fn partial(&mut self, idx: usize) -> Result<Musig1Partial, MusigError> {
        let n = self.session.pubkeys.len();
        if idx >= n {
            panic!(
                "Musig1Signer::partial called with out-of-range idx (got {} but n = {})",
                idx, n
            );
        }
        // Check that exactly n−1 commits and n−1 reveals have been received.
        if self.session.commits.len() != n.saturating_sub(1) {
            return Err(MusigError::MissingCommits {
                expected: n.saturating_sub(1),
                got: self.session.commits.len(),
            });
        }
        if self.session.reveals.len() != n.saturating_sub(1) {
            return Err(MusigError::MissingReveals {
                expected: n.saturating_sub(1),
                got: self.session.reveals.len(),
            });
        }

        // Finalize nonces and compute challenge if not done already.
        if self.session.R_agg.is_none() {
            self.session.finalize_nonces();
            self.session.compute_challenge();
        }

        Ok(self.session.partial_sig(idx))
    }

    /// Aggregate a complete set of partials into the final `(R, s)` signature.
    ///
    /// Returns `Err(MusigError::MissingPartials)` if the number of partials is not exactly n.
    pub fn aggregate(
        &self,
        partials: HashMap<usize, Musig1Partial>,
    ) -> Result<(Secp256k1Point, Secp256k1Scalar), MusigError> {
        let n = self.session.pubkeys.len();
        let expected = n;
        let got = partials.len();
        if got != expected {
            return Err(MusigError::MissingPartials { expected, got });
        }

        // Collect them in order 0..n, error if any index is missing.
        let mut vec = Vec::with_capacity(n);
        for i in 0..n {
            match partials.get(&i) {
                Some(s_i) => vec.push(s_i.clone()),
                None => {
                    return Err(MusigError::MissingPartials {
                        expected: n,
                        got: partials.len(),
                    });
                }
            }
        }

        Ok(self.session.aggregate_sig(&vec))
    }
}

/// Perform an n-party MuSig1 signature entirely in-process.
///
/// # Arguments
/// - `sks`: slice of secret keys, one per signer.
/// - `pks`: slice of public keys (must correspond 1:1 with `sks`).
/// - `msg`: message bytes to be signed.
/// - `use_pure`: if true, uses the pure paper-spec key aggregation; otherwise uses the optimized C-style.
///
/// # Returns
/// On success, returns `(R, s, X_agg)`, where:
///   - `R` is the aggregate nonce point (even-Y normalized),
///   - `s` is the final signature scalar,
///   - `X_agg` is the aggregate public key (even-Y normalized).
///
/// Returns `Err(MusigError)` if any signer fails to supply the correct number of commits, reveals, or partials.
pub fn sign_multi(
    sks: &[Secp256k1Scalar],
    pks: &[Secp256k1Point],
    msg: Vec<u8>,
    use_pure: bool,
) -> Result<(Secp256k1Point, Secp256k1Scalar, Secp256k1Point), MusigError> {
    let n = sks.len();
    assert!(n == pks.len(), "sign_multi: sks.len() must equal pks.len()");

    // 1) Initialize one Musig1Signer per party.
    let mut signers: Vec<Musig1Signer> = (0..n)
        .map(|i| Musig1Signer::new(sks[i].clone(), pks.to_vec(), msg.clone(), use_pure))
        .collect();

    // 2) Round-1: each signer produces a Commit.
    let commits: Vec<_> = signers.iter().map(|s| s.commit()).collect();

    // 3) Broadcast commits to all other signers.
    for i in 0..n {
        let mut peer_map = HashMap::with_capacity(n - 1);
        for j in 0..n {
            if j != i {
                peer_map.insert(j, commits[j].clone());
            }
        }
        signers[i].receive_commits(peer_map)?;
    }

    // 4) Round-2: each signer produces a Reveal.
    let reveals: Vec<_> = signers.iter().map(|s| s.reveal()).collect();

    // 5) Broadcast reveals to all other signers.
    for i in 0..n {
        let mut peer_map = HashMap::with_capacity(n - 1);
        for j in 0..n {
            if j != i {
                peer_map.insert(j, reveals[j].clone());
            }
        }
        signers[i].receive_reveals(peer_map)?;
    }

    // 6) Each signer is now ready to produce its partial signature.
    //    partial(i) will finalize nonces, compute challenge, then return s_i.
    let mut partials_map: HashMap<usize, Secp256k1Scalar> = HashMap::with_capacity(n);
    for i in 0..n {
        let s_i = signers[i].partial(i)?;
        partials_map.insert(i, s_i);
    }

    // 7) Aggregate all partials into the final (R, s).
    let (R_agg, s) = signers[0].aggregate(partials_map)?;

    // 8) Return aggregate pubkey as well
    let X_agg = signers[0].session.X_agg.clone();
    Ok((R_agg, s, X_agg))
}

/// Convenience function: single-party MuSig1 (Schnorr) signature.
///
/// Equivalent to running the full protocol with exactly one participant.
///
/// # Returns
/// `(R, s)` on success, or `Err(MusigError)` if something unexpected happened.
pub fn musig1_sign_single(
    sk: Secp256k1Scalar,
    msg: Vec<u8>,
) -> Result<(Secp256k1Point, Secp256k1Scalar), MusigError> {
    // Build a one-element keyset
    let pk = Secp256k1Point::generator() * &sk;
    let mut signer = Musig1Signer::new(sk.clone(), vec![pk.clone()], msg, false);

    // No peers → expect 0 commits & 0 reveals
    signer.receive_commits(HashMap::new())?;
    signer.receive_reveals(HashMap::new())?;

    // Compute single-party (Schnorr-style) partial
    let s_i = signer.partial(0)?;
    let (R, s) = signer.aggregate([(0, s_i)].iter().cloned().collect())?;
    Ok((R, s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::musig1_verify;
    use num_bigint::BigUint;

    fn generator() -> Secp256k1Point {
        Secp256k1Point::generator()
    }

    /// Helper: deterministically build scalar keys [1, 2, 3, ...].
    fn build_keypairs(n: usize) -> (Vec<Secp256k1Scalar>, Vec<Secp256k1Point>) {
        let mut sks = Vec::with_capacity(n);
        let mut pks = Vec::with_capacity(n);
        for i in 1..=n {
            let scalar = Secp256k1Scalar::new(BigUint::from(i as u64));
            sks.push(scalar.clone());
            pks.push(generator() * &scalar);
        }
        (sks, pks)
    }

    #[test]
    fn test_single_party_schnorr() {
        let sk = Secp256k1Scalar::one(); // secret = 1
        let msg = b"hello single".to_vec();
        let (R, s) =
            musig1_sign_single(sk.clone(), msg.clone()).expect("single-party signing failed");

        let pk = generator() * &sk;
        assert!(
            musig1_verify(&[pk.clone()], &msg, R, s, false),
            "Single-party Schnorr did not verify"
        );
    }

    #[test]
    fn test_two_party_optimized() {
        // Build 2 keypairs: sk = 1,2
        let (sks, pks) = build_keypairs(2);
        let msg = b"two-party optimized".to_vec();

        // Use `use_pure = false` for optimized
        let (R, s, _X_agg) =
            sign_multi(&sks, &pks, msg.clone(), false).expect("two-party optimized signing failed");

        // Verify joint signature against X_agg
        assert!(
            musig1_verify(&pks, &msg, R, s, false),
            "Two-party optimized signature did not verify"
        );
    }

    #[test]
    fn test_two_party_pure() {
        // Build 2 keypairs: sk = 1,2
        let (sks, pks) = build_keypairs(2);
        let msg = b"two-party pure".to_vec();

        // Use `use_pure = true`
        let (R, s, _X_agg) =
            sign_multi(&sks, &pks, msg.clone(), true).expect("two-party pure signing failed");

        assert!(
            musig1_verify(&pks, &msg, R, s, true),
            "Two-party pure signature did not verify"
        );
    }

    #[test]
    fn test_three_party_optimized() {
        // Build 3 keypairs: sk = 1,2,3
        let (sks, pks) = build_keypairs(3);
        let msg = b"three-party optimized".to_vec();

        let (R, s, _X_agg) = sign_multi(&sks, &pks, msg.clone(), false)
            .expect("three-party optimized signing failed");

        assert!(
            musig1_verify(&pks, &msg, R, s, false),
            "Three-party optimized signature did not verify"
        );
    }

    #[test]
    fn test_three_party_pure() {
        // Build 3 keypairs: sk = 1,2,3
        let (sks, pks) = build_keypairs(3);
        let msg = b"three-party pure".to_vec();

        let (R, s, _X_agg) =
            sign_multi(&sks, &pks, msg.clone(), true).expect("three-party pure signing failed");

        assert!(
            musig1_verify(&pks, &msg, R, s, true),
            "Three-party pure signature did not verify"
        );
    }

    /// Error if `sign_multi` is given mismatched SK/PK lengths.
    #[test]
    #[should_panic(expected = "sks.len() must equal pks.len")]
    fn test_sign_multi_mismatched_lengths() {
        let sks = vec![Secp256k1Scalar::one()]; // 1 sk
        let pks = vec![
            generator() * &Secp256k1Scalar::one(),
            generator() * &Secp256k1Scalar::new(BigUint::from(2u8)),
        ]; // 2 pks
        let _ = sign_multi(&sks, &pks, b"oops".to_vec(), false).unwrap();
    }

    /// Error if someone calls `partial` before receiving any commits.
    #[test]
    fn test_missing_commits_error() {
        // Build 2 keypairs: sk = 1,2
        let (sks, pks) = build_keypairs(2);
        let msg = b"missing commits test".to_vec();

        // Manually use Musig1Signer to drive error
        let mut signer = Musig1Signer::new(sks[0].clone(), pks.clone(), msg.clone(), false);

        // Directly calling `partial(0)` without receiving commits should Err(MissingCommits)
        let err = signer.partial(0).unwrap_err();
        match err {
            MusigError::MissingCommits { expected, got } => {
                assert_eq!(expected, 1);
                assert_eq!(got, 0);
            }
            _ => panic!("Expected MissingCommits, got {:?}", err),
        }
    }

    /// Error if reveal count is incorrect.
    #[test]
    fn test_missing_reveals_error() {
        let (sks, pks) = build_keypairs(2);
        let msg = b"missing reveals test".to_vec();

        let mut signer = Musig1Signer::new(sks[0].clone(), pks.clone(), msg.clone(), false);

        // Provide commits but no reveals
        let c1 = signer.commit();
        let mut commit_map = HashMap::new();
        commit_map.insert(1, c1);
        signer.receive_commits(commit_map).unwrap();

        // Now calling `partial(0)` should Err(MusigError::MissingReveals)
        let err = signer.partial(0).unwrap_err();
        match err {
            MusigError::MissingReveals { expected, got } => {
                assert_eq!(expected, 1);
                assert_eq!(got, 0);
            }
            _ => panic!("Expected MissingReveals, got {:?}", err),
        }
    }

    /// Error if aggregate receives wrong number of partials.
    #[test]
    fn test_missing_partials_error() {
        let (sks, pks) = build_keypairs(2);
        let msg = b"missing partials test".to_vec();

        // Use sign_multi to get a valid signature first.
        let (_R, _s_val, _X_agg) = sign_multi(&sks, &pks, msg.clone(), false).unwrap();

        // But manually call `aggregate` with only one partial instead of two.
        let mut partials_map = HashMap::new();
        partials_map.insert(0, Secp256k1Scalar::one()); // only one partial

        // Use a fresh signer to call `aggregate`:
        let signer = Musig1Signer::new(sks[0].clone(), pks.clone(), msg.clone(), false);
        let err = signer.aggregate(partials_map).unwrap_err();
        match err {
            MusigError::MissingPartials { expected, got } => {
                assert_eq!(expected, 2);
                assert_eq!(got, 1);
            }
            _ => panic!("Expected MissingPartials, got {:?}", err),
        }
    }
}
