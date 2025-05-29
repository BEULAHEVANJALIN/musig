// This session based API orchestrates the MuSig1 signing protocol,
// managing the session state for each signer.
// It handles Key aggregation (pure or optimized),
// nonce generation, commitment, reveal rounds,
// challenge computation,
// partial signatures and
// signature aggregation.
use crate::challenge::compute_challenge;
use crate::keyagg::{keyagg, keyagg_pure};
use crate::nonce::{Commit, NonceCommitment, Reveal, aggregate_nonces};
use crypto_rs::secp256k1::{Secp256k1Point, Secp256k1Scalar};
use std::collections::HashMap;

/// Per-signer session state for MuSig1.
///
/// Holds our secret key, all peers' public keys, nonce commitments, and intermediate state
/// through the protocol rounds.
pub struct Musig1Session {
    /// Our secret signing key x_i.
    pub sk: Secp256k1Scalar,
    /// All participant public keys (including our own).
    pub pubkeys: Vec<Secp256k1Point>,
    /// Aggregated public key X = \sum_i a_i * X_i (even-Y).
    pub X_agg: Secp256k1Point,
    /// Per-key aggregation coefficients a_i.
    pub coeffs: Vec<Secp256k1Scalar>,
    /// Our per-session nonce commitment (Secret scalar `k_i`, Public nonce point `R_i = k_i * G`, and Commitment `t_i = H_com(R_i_bytes)`).
    pub nonce: NonceCommitment,
    /// Peers' round-1 commitments, keyed by signer index.
    pub commits: HashMap<usize, Commit>,
    /// Peers' round-2 reveals, keyed by signer index.
    pub reveals: HashMap<usize, Reveal>,
    /// Aggregate nonce point R_agg = \sum_i a_i * R_i (even-Y), after collecting all reveals.
    pub R_agg: Option<Secp256k1Point>,
    /// Flag indicating if R was flipped to achieve even Y.
    pub flipped: bool,
    /// The computed challenge scalar  `e = H_tag("MuSig/agg", R || X || m) mod n`.
    pub challenge: Option<Secp256k1Scalar>,
    /// The message being signed in this session.
    pub msg: Vec<u8>,
}

impl Musig1Session {
    /// Initialize a new MuSig1 session.
    ///
    /// # Parameters
    /// - `sk`: secret key of the current signer.
    /// - `pubkeys`: slice of public keys of all signers (including the current one).
    /// - `msg`: message to sign.
    /// - `use_pure`: if `true`, use the "pure" key-aggregation variant.
    ///
    /// # Returns
    /// A new `Musig1Session` instance with generated nonce and aggregated key state ready to be used for the signing protocol.
    pub fn new(
        sk: Secp256k1Scalar,
        pubkeys: Vec<Secp256k1Point>,
        msg: Vec<u8>,
        use_pure: bool,
    ) -> Self {
        let (X_agg, coeffs) = if use_pure {
            keyagg_pure(&pubkeys)
        } else {
            keyagg(&pubkeys)
        };
        let nonce = NonceCommitment::random().expect("nonce generation failed");
        Musig1Session {
            sk,
            pubkeys,
            X_agg,
            coeffs,
            nonce,
            commits: HashMap::new(),
            reveals: HashMap::new(),
            R_agg: None,
            flipped: false,
            challenge: None,
            msg,
        }
    }

    /// Generate our Round-1 commitment message to broadcast to peers.
    pub fn round1_commit(&self) -> Commit {
        self.nonce.commit()
    }

    /// Store a peer's Round-1 commitment.
    ///
    /// # Arguments
    /// - `id`: Unique index of the peer signer.
    /// - `c`: Their commitment value.
    pub fn receive_commit(&mut self, id: usize, c: Commit) {
        self.commits.insert(id, c);
    }

    /// Generate our Round-2 reveal once all commits are collected.
    pub fn round2_reveal(&self) -> Reveal {
        self.nonce.reveal()
    }

    /// Store a peer's Round-2 reveal message.
    ///
    /// # Arguments
    /// - `id`: Unique index of the peer signer.
    /// - `r`: Their reveal value.
    pub fn receive_reveal(&mut self, id: usize, r: Reveal) {
        self.reveals.insert(id, r);
    }

    /// Finalize nonces: aggregate all reveals into R_agg and apply flip to secret nonce.
    ///
    /// Panics if reveals are incomplete or aggregation fails.
    pub fn finalize_nonces(&mut self) {
        let mut pts = Vec::new();
        if self.pubkeys.len() > 1 {
            let peer_reveals: Vec<Reveal> = self.reveals.values().cloned().collect();
            if peer_reveals.len() != self.pubkeys.len() - 1 {
                panic!(
                    "Expected {} reveals, got {}",
                    self.pubkeys.len() - 1,
                    peer_reveals.len()
                );
            }
            pts = peer_reveals;
        }
        // Include our own reveal last
        pts.push(self.nonce.reveal());
        let (R, flip) = aggregate_nonces(&pts).expect("agg nonces");
        // Apply flip to our local nonce secret
        let mut n = self.nonce.clone();
        n.apply_flip(flip);
        self.nonce = n;
        self.R_agg = Some(R);
        self.flipped = flip;
    }

    /// Compute the MuSig challenge scalar `e = H_tag("MuSig/agg", R || X || m) mod n`.
    ///
    /// Must be called after `finalize_nonces()`.
    pub fn compute_challenge(&mut self) {
        let R = self.R_agg.clone().expect("no R_agg");
        self.challenge = Some(compute_challenge(&R, &self.X_agg, &self.msg));
    }

    /// Produce our partial signature `s_i = k_i + e * a_i * x_i`.
    ///
    /// # Arguments
    /// - `idx`: Index of this signer in the `pubkeys` list.
    pub fn partial_sig(&self, idx: usize) -> Secp256k1Scalar {
        let e = self.challenge.clone().unwrap();
        let a = &self.coeffs[idx];
        self.nonce.secret.clone() + &(a * &self.sk * &e)
    }

    /// Aggregate an array of partial signatures into the final single aggregate signature pair `(R, s)`.
    ///
    /// # Arguments
    /// - `partials`: Slice of each signer's partial scalar.
    pub fn aggregate_sig(&self, partials: &[Secp256k1Scalar]) -> (Secp256k1Point, Secp256k1Scalar) {
        let R = self.R_agg.clone().unwrap();
        let s = partials
            .iter()
            .cloned()
            .fold(Secp256k1Scalar::zero(), |acc, x| acc + &x);
        (R, s)
    }
}

#[cfg(test)]
mod musig1_tests {
    use super::*;
    use crypto_rs::{
        schnorr::schnorr_verify,
        secp256k1::{Secp256k1Point, Secp256k1Scalar},
    };
    use rand::rng;

    /// Generate a random keypair for testing.
    fn keypair() -> (Secp256k1Scalar, Secp256k1Point) {
        let mut rng = rng();
        let sk = Secp256k1Scalar::random(&mut rng);
        let pk = Secp256k1Point::generator() * &sk;
        (sk, pk)
    }

    #[test]
    fn two_party_musig1_flow_schnorr_verify() {
        let (sk1, pk1) = keypair();
        let (sk2, pk2) = keypair();
        let pubs = vec![pk1.clone(), pk2.clone()];
        let msg = b"The MuSig1 test".to_vec();
        let mut s1 = Musig1Session::new(sk1.clone(), pubs.clone(), msg.clone(), false);
        let mut s2 = Musig1Session::new(sk2.clone(), pubs.clone(), msg.clone(), false);

        // Round 1: commits
        let c1 = s1.round1_commit();
        let c2 = s2.round1_commit();
        s1.receive_commit(1, c2.clone());
        s2.receive_commit(0, c1.clone());

        // Round 2: reveals
        let r1 = s1.round2_reveal();
        let r2 = s2.round2_reveal();
        s1.receive_reveal(1, r2.clone());
        s2.receive_reveal(0, r1.clone());

        // Finalize nonces & compute challenge
        s1.finalize_nonces();
        s2.finalize_nonces();
        s1.compute_challenge();
        s2.compute_challenge();

        // Partial signatures
        let sig1 = s1.partial_sig(0);
        let sig2 = s2.partial_sig(1);

        // Aggregate signatures
        let (R, s) = s1.aggregate_sig(&[sig1, sig2]);

        // Encode into 64-byte signature: {R.x_only || s}
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&R.x_only_bytes());
        sig_bytes[32..].copy_from_slice(&s.to_bytes_be());

        // Verify the aggregate signature
        assert!(
            schnorr_verify(&s1.X_agg.x_only_bytes(), &msg, &sig_bytes),
            "MuSig1 aggregate signature should verify"
        );
        // Also verify using the second session
        assert!(
            schnorr_verify(&s2.X_agg.x_only_bytes(), &msg, &sig_bytes),
            "MuSig1 aggregate signature should verify"
        );
    }

    #[test]
    fn single_party_falls_back_to_schnorr_verify() {
        let (sk, pk) = keypair();
        let msg = b"Single-party test".to_vec();

        let mut s = Musig1Session::new(sk.clone(), vec![pk.clone()], msg.clone(), false);

        // No peers, so no commits or reveals
        let r = s.round2_reveal();
        s.receive_reveal(0, r.clone());
        s.finalize_nonces();
        s.compute_challenge();

        let sigma = s.partial_sig(0);
        let (R, s_final) = s.aggregate_sig(&[sigma]);

        // Encode and verify
        let r_bytes = R.x_only_bytes();
        let s_bytes = s_final.to_bytes_be();
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_bytes);
        sig[32..].copy_from_slice(&s_bytes);

        let pk_bytes = pk.x_only_bytes();
        assert!(
            schnorr_verify(&pk_bytes, &msg, &sig),
            "Single-party Musig1 must verify as Schnorr"
        );
    }

    #[test]
    #[should_panic(expected = "Expected 2 reveals")]
    fn finalize_without_all_reveals_panics() {
        // Three-party example but only 1 reveal inserted
        let (_, pk1) = keypair();
        let (_, pk2) = keypair();
        let (_, pk3) = keypair();
        let pubs = vec![pk1, pk2, pk3];
        let mut sess = Musig1Session::new(Secp256k1Scalar::zero(), pubs, b"".to_vec(), false);
        // Insert only one reveal
        sess.receive_reveal(1, sess.round2_reveal());
        sess.finalize_nonces();
    }

    #[test]
    fn flip_even_y_test() {
        let (sk1, pk1) = keypair();
        let (sk2, pk2) = keypair();
        let pubs = vec![pk1.clone(), pk2.clone()];
        let msg = b"Flip test".to_vec();
        let mut a = Musig1Session::new(sk1.clone(), pubs.clone(), msg.clone(), false);
        let mut b = Musig1Session::new(sk2.clone(), pubs.clone(), msg.clone(), false);
        let c1 = a.round1_commit();
        let c2 = b.round1_commit();
        a.receive_commit(1, c2.clone());
        b.receive_commit(0, c1.clone());
        let r1 = a.round2_reveal();
        let r2 = b.round2_reveal();
        a.receive_reveal(1, r2.clone());
        b.receive_reveal(0, r1.clone());
        a.finalize_nonces();
        // Check even Y
        assert!(!a.R_agg.unwrap().y_is_odd());
    }
}
