//! MuSig1: Multi-signature Schnorr implementation (n-of-n) using secp256k1.
//! Uses crypto-rs v0.1.0 (<https://github.com/BEULAHEVANJALIN/crypto-rs>) for elliptic curve operations.
#![allow(non_snake_case)]
mod keyagg;
pub use keyagg::keyagg;
pub use keyagg::keyagg_pure;
mod nonce;
pub use nonce::NonceCommitment;
pub use nonce::aggregate_nonces;
mod challenge;
pub use challenge::compute_challenge;
pub mod session;
pub mod sign;
pub mod verify;
