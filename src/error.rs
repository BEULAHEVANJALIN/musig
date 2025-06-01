use crate::nonce::NonceError;
use thiserror::Error;

/// Errors that can occur during the MuSig1 (and related) signing process.
#[derive(Debug, Error, PartialEq)]
pub enum MusigError {
    /// Not enough peer commitments collected.
    #[error("missing {expected} commits, got {got}")]
    MissingCommits {
        /// Number of commitments expected (n − 1 for multi-party, or 0 for single-party).
        expected: usize,
        /// Number of commitments actually received.
        got: usize,
    },

    /// Not enough peer reveals collected.
    #[error("missing {expected} reveals, got {got}")]
    MissingReveals {
        /// Number of reveals expected (n − 1 for multi-party, or 0 for single-party).
        expected: usize,
        /// Number of reveals actually received.
        got: usize,
    },

    /// Not enough peer partials collected.
    #[error("missing {expected} partials, got {got}")]
    MissingPartials {
        /// Number of partials expected (equal to number of participants).
        expected: usize,
        /// Number of partials actually provided.
        got: usize,
    },

    /// A nonce‐generation error (e.g. zero scalar, invalid point).
    #[error("nonce error: {0}")]
    Nonce(#[from] NonceError),

    /// The input public key was invalid.
    #[error("invalid public key")]
    InvalidPubkey,
    // (You can add more high-level variants here, e.g. for challenge errors, key aggregation errors, etc.)
}
