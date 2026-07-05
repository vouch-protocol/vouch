//! Error type for the Vouch core.

use std::fmt;

/// Errors returned by the protocol core. Kept small and stable so the WASM and
/// UniFFI/C-FFI wrappers can surface them uniformly across languages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// A key had the wrong length for its algorithm.
    InvalidKeyLength { expected: usize, got: usize },
    /// A multikey string was malformed (bad prefix, bad base58, too short).
    InvalidMultikey(String),
    /// The multicodec prefix did not match a supported algorithm.
    UnknownMulticodec(String),
    /// A DID string was malformed or used an unsupported method.
    InvalidDid(String),
    /// A signature length was wrong.
    InvalidSignatureLength { expected: usize, got: usize },
    /// A cryptographic operation failed (keygen RNG, parse, etc.).
    Crypto(String),
    /// JSON was malformed or had an unexpected shape.
    Json(String),
    /// A FROST threshold-signing operation failed (bad share, wrong
    /// participant count, mismatched commitments).
    Threshold(String),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::InvalidKeyLength { expected, got } => {
                write!(f, "invalid key length: expected {expected} bytes, got {got}")
            }
            CoreError::InvalidMultikey(m) => write!(f, "invalid multikey: {m}"),
            CoreError::UnknownMulticodec(m) => write!(f, "unknown multicodec prefix: {m}"),
            CoreError::InvalidDid(m) => write!(f, "invalid did: {m}"),
            CoreError::InvalidSignatureLength { expected, got } => {
                write!(f, "invalid signature length: expected {expected} bytes, got {got}")
            }
            CoreError::Crypto(m) => write!(f, "crypto error: {m}"),
            CoreError::Json(m) => write!(f, "json error: {m}"),
            CoreError::Threshold(m) => write!(f, "threshold signing error: {m}"),
        }
    }
}

impl std::error::Error for CoreError {}

/// Convenience alias for results in the core.
pub type Result<T> = std::result::Result<T, CoreError>;
