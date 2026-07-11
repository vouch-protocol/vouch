//! Vouch Protocol canonical core.
//!
//! One byte-exact Rust implementation of the protocol primitives (JCS
//! canonicalization, Ed25519 and ML-DSA proofs, did:key/multikey, Data Integrity
//! eddsa-jcs-2022, credentials, delegation, revocation), shared by every language
//! SDK through WASM and UniFFI/C-FFI so that no primitive is re-derived per
//! language. Behavior MUST match the TypeScript reference SDK byte-for-byte and
//! pass the shared interop vectors in `test-vectors/`.

pub mod credentials;
pub mod data_integrity;
pub mod delegation;
pub mod error;
pub mod hybrid;
pub mod jcs;
pub mod keys;
pub mod multikey;
pub mod pq;
pub mod recovery;
pub mod recovery_json;
pub mod robotics;
pub mod robotics_json;
pub mod status_list;
pub mod threshold;
pub mod threshold_json;
pub mod time;

pub use error::{CoreError, Result};
