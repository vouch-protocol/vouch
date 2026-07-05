//! Revocation interop against the shared BitstringStatusList vector.
//!
//! The Rust core must decode the Python-generated `expected_encoded_list` and
//! report the SAME revoked/active bits, and `verify_status` must agree with the
//! sample credentialStatus entries. (Decode/gunzip is deterministic, so this
//! interoperates with lists from any SDK regardless of the compressor used.)

use serde_json::Value;
use std::fs;

use vouch_core::status_list::{
    decode_bitstring, encode_bitstring, get_status, set_status, verify_status,
    DEFAULT_BITSTRING_LENGTH,
};

fn vector() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/bitstring-status-list/vector.json"
    );
    serde_json::from_str(&fs::read_to_string(path).expect("read status vector"))
        .expect("parse status vector")
}

#[test]
fn decodes_shared_list_and_reports_correct_bits() {
    let v = vector();
    let encoded = v["expected_encoded_list"].as_str().unwrap();
    let bits = decode_bitstring(encoded).unwrap();
    assert_eq!(
        bits.len() * 8,
        v["bitstring_length_bits"].as_u64().unwrap() as usize
    );

    for idx in v["revoked_indices"].as_array().unwrap() {
        let i = idx.as_u64().unwrap() as usize;
        assert!(get_status(&bits, i).unwrap(), "index {i} must be revoked");
    }
    for idx in v["active_indices_sample"].as_array().unwrap() {
        let i = idx.as_u64().unwrap() as usize;
        assert!(!get_status(&bits, i).unwrap(), "index {i} must be active");
    }
}

#[test]
fn verify_status_matches_sample_entries() {
    let v = vector();
    let sl = &v["status_list_credential"];
    assert!(
        verify_status(&v["sample_credential_status_revoked"], sl).unwrap(),
        "revoked sample must report set"
    );
    assert!(
        !verify_status(&v["sample_credential_status_active"], sl).unwrap(),
        "active sample must report unset"
    );
}

#[test]
fn reencode_is_semantically_equivalent_to_shared_vector() {
    // Rebuild the bitstring from revoked_indices, encode it, and confirm it
    // decodes to the SAME bits as the Python-generated list. The compressed
    // bytes need not be identical (pure-Rust DEFLATE differs from zlib's), but
    // the decoded content is, which is what a verifier relies on.
    let v = vector();
    let mut bits = vec![0u8; DEFAULT_BITSTRING_LENGTH / 8];
    for idx in v["revoked_indices"].as_array().unwrap() {
        set_status(&mut bits, idx.as_u64().unwrap() as usize, true).unwrap();
    }
    let rust_encoded = encode_bitstring(&bits).unwrap();
    let from_rust = decode_bitstring(&rust_encoded).unwrap();
    let from_vector = decode_bitstring(v["expected_encoded_list"].as_str().unwrap()).unwrap();
    assert_eq!(
        from_rust, from_vector,
        "Rust-encoded list must decode to the same bits as the shared vector"
    );
}
