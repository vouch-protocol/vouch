//! Round-trip interop on the shared eddsa-jcs-2022 vector (Rust side).
//!
//! The companion test in the TypeScript SDK
//! (packages/sdk-ts/tests/core-eddsa-interop.test.ts) reads the SAME vector and
//! asserts the SAME two properties, proving Rust and TS agree byte-for-byte.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;
use std::fs;

use vouch_core::data_integrity::{build_proof, verify_proof, BuildProofOptions};

fn vector() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/data-integrity-eddsa-jcs-2022/vector.json"
    );
    serde_json::from_str(&fs::read_to_string(path).expect("read eddsa vector"))
        .expect("parse eddsa vector")
}

#[test]
fn verifies_shared_signed_credential() {
    let v = vector();
    let pub_key = STANDARD
        .decode(v["ed25519"]["public_key_b64"].as_str().unwrap())
        .unwrap();
    assert!(
        verify_proof(&v["signed_credential"], &pub_key).unwrap(),
        "Rust must verify the shared signed credential"
    );
}

#[test]
fn reproduces_shared_proof_value() {
    let v = vector();
    let seed = STANDARD
        .decode(v["ed25519"]["seed_b64"].as_str().unwrap())
        .unwrap();
    let opts = BuildProofOptions::new(
        v["verificationMethod"].as_str().unwrap().to_string(),
        v["created"].as_str().unwrap().to_string(),
    );
    let proof = build_proof(&v["unsigned_credential"], &seed, &opts).unwrap();
    assert_eq!(
        proof["proofValue"], v["proofValue"],
        "Rust must reproduce the shared proofValue exactly"
    );
}
