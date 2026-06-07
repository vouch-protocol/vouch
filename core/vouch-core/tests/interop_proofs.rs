//! Cross-implementation Data Integrity interop.
//!
//! The hybrid vector publishes `expected_canonical_sha256_b64`, the base64 of
//! SHA-256 over the JCS canonical form of the credential with its unsigned proof
//! attached. That is exactly the eddsa-jcs-2022 signing preimage. Reproducing it
//! in Rust proves the JCS + SHA-256 pipeline matches the reference SDK on a real
//! credential, so a signature over the digest is computed on identical bytes
//! across implementations.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{Map, Value};
use std::fs;

use vouch_core::data_integrity::proof_digest;

#[test]
fn jcs_sha256_digest_matches_shared_vector() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/hybrid-eddsa-mldsa44/vector.json"
    );
    let doc: Value = serde_json::from_str(&fs::read_to_string(path).expect("read hybrid vector"))
        .expect("parse hybrid vector");
    let expected = doc["expected_canonical_sha256_b64"]
        .as_str()
        .expect("expected_canonical_sha256_b64");
    let sc = &doc["signed_credential"];

    let mut unsigned: Map<String, Value> = sc["proof"].as_object().expect("proof object").clone();
    unsigned.remove("proofValue");

    let mut cred = sc.clone();
    cred.as_object_mut().unwrap().remove("proof");

    let digest = proof_digest(&cred, &unsigned).expect("digest");
    let got = STANDARD.encode(digest);

    assert_eq!(
        got, expected,
        "Rust JCS + SHA-256 digest must match the shared vector"
    );
}
