//! Intent-recheck interop against the shared, Python-generated vector.
//!
//! The Rust core must agree with the reference on the SAME bytes: a seal built in
//! Python (the credential's `eddsa-jcs-2022` proof) verifies here, the pinned
//! `justification_digest` recomputes byte-for-byte, and `verify_intent_freshness`
//! returns the SAME reason string for every case, so a fresh seal is accepted and
//! a stale seal is rejected identically across languages.

use serde_json::Value;
use std::fs;

use vouch_core::data_integrity::verify_proof;
use vouch_core::reasoning::{
    check_reasoned_action, default_requirement, justification_digest, verify_intent_freshness,
};

fn vector() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/intent-recheck/vector.json"
    );
    serde_json::from_str(&fs::read_to_string(path).expect("read intent-recheck vector"))
        .expect("parse intent-recheck vector")
}

fn public_key(v: &Value) -> Vec<u8> {
    let hex = v["public_key_hex"].as_str().unwrap();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn justification_digest_matches_reference() {
    let v = vector();
    let digest = justification_digest(&v["reference_justification"]).unwrap();
    assert_eq!(
        digest,
        v["expected_justification_digest"].as_str().unwrap(),
        "JCS justification digest must match the Python reference byte for byte"
    );
}

#[test]
fn cross_language_signature_verifies() {
    let v = vector();
    let pk = public_key(&v);
    for case in v["cases"].as_array().unwrap() {
        let cred = &case["credential"];
        assert!(
            verify_proof(cred, &pk).unwrap(),
            "case {}: Python-signed credential must verify in Rust",
            case["name"]
        );
        // signature + commitment gate agrees
        assert!(
            check_reasoned_action(cred, &pk, None, false).is_none(),
            "case {}: check_reasoned_action must pass",
            case["name"]
        );
    }
}

#[test]
fn intent_freshness_verdict_matches_every_case() {
    let v = vector();
    for case in v["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let tier = case["tier"].as_i64().unwrap();
        let last_pulse = case["last_pulse"].as_str().unwrap();
        let cred = &case["credential"];

        let got =
            verify_intent_freshness(cred, tier, last_pulse, default_requirement(tier)).unwrap();
        let expected = case["expected_reason"].as_str();

        assert_eq!(
            got.as_deref(),
            expected,
            "case {name}: intent-freshness verdict must match the reference (null == accepted)"
        );
    }
}
