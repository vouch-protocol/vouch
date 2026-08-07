//! Round-trip interop on the shared Authority Freshness vector (Rust side).
//!
//! The companion runners in Python (tests/test_authority_state_vectors.py), the
//! TypeScript SDK, and the Go sidecar read the SAME vector and assert the SAME
//! properties, proving every language agrees byte-for-byte on the AuthorityState
//! proof and on the epoch-collapse rule.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;
use std::fs;

use vouch_core::authority_state::{evaluate_authority_freshness, verify};
use vouch_core::data_integrity::{build_proof, BuildProofOptions};

fn vector() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/authority-state/vector.json"
    );
    serde_json::from_str(&fs::read_to_string(path).expect("read authority-state vector"))
        .expect("parse authority-state vector")
}

#[test]
fn verifies_shared_signed_credential() {
    let v = vector();
    let pub_key = STANDARD
        .decode(v["ed25519"]["public_key_b64"].as_str().unwrap())
        .unwrap();
    let result = verify(
        &v["signed_credential"],
        &pub_key,
        "2026-07-26T10:02:00Z",
        30,
    )
    .unwrap();
    assert!(
        result.is_valid(),
        "Rust must verify the shared AuthorityState credential"
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

#[test]
fn rejects_stale_epoch_tamper() {
    let v = vector();
    let pub_key = STANDARD
        .decode(v["ed25519"]["public_key_b64"].as_str().unwrap())
        .unwrap();
    let mut tampered = v["signed_credential"].clone();
    tampered["credentialSubject"]["authorityEpoch"] = serde_json::json!(999);
    let result = verify(&tampered, &pub_key, "2026-07-26T10:02:00Z", 30).unwrap();
    assert!(
        !result.proof_valid,
        "Rust must reject a credential whose epoch was tampered after signing"
    );
}

#[test]
fn freshness_cases_match() {
    let v = vector();
    for case in v["freshness"]["cases"].as_array().unwrap() {
        let tier = case["tier"].as_str().unwrap();
        let voucher_epoch = case["voucher_epoch"].as_i64();
        let last_seen_epoch = case["last_seen_epoch"].as_i64();
        let current_status = case["current_status"].as_str();
        let live_cosign_ok = case["live_cosign_ok"].as_bool();
        let verdict = evaluate_authority_freshness(
            tier,
            voucher_epoch,
            last_seen_epoch,
            current_status,
            live_cosign_ok,
        );
        let name = case["name"].as_str().unwrap();
        assert_eq!(
            verdict.allow,
            case["expected_allow"].as_bool().unwrap(),
            "allow mismatch for {name}"
        );
        if let Some(expected_reason) = case.get("expected_reason").and_then(|r| r.as_str()) {
            assert_eq!(
                verdict.reason, expected_reason,
                "reason mismatch for {name}"
            );
        }
    }
}
