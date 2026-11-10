//! Delegation chain verification against the shared vector (Rust side).
//!
//! The Python reference (tests/test_delegation_chain_vectors.py), the TypeScript
//! SDK, and the Go sidecar read the SAME vector and must return the SAME verdict
//! for every case.

use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;

use vouch_core::credentials;
use vouch_core::delegation::verify_delegation_chain;
use vouch_core::multikey;

fn cases() -> Vec<Value> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/delegation-chain/vector.json"
    );
    let v: Value =
        serde_json::from_str(&fs::read_to_string(path).expect("read delegation-chain vector"))
            .expect("parse vector");
    v["cases"].as_array().expect("cases").clone()
}

#[test]
fn chain_verdicts_match_reference() {
    let cases = cases();
    assert!(cases.len() >= 16);
    for case in &cases {
        let name = case["name"].as_str().unwrap();
        let now = case["now"].as_str().unwrap();
        let got = verify_delegation_chain(&case["credential"], now, 30, &BTreeMap::new(), None);
        let expected = case["expected"].as_str().map(String::from);
        assert_eq!(got, expected, "case {name}");
    }
}

#[test]
fn full_verify_agrees_with_chain_verdict() {
    for case in cases() {
        let name = case["name"].as_str().unwrap();
        let cred = &case["credential"];
        let issuer = cred["issuer"].as_str().unwrap();
        let key = multikey::decode(issuer.strip_prefix("did:key:").unwrap())
            .unwrap()
            .raw_key;
        let r = credentials::verify(cred, &key, case["now"].as_str().unwrap(), 30).unwrap();
        assert_eq!(r.is_valid(), case["expected"].is_null(), "case {name}");
    }
}

#[test]
fn untrusted_root_is_refused_when_roots_are_pinned() {
    let valid = cases()
        .into_iter()
        .find(|c| c["name"] == "valid_two_hop")
        .unwrap();
    let now = valid["now"].as_str().unwrap();
    let pinned = vec!["did:key:z6MkNotTheRoot".to_string()];
    assert_eq!(
        verify_delegation_chain(
            &valid["credential"],
            now,
            30,
            &BTreeMap::new(),
            Some(&pinned)
        ),
        Some("untrusted_principal".to_string())
    );
}
