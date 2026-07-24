//! Interop: the shared delegation-attenuation vectors are the cross-language
//! contract. This test pins the Rust core to `test-vectors/delegation-attenuation/
//! vector.json`; the Python, Go, and TypeScript SDKs run the same file and MUST
//! produce identical verdicts.

use serde_json::Value;
use vouch_core::attenuation::validate_chain_json;

fn load_vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/delegation-attenuation/vector.json"
    );
    let text = std::fs::read_to_string(path).expect("read delegation vectors");
    serde_json::from_str(&text).expect("parse delegation vectors")
}

#[test]
fn core_matches_delegation_vectors() {
    let vectors = load_vectors();
    let cases = vectors["cases"].as_array().expect("cases array");
    assert!(!cases.is_empty(), "vector file has no cases");

    for case in cases {
        let name = case["name"].as_str().unwrap_or("<unnamed>");
        let request = case["request"].to_string();
        let expect = &case["expect"];

        let verdict: Value =
            serde_json::from_str(&validate_chain_json(&request)).expect("verdict is json");

        assert_eq!(
            verdict["valid"], expect["valid"],
            "case {name}: valid mismatch (got {verdict})"
        );

        if expect["valid"] == Value::Bool(false) {
            assert_eq!(
                verdict["code"], expect["code"],
                "case {name}: code mismatch (got {verdict})"
            );
            for field in ["dimension", "limit", "linkIndex"] {
                if !expect[field].is_null() {
                    assert_eq!(
                        verdict[field], expect[field],
                        "case {name}: {field} mismatch (got {verdict})"
                    );
                }
            }
        }
    }
}
