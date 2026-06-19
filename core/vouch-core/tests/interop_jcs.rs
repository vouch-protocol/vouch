//! Cross-implementation JCS interop test.
//!
//! Runs the shared RFC 8785 vectors in test-vectors/jcs/vectors.json (the same
//! vectors the TypeScript and Python SDKs run) through the Rust core. The Rust
//! output MUST be byte-identical to the published canonical form for every
//! vector, so a proof built by any implementation canonicalizes the same way.

use serde_json::Value;
use std::fs;

use vouch_core::jcs::canonicalize_to_string;

#[test]
fn jcs_interop_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/jcs/vectors.json"
    );
    let data = fs::read_to_string(path).expect("read jcs vectors");
    let doc: Value = serde_json::from_str(&data).expect("parse jcs vectors");
    let vectors = doc["vectors"].as_array().expect("vectors array");

    let mut failures = Vec::new();
    for v in vectors {
        let name = v["name"].as_str().unwrap_or("<unnamed>");
        let expected = v["canonical"].as_str().expect("canonical string");
        let got = canonicalize_to_string(&v["input"]);
        if got != expected {
            failures.push(format!("  {name}: got {got:?} want {expected:?}"));
        }
    }

    assert!(
        failures.is_empty(),
        "JCS interop mismatches ({}):\n{}",
        failures.len(),
        failures.join("\n")
    );
    eprintln!("JCS interop: {} vectors passed", vectors.len());
}
