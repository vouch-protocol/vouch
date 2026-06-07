//! Generate the shared `eddsa-jcs-2022` interop vector.
//!
//! Run once with: `cargo run --example generate_eddsa_vector`. The output is a
//! deterministic credential + proof (fixed seed, fixed `created`), so both the
//! Rust core and the TypeScript SDK can assert they reproduce the exact same
//! proofValue and that each verifies the other's output.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

use vouch_core::data_integrity::{build_proof, BuildProofOptions};
use vouch_core::keys::Ed25519KeyPair;

fn main() {
    // Reuse the shared hybrid Ed25519 seed so the public key is a known value.
    let seed_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=";
    let seed = STANDARD.decode(seed_b64).expect("decode seed");
    let kp = Ed25519KeyPair::from_seed_slice(&seed).expect("from seed");
    let public_key_b64 = STANDARD.encode(kp.public_key());

    let verification_method = "did:web:test.example.com#key-1";
    let created = "2026-04-26T10:00:00Z";

    let unsigned: Value = json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://vouch-protocol.com/contexts/v1"
        ],
        "type": ["VerifiableCredential", "VouchCredential"],
        "issuer": "did:web:test.example.com",
        "validFrom": "2026-04-26T10:00:00Z",
        "validUntil": "2026-04-26T10:05:00Z",
        "credentialSubject": {
            "id": "did:web:test.example.com",
            "vouchVersion": "1.0",
            "intent": {
                "action": "read_database",
                "target": "users_table",
                "resource": "https://api.example.com/v1/users"
            }
        }
    });

    let opts = BuildProofOptions::new(verification_method, created);
    let proof = build_proof(&unsigned, &seed, &opts).expect("build proof");

    let mut signed = unsigned.clone();
    signed
        .as_object_mut()
        .unwrap()
        .insert("proof".into(), proof.clone());

    let vector = json!({
        "description": "Shared eddsa-jcs-2022 Data Integrity interop vector. The Rust core, the TypeScript SDK, and Python MUST (1) reproduce proofValue exactly from (ed25519.seed_b64, unsigned_credential, verificationMethod, created), and (2) verify signed_credential against ed25519.public_key_b64. Ed25519 (RFC 8032), JCS (RFC 8785), and SHA-256 are all deterministic, so the proofValue is reproducible byte-for-byte.",
        "cryptosuite": "eddsa-jcs-2022",
        "ed25519": { "seed_b64": seed_b64, "public_key_b64": public_key_b64 },
        "verificationMethod": verification_method,
        "created": created,
        "unsigned_credential": unsigned,
        "signed_credential": signed,
        "proofValue": proof["proofValue"]
    });

    let mut out = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    out.push("../../test-vectors/data-integrity-eddsa-jcs-2022/vector.json");
    fs::create_dir_all(out.parent().unwrap()).expect("mkdir");
    let mut text = serde_json::to_string_pretty(&vector).expect("serialize");
    text.push('\n');
    fs::write(&out, text).expect("write vector");
    println!("wrote {}", out.display());
    println!("proofValue = {}", proof["proofValue"]);
}
