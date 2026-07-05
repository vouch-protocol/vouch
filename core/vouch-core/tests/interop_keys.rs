//! Cross-implementation key interop.
//!
//! Asserts that the Rust core derives the SAME Ed25519 public key from a seed as
//! the reference SDK, using the shared hybrid vector. If keygen drifts, a proof
//! signed by one implementation will not verify in another, so this KAT guards
//! the most basic interop property.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;
use std::fs;

use vouch_core::keys::{did_key_to_ed25519, ed25519_to_did_key, Ed25519KeyPair};
use vouch_core::multikey;

fn hybrid_vector() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/hybrid-eddsa-mldsa44/vector.json"
    );
    serde_json::from_str(&fs::read_to_string(path).expect("read hybrid vector"))
        .expect("parse hybrid vector")
}

#[test]
fn ed25519_seed_to_public_kat() {
    let v = hybrid_vector();
    let seed_b64 = v["ed25519"]["seed_b64"].as_str().expect("seed_b64");
    let pub_b64 = v["ed25519"]["public_key_b64"]
        .as_str()
        .expect("public_key_b64");

    let seed = STANDARD.decode(seed_b64).expect("decode seed");
    let kp = Ed25519KeyPair::from_seed_slice(&seed).expect("from seed");
    let derived = STANDARD.encode(kp.public_key());

    assert_eq!(
        derived, pub_b64,
        "Rust Ed25519 keygen must derive the same public key as the reference SDK"
    );
}

#[test]
fn mldsa44_public_key_multikey_roundtrips() {
    // The shared vector carries a real 1312-byte ML-DSA-44 public key; confirm
    // the multikey encode/decode handles it (used by the hybrid PQ profile).
    let v = hybrid_vector();
    let pub_b64 = v["mldsa44"]["public_key_b64"]
        .as_str()
        .expect("mldsa44 pub");
    let raw = STANDARD.decode(pub_b64).expect("decode mldsa pub");
    assert_eq!(raw.len(), 1312, "ML-DSA-44 public key is 1312 bytes");
    let mk = multikey::encode_mldsa44_public(&raw).expect("encode mldsa multikey");
    let decoded = multikey::decode(&mk).expect("decode mldsa multikey");
    assert_eq!(decoded.algorithm, "ML-DSA-44");
    assert_eq!(decoded.raw_key, raw);
}

#[test]
fn did_key_uses_ed25519_multikey() {
    let v = hybrid_vector();
    let pub_b64 = v["ed25519"]["public_key_b64"].as_str().unwrap();
    let raw = STANDARD.decode(pub_b64).unwrap();
    let did = ed25519_to_did_key(&raw).unwrap();
    assert!(did.starts_with("did:key:z6Mk"));
    assert_eq!(did_key_to_ed25519(&did).unwrap(), raw);
}
