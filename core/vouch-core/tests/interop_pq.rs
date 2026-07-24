//! Post-quantum interop: can the Rust FIPS-204 core verify an ML-DSA-44
//! signature produced by the SDK's `@noble/post-quantum`?
//!
//! The shared hybrid vector carries a composite proofValue =
//! base58btc(ed25519_sig(64) || mldsa44_sig(2420)) over the SHA-256 digest of
//! the JCS-canonical credential (with unsigned proof). We split out the ML-DSA
//! signature and verify it against the vector's ML-DSA public key. Success
//! proves cross-library ML-DSA verification interop (the property that matters,
//! since ML-DSA signing is randomized and not byte-reproducible).

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{Map, Value};
use std::fs;

use vouch_core::data_integrity::legacy_proof_digest;
use vouch_core::hybrid;
use vouch_core::pq;

const ED25519_SIG_LEN: usize = 64;

fn hybrid_vector() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/hybrid-eddsa-mldsa44/vector.json"
    );
    serde_json::from_str(&fs::read_to_string(path).expect("read hybrid vector"))
        .expect("parse hybrid vector")
}

#[test]
fn verifies_noble_mldsa_signature() {
    let v = hybrid_vector();
    let mldsa_pub = STANDARD
        .decode(v["mldsa44"]["public_key_b64"].as_str().unwrap())
        .unwrap();

    let sc = &v["signed_credential"];
    let mut unsigned: Map<String, Value> = sc["proof"].as_object().unwrap().clone();
    unsigned.remove("proofValue");
    let mut cred = sc.clone();
    cred.as_object_mut().unwrap().remove("proof");
    // The shared vector is the v1.6.x composite, signed over the pre-alignment
    // digest, so the ML-DSA signature verifies against that digest.
    let digest = legacy_proof_digest(&cred, &unsigned).unwrap();

    let proof_value = sc["proof"]["proofValue"].as_str().unwrap();
    let combined = bs58::decode(&proof_value[1..]).into_vec().unwrap();
    assert_eq!(combined.len(), ED25519_SIG_LEN + pq::MLDSA44_SIG_LEN);
    let mldsa_sig = &combined[ED25519_SIG_LEN..];

    assert!(
        pq::verify(&mldsa_pub, &digest, mldsa_sig).unwrap(),
        "Rust FIPS-204 must verify the SDK's @noble ML-DSA-44 signature"
    );
}

#[test]
fn verifies_shared_composite_credential_end_to_end() {
    // Verify the full v1.6.x composite hybrid credential (both Ed25519 and
    // ML-DSA-44 signatures) from the shared vector, against both public keys.
    let v = hybrid_vector();
    let ed_pub = STANDARD
        .decode(v["ed25519"]["public_key_b64"].as_str().unwrap())
        .unwrap();
    let ml_pub = STANDARD
        .decode(v["mldsa44"]["public_key_b64"].as_str().unwrap())
        .unwrap();
    assert!(
        hybrid::verify_composite(&v["signed_credential"], &ed_pub, &ml_pub).unwrap(),
        "Rust must verify the shared composite hybrid credential end to end"
    );
}

#[test]
fn imports_shared_keypair_and_signs() {
    // Load the vector's real ML-DSA secret/public key, sign, and self-verify,
    // confirming the key import path works on standard FIPS 204 key bytes.
    let v = hybrid_vector();
    let pk = STANDARD
        .decode(v["mldsa44"]["public_key_b64"].as_str().unwrap())
        .unwrap();
    let sk = STANDARD
        .decode(v["mldsa44"]["secret_key_b64"].as_str().unwrap())
        .unwrap();
    let kp = pq::MlDsa44KeyPair::from_bytes(&sk, &pk).unwrap();
    let sig = kp.sign(b"interop").unwrap();
    assert!(pq::verify(&kp.public_key(), b"interop", &sig).unwrap());
}
