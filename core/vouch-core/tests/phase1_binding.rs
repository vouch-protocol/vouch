// Security regression tests for proofPurpose enforcement, verificationMethod
// to issuer binding (data_integrity), and the delegation time-attenuation
// widening fix (delegation).

use serde_json::json;
use vouch_core::data_integrity::{sign, verify_proof, BuildProofOptions};
use vouch_core::delegation::verify_chain_time_bound;
use vouch_core::keys::Ed25519KeyPair;

fn signed_credential() -> (serde_json::Value, Vec<u8>) {
    let seed = [7u8; 32];
    let kp = Ed25519KeyPair::from_seed_slice(&seed).unwrap();
    let cred = json!({
        "issuer": "did:web:test.example.com",
        "credentialSubject": { "id": "did:web:agent.example.com" }
    });
    let opts = BuildProofOptions::new(
        "did:web:test.example.com#key-1",
        "2025-01-01T00:00:00Z",
    );
    let signed = sign(&cred, &seed, &opts).unwrap();
    (signed, kp.public_key().to_vec())
}

#[test]
fn bound_credential_verifies() {
    let (cred, pk) = signed_credential();
    assert_eq!(verify_proof(&cred, &pk).unwrap(), true);
}

#[test]
fn wrong_proof_purpose_is_rejected() {
    let (mut cred, pk) = signed_credential();
    cred["proof"]["proofPurpose"] = json!("authentication");
    // Binding runs before signature verification, so this is an Err.
    assert!(verify_proof(&cred, &pk).is_err());
}

#[test]
fn cross_issuer_verification_method_is_rejected() {
    let (mut cred, pk) = signed_credential();
    cred["proof"]["verificationMethod"] = json!("did:web:attacker.example.com#key-1");
    assert!(verify_proof(&cred, &pk).is_err());
}

#[test]
fn delegation_child_omitting_bound_inherits_parent() {
    // Parent valid 2025-01-01..2025-01-02. Child omits validUntil and must not
    // be treated as unbounded: it inherits the parent's end, so a `now` after
    // the parent's window is rejected.
    let chain = vec![
        json!({ "validFrom": "2025-01-01T00:00:00Z", "validUntil": "2025-01-02T00:00:00Z" }),
        json!({ "validFrom": "2025-01-01T00:00:00Z" }),
    ];
    // now after parent's validUntil -> must be invalid (no widening).
    assert_eq!(
        verify_chain_time_bound(&chain, "2025-01-03T00:00:00Z", 0).unwrap(),
        false
    );
    // now inside the inherited window -> valid.
    assert_eq!(
        verify_chain_time_bound(&chain, "2025-01-01T12:00:00Z", 0).unwrap(),
        true
    );
}
