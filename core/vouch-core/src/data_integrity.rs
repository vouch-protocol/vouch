//! Data Integrity proofs, cryptosuite `eddsa-jcs-2022`.
//!
//! Signing input follows the W3C Data Integrity hashing algorithm, so proofs
//! issued here verify under any conformant `eddsa-jcs-2022` implementation:
//!   1. Build the proof configuration (the unsigned proof plus the document's
//!      `@context`) and JCS-canonicalize it (RFC 8785).
//!   2. JCS-canonicalize the unsecured document (the credential with no proof).
//!   3. hashData = SHA-256(canonical proof configuration)
//!                 || SHA-256(canonical document)   (64 bytes, config first).
//!   4. Ed25519-sign hashData.
//!   5. proofValue = "z" + base58btc(signature).
//!
//! Verification also accepts the pre-alignment signing input (a single SHA-256
//! over the JCS form of the credential with the unsigned proof attached) so
//! credentials issued before this alignment keep verifying. See
//! [`legacy_proof_digest`].

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::error::{CoreError, Result};
use crate::jcs;
use crate::keys::{self, Ed25519KeyPair};

pub const CRYPTOSUITE_ID: &str = "eddsa-jcs-2022";
pub const PROOF_TYPE: &str = "DataIntegrityProof";

/// Options for building a proof. `created` is supplied by the caller (an
/// ISO-8601 instant such as "2026-04-26T10:00:00Z") so proofs are deterministic
/// and reproducible across implementations.
#[derive(Debug, Clone)]
pub struct BuildProofOptions {
    pub verification_method: String,
    pub proof_purpose: String,
    pub created: String,
}

impl BuildProofOptions {
    pub fn new(verification_method: impl Into<String>, created: impl Into<String>) -> Self {
        Self {
            verification_method: verification_method.into(),
            proof_purpose: "assertionMethod".to_string(),
            created: created.into(),
        }
    }
}

fn unsigned_proof(opts: &BuildProofOptions) -> Map<String, Value> {
    // Field insertion order matches the reference SDK so the emitted proof is
    // byte-identical. JCS sorts keys for signing, so order is irrelevant to the
    // signature, but it keeps the stored document stable across SDKs.
    let mut proof = Map::new();
    proof.insert("type".into(), Value::String(PROOF_TYPE.into()));
    proof.insert("cryptosuite".into(), Value::String(CRYPTOSUITE_ID.into()));
    proof.insert("created".into(), Value::String(opts.created.clone()));
    proof.insert(
        "verificationMethod".into(),
        Value::String(opts.verification_method.clone()),
    );
    proof.insert(
        "proofPurpose".into(),
        Value::String(opts.proof_purpose.clone()),
    );
    proof
}

/// Strip any `proof` member, yielding the unsecured document.
fn unsecured_document(credential: &Value) -> Result<Value> {
    let mut doc = credential.clone();
    doc.as_object_mut()
        .ok_or_else(|| CoreError::Json("credential must be a JSON object".into()))?
        .remove("proof");
    Ok(doc)
}

/// Build the proof configuration: the unsigned proof carrying the document's
/// `@context`, per the Data Integrity proof configuration algorithm.
fn proof_configuration(
    document: &Value,
    unsigned: &Map<String, Value>,
) -> Result<Map<String, Value>> {
    let mut config = unsigned.clone();
    config.remove("proofValue");
    if let Some(ctx) = document.get("@context") {
        config.insert("@context".into(), ctx.clone());
    }
    Ok(config)
}

/// Compute the 64-byte W3C Data Integrity signing input for a JCS cryptosuite:
/// SHA-256 of the canonical proof configuration, joined with SHA-256 of the
/// canonical unsecured document. This is the value that gets signed.
pub fn hash_data(credential: &Value, unsigned: &Map<String, Value>) -> Result<[u8; 64]> {
    let document = unsecured_document(credential)?;
    let config = proof_configuration(&document, unsigned)?;

    let config_hash = Sha256::digest(&jcs::canonicalize(&Value::Object(config)));
    let document_hash = Sha256::digest(&jcs::canonicalize(&document));

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&config_hash);
    out[32..].copy_from_slice(&document_hash);
    Ok(out)
}

/// The pre-alignment signing input: a single SHA-256 over the JCS canonical form
/// of the credential with the unsigned proof attached. Retained so credentials
/// issued before the Data Integrity alignment continue to verify. Never used for
/// new proofs.
pub fn legacy_proof_digest(credential: &Value, unsigned: &Map<String, Value>) -> Result<[u8; 32]> {
    let mut with_proof = credential.clone();
    with_proof
        .as_object_mut()
        .ok_or_else(|| CoreError::Json("credential must be a JSON object".into()))?
        .insert("proof".into(), Value::Object(unsigned.clone()));
    let canonical = jcs::canonicalize(&with_proof);
    let digest = Sha256::digest(&canonical);
    Ok(digest.into())
}

/// Build an `eddsa-jcs-2022` proof for `credential` using a raw 32-byte Ed25519
/// seed. Returns the proof object (the caller attaches it, or use `sign`).
pub fn build_proof(
    credential: &Value,
    raw_private_seed: &[u8],
    opts: &BuildProofOptions,
) -> Result<Value> {
    let kp = Ed25519KeyPair::from_seed_slice(raw_private_seed)?;
    let mut proof = unsigned_proof(opts);
    let signing_input = hash_data(credential, &proof)?;
    let signature = kp.sign(&signing_input);
    let proof_value = format!("z{}", bs58::encode(signature).into_string());
    proof.insert("proofValue".into(), Value::String(proof_value));
    Ok(Value::Object(proof))
}

/// Sign a credential: build the proof and return the credential with `proof`
/// attached.
pub fn sign(
    credential: &Value,
    raw_private_seed: &[u8],
    opts: &BuildProofOptions,
) -> Result<Value> {
    let proof = build_proof(credential, raw_private_seed, opts)?;
    let mut signed = credential.clone();
    signed
        .as_object_mut()
        .ok_or_else(|| CoreError::Json("credential must be a JSON object".into()))?
        .insert("proof".into(), proof);
    Ok(signed)
}

/// Verify an `eddsa-jcs-2022` proof attached to `credential` against a raw
/// 32-byte Ed25519 public key. Returns Ok(true) on a valid signature, Ok(false)
/// on a signature mismatch, Err on a malformed proof.
///
/// SECURITY: this checks the signature against the key you pass, NOT that the
/// key belongs to the `verificationMethod` the proof claims. Resolve the key
/// from [`proof_verification_method`] (or otherwise confirm the key-to-method
/// binding) so a credential cannot claim one method while being signed by
/// another key you happen to trust.
pub fn verify_proof(credential: &Value, raw_public_key: &[u8]) -> Result<bool> {
    let obj = credential
        .as_object()
        .ok_or_else(|| CoreError::Json("credential must be a JSON object".into()))?;
    let proof = obj
        .get("proof")
        .and_then(|p| p.as_object())
        .ok_or_else(|| CoreError::Json("credential has no proof object".into()))?;

    match proof.get("type").and_then(|v| v.as_str()) {
        Some(PROOF_TYPE) => {}
        other => return Err(CoreError::Json(format!("unexpected proof type: {other:?}"))),
    }
    match proof.get("cryptosuite").and_then(|v| v.as_str()) {
        Some(CRYPTOSUITE_ID) => {}
        other => {
            return Err(CoreError::Json(format!(
                "unexpected cryptosuite: {other:?}"
            )))
        }
    }
    let proof_value = proof
        .get("proofValue")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CoreError::Json("missing proofValue".into()))?;
    let body = proof_value
        .strip_prefix('z')
        .ok_or_else(|| CoreError::Json("proofValue must be multibase base58btc (z)".into()))?;
    let signature = crate::multikey::decode_base58_bounded(body)?;

    let mut unsigned = proof.clone();
    unsigned.remove("proofValue");

    let signing_input = hash_data(credential, &unsigned)?;
    if keys::verify(raw_public_key, &signing_input, &signature)? {
        return Ok(true);
    }
    // Fall back to the pre-alignment signing input so credentials issued before
    // the Data Integrity alignment still verify.
    let legacy = legacy_proof_digest(credential, &unsigned)?;
    keys::verify(raw_public_key, &legacy, &signature)
}

/// Convenience: derive the public key from a seed and verify (for self-checks).
pub fn verify_with_seed(credential: &Value, raw_private_seed: &[u8]) -> Result<bool> {
    let kp = Ed25519KeyPair::from_seed_slice(raw_private_seed)?;
    verify_proof(credential, &kp.public_key())
}

/// Return the `verificationMethod` declared by the credential's proof. Callers
/// should resolve the verification key from THIS identifier before verifying, so
/// the key is bound to the method the proof claims (see the SECURITY note on
/// [`verify_proof`]).
pub fn proof_verification_method(credential: &Value) -> Result<String> {
    credential
        .as_object()
        .and_then(|o| o.get("proof"))
        .and_then(|p| p.as_object())
        .and_then(|p| p.get("verificationMethod"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| CoreError::Json("proof has no verificationMethod".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A credential issued before the Data Integrity alignment, whose signature
    /// covers the pre-alignment signing input, MUST still verify.
    #[test]
    fn verifies_pre_alignment_credential() {
        let public_key = [
            0x4c, 0xb5, 0xab, 0xf6, 0xad, 0x79, 0xfb, 0xf5, 0xab, 0xbc, 0xca, 0xfc, 0xc2, 0x69,
            0xd8, 0x5c, 0xd2, 0x65, 0x1e, 0xd4, 0xb8, 0x85, 0xb5, 0x86, 0x9f, 0x24, 0x1a, 0xed,
            0xf0, 0xa5, 0xba, 0x29,
        ];
        let credential = json!({
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
            },
            "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "created": "2026-04-26T10:00:00Z",
                "verificationMethod": "did:web:test.example.com#key-1",
                "proofPurpose": "assertionMethod",
                "proofValue": "z24FsZHuADF9uwHAfsjW3okmynrNCCN4QkQirEPfEy5MtcXzg4uhFqz4o3RVH57cFvVXg9oarC4m51YEmNu5UQRLQ"
            }
        });
        assert!(verify_proof(&credential, &public_key).expect("verification error"));
    }

    fn sample_credential() -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "VouchCredential"],
            "issuer": "did:web:agent.example.com",
            "validFrom": "2026-04-26T10:00:00Z",
            "validUntil": "2026-04-26T10:05:00Z",
            "credentialSubject": {
                "id": "did:web:agent.example.com",
                "vouchVersion": "1.0",
                "intent": {
                    "action": "read_database",
                    "target": "users_table",
                    "resource": "https://api.example.com/v1/users"
                }
            }
        })
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let seed = [9u8; 32];
        let cred = sample_credential();
        let opts =
            BuildProofOptions::new("did:web:agent.example.com#key-1", "2026-04-26T10:00:00Z");
        let signed = sign(&cred, &seed, &opts).unwrap();
        assert!(verify_with_seed(&signed, &seed).unwrap());
    }

    #[test]
    fn tamper_fails_verification() {
        let seed = [9u8; 32];
        let cred = sample_credential();
        let opts =
            BuildProofOptions::new("did:web:agent.example.com#key-1", "2026-04-26T10:00:00Z");
        let mut signed = sign(&cred, &seed, &opts).unwrap();
        signed["credentialSubject"]["intent"]["action"] = json!("delete_database");
        assert!(!verify_with_seed(&signed, &seed).unwrap());
    }

    #[test]
    fn exposes_proof_verification_method() {
        let seed = [9u8; 32];
        let opts =
            BuildProofOptions::new("did:web:agent.example.com#key-1", "2026-04-26T10:00:00Z");
        let signed = sign(&sample_credential(), &seed, &opts).unwrap();
        assert_eq!(
            proof_verification_method(&signed).unwrap(),
            "did:web:agent.example.com#key-1"
        );
        assert!(proof_verification_method(&sample_credential()).is_err());
    }

    #[test]
    fn deterministic_proof_value() {
        let seed = [9u8; 32];
        let cred = sample_credential();
        let opts =
            BuildProofOptions::new("did:web:agent.example.com#key-1", "2026-04-26T10:00:00Z");
        let a = build_proof(&cred, &seed, &opts).unwrap();
        let b = build_proof(&cred, &seed, &opts).unwrap();
        assert_eq!(a["proofValue"], b["proofValue"]);
    }
}
