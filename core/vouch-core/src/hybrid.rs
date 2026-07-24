//! Post-quantum credentials as a Data Integrity proof set.
//!
//! The credential carries a `proof` ARRAY of two independent proofs,
//! `eddsa-jcs-2022` and `mldsa44-jcs-2024`. Each proof is computed over the
//! same unsecured document with only its own proof configuration, and each
//! verifies on its own, so a verifier that understands only one of the two
//! cryptosuites can still check that proof. Both must verify for
//! [`verify_dual`] to succeed.
//!
//! Two pre-alignment shapes are accepted on verification and never emitted:
//! the `mldsa44-jcs-2026` identifier, and the v1.6.x composite
//! `hybrid-eddsa-mldsa44-jcs-2026` whose single proofValue was
//! base58btc(ed25519_sig || mldsa44_sig).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{Map, Value};

use crate::data_integrity::{self, legacy_proof_digest, BuildProofOptions, PROOF_TYPE};
use crate::error::{CoreError, Result};
use crate::keys::{self, Ed25519KeyPair};
use crate::pq::{self, MlDsa44KeyPair, MLDSA44_SIG_LEN};

pub const EDDSA_CRYPTOSUITE_ID: &str = "eddsa-jcs-2022";
/// The W3C Quantum-Resistant Cryptosuites identifier for ML-DSA-44 over JCS.
pub const MLDSA44_CRYPTOSUITE_ID: &str = "mldsa44-jcs-2024";
/// Pre-alignment identifier, accepted on verification only.
pub const MLDSA44_LEGACY_CRYPTOSUITE_ID: &str = "mldsa44-jcs-2026";
/// The v1.6.x composite. Accepted on verification only; never emitted.
pub const HYBRID_COMPOSITE_CRYPTOSUITE_ID: &str = "hybrid-eddsa-mldsa44-jcs-2026";

const ED25519_SIG_LEN: usize = 64;

fn strip_proof(credential: &Value) -> Result<Value> {
    let mut base = credential.clone();
    base.as_object_mut()
        .ok_or_else(|| CoreError::Json("credential must be an object".into()))?
        .remove("proof");
    Ok(base)
}

fn mldsa_unsigned_proof(verification_method: &str, created: &str) -> Map<String, Value> {
    let mut p = Map::new();
    p.insert("type".into(), Value::String(PROOF_TYPE.into()));
    p.insert(
        "cryptosuite".into(),
        Value::String(MLDSA44_CRYPTOSUITE_ID.into()),
    );
    p.insert("created".into(), Value::String(created.into()));
    p.insert(
        "verificationMethod".into(),
        Value::String(verification_method.into()),
    );
    p.insert(
        "proofPurpose".into(),
        Value::String("assertionMethod".into()),
    );
    p
}

/// Build a dual proof (an array of two proofs) for `credential`.
pub fn build_dual_proof(
    credential: &Value,
    ed25519_seed: &[u8],
    mldsa: &MlDsa44KeyPair,
    ed25519_verification_method: &str,
    mldsa_verification_method: &str,
    created: &str,
) -> Result<Value> {
    let base = strip_proof(credential)?;

    let ed_proof = data_integrity::build_proof(
        &base,
        ed25519_seed,
        &BuildProofOptions::new(ed25519_verification_method, created),
    )?;

    let mut ml_proof = mldsa_unsigned_proof(mldsa_verification_method, created);
    let ml_signing_input = data_integrity::hash_data(&base, &ml_proof)?;
    let ml_sig = mldsa.sign(&ml_signing_input)?;
    // The Quantum-Resistant Cryptosuites specification encodes proofValue as a
    // base64url-nopad Multibase value ("u"). The classical eddsa-jcs-2022 suite
    // is specified separately and keeps base58btc ("z").
    ml_proof.insert(
        "proofValue".into(),
        Value::String(format!("u{}", URL_SAFE_NO_PAD.encode(ml_sig))),
    );

    Ok(Value::Array(vec![ed_proof, Value::Object(ml_proof)]))
}

/// Build a dual proof and attach it to the credential under `proof`.
pub fn sign_dual(
    credential: &Value,
    ed25519_seed: &[u8],
    mldsa: &MlDsa44KeyPair,
    ed25519_verification_method: &str,
    mldsa_verification_method: &str,
    created: &str,
) -> Result<Value> {
    let proof = build_dual_proof(
        credential,
        ed25519_seed,
        mldsa,
        ed25519_verification_method,
        mldsa_verification_method,
        created,
    )?;
    let mut signed = strip_proof(credential)?;
    signed
        .as_object_mut()
        .unwrap()
        .insert("proof".into(), proof);
    Ok(signed)
}

/// Verify a dual proof: both the Ed25519 and the ML-DSA-44 proofs in the array
/// MUST validate. Returns Ok(true) only if both are present and valid.
pub fn verify_dual(credential: &Value, ed25519_public: &[u8], mldsa_public: &[u8]) -> Result<bool> {
    let proofs = credential
        .as_object()
        .and_then(|o| o.get("proof"))
        .and_then(|p| p.as_array())
        .ok_or_else(|| CoreError::Json("dual proof requires a proof array".into()))?;
    let base = strip_proof(credential)?;

    // Every proof present in the set must verify. A proof that fails fails the
    // whole set immediately, so a later proof of the same cryptosuite can never
    // overwrite an earlier failure.
    let mut ed_seen = false;
    let mut ml_seen = false;

    for p in proofs {
        let cs = p.get("cryptosuite").and_then(|v| v.as_str());
        match cs {
            Some(EDDSA_CRYPTOSUITE_ID) => {
                let mut c = base.clone();
                c.as_object_mut().unwrap().insert("proof".into(), p.clone());
                if !data_integrity::verify_proof(&c, ed25519_public)? {
                    return Ok(false);
                }
                ed_seen = true;
            }
            Some(MLDSA44_CRYPTOSUITE_ID) | Some(MLDSA44_LEGACY_CRYPTOSUITE_ID) => {
                let proof_obj = p
                    .as_object()
                    .ok_or_else(|| CoreError::Json("ml-dsa proof must be an object".into()))?;
                let pv = proof_obj
                    .get("proofValue")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| CoreError::Json("ml-dsa proof missing proofValue".into()))?;
                // Accept the specified base64url-nopad encoding, and the
                // pre-alignment base58btc encoding for credentials already issued.
                let sig = if let Some(body) = pv.strip_prefix('u') {
                    URL_SAFE_NO_PAD
                        .decode(body)
                        .map_err(|e| CoreError::Json(format!("bad base64url proofValue: {e}")))?
                } else if let Some(body) = pv.strip_prefix('z') {
                    crate::multikey::decode_base58_bounded(body)?
                } else {
                    return Err(CoreError::Json(
                        "proofValue must be multibase base64url (u) or base58btc (z)".into(),
                    ));
                };
                let mut unsigned = proof_obj.clone();
                unsigned.remove("proofValue");
                let signing_input = data_integrity::hash_data(&base, &unsigned)?;
                let mut ok = pq::verify(mldsa_public, &signing_input, &sig)?;
                if !ok {
                    let legacy = data_integrity::legacy_proof_digest(&base, &unsigned)?;
                    ok = pq::verify(mldsa_public, &legacy, &sig)?;
                }
                if !ok {
                    return Ok(false);
                }
                ml_seen = true;
            }
            _ => {}
        }
    }
    // Both members of the set must be present, so a credential cannot drop the
    // post-quantum proof and still be accepted as a proof set.
    Ok(ed_seen && ml_seen)
}

fn composite_unsigned_proof(verification_method: &str, created: &str) -> Map<String, Value> {
    let mut p = Map::new();
    p.insert("type".into(), Value::String(PROOF_TYPE.into()));
    p.insert(
        "cryptosuite".into(),
        Value::String(HYBRID_COMPOSITE_CRYPTOSUITE_ID.into()),
    );
    p.insert("created".into(), Value::String(created.into()));
    p.insert(
        "verificationMethod".into(),
        Value::String(verification_method.into()),
    );
    p.insert(
        "proofPurpose".into(),
        Value::String("assertionMethod".into()),
    );
    p
}

/// Build a v1.6.x composite proof (a single proof whose proofValue is
/// base58btc(ed25519_sig || mldsa44_sig)) for `credential`, using the
/// pre-alignment signing input that format was issued under.
///
/// Retained only so the older wire format can be reproduced for regression
/// checks. New credentials use [`build_dual_proof`], which emits a proof set.
#[deprecated(note = "the composite wire format is verify-only; use build_dual_proof")]
pub fn build_composite(
    credential: &Value,
    ed25519_seed: &[u8],
    mldsa: &MlDsa44KeyPair,
    verification_method: &str,
    created: &str,
) -> Result<Value> {
    let base = strip_proof(credential)?;
    let mut proof = composite_unsigned_proof(verification_method, created);
    let digest = legacy_proof_digest(&base, &proof)?;

    let kp = Ed25519KeyPair::from_seed_slice(ed25519_seed)?;
    let ed_sig = kp.sign(&digest);
    let ml_sig = mldsa.sign(&digest)?;

    let mut combined = Vec::with_capacity(ED25519_SIG_LEN + ml_sig.len());
    combined.extend_from_slice(&ed_sig);
    combined.extend_from_slice(&ml_sig);
    proof.insert(
        "proofValue".into(),
        Value::String(format!("z{}", bs58::encode(combined).into_string())),
    );
    Ok(Value::Object(proof))
}

/// Build a composite proof and attach it to the credential under `proof`,
/// replacing any existing proof. Verify-only wire format, retained for
/// regression checks against credentials issued under v1.6.x.
#[deprecated(note = "the composite wire format is verify-only; use sign_dual")]
#[allow(deprecated)]
pub fn sign_composite(
    credential: &Value,
    ed25519_seed: &[u8],
    mldsa: &MlDsa44KeyPair,
    verification_method: &str,
    created: &str,
) -> Result<Value> {
    let proof = build_composite(
        credential,
        ed25519_seed,
        mldsa,
        verification_method,
        created,
    )?;
    let mut signed = strip_proof(credential)?;
    signed
        .as_object_mut()
        .unwrap()
        .insert("proof".into(), proof);
    Ok(signed)
}

/// Verify a v1.6.x composite hybrid proof (single proof, concatenated
/// proofValue). Both embedded signatures MUST validate.
pub fn verify_composite(
    credential: &Value,
    ed25519_public: &[u8],
    mldsa_public: &[u8],
) -> Result<bool> {
    let proof = credential
        .as_object()
        .and_then(|o| o.get("proof"))
        .and_then(|p| p.as_object())
        .ok_or_else(|| CoreError::Json("composite proof must be an object".into()))?;
    if proof.get("cryptosuite").and_then(|v| v.as_str()) != Some(HYBRID_COMPOSITE_CRYPTOSUITE_ID) {
        return Err(CoreError::Json("not a composite hybrid proof".into()));
    }
    let pv = proof
        .get("proofValue")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CoreError::Json("missing proofValue".into()))?;
    let body = pv
        .strip_prefix('z')
        .ok_or_else(|| CoreError::Json("proofValue must be base58btc (z)".into()))?;
    let combined = crate::multikey::decode_base58_bounded(body)?;
    if combined.len() != ED25519_SIG_LEN + MLDSA44_SIG_LEN {
        return Ok(false);
    }
    let ed_sig = &combined[..ED25519_SIG_LEN];
    let ml_sig = &combined[ED25519_SIG_LEN..];

    let mut unsigned = proof.clone();
    unsigned.remove("proofValue");
    let base = strip_proof(credential)?;
    let digest = legacy_proof_digest(&base, &unsigned)?;

    Ok(
        keys::verify(ed25519_public, &digest, ed_sig)?
            && pq::verify(mldsa_public, &digest, ml_sig)?,
    )
}

/// Convenience: derive the Ed25519 public key for a dual self-check.
pub fn ed25519_public_from_seed(seed: &[u8]) -> Result<[u8; 32]> {
    Ok(Ed25519KeyPair::from_seed_slice(seed)?.public_key())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cred() -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "VouchCredential"],
            "issuer": "did:web:agent.example.com",
            "validFrom": "2026-04-26T10:00:00Z",
            "validUntil": "2026-04-26T10:05:00Z",
            "credentialSubject": { "id": "did:web:agent.example.com", "vouchVersion": "1.0",
                "intent": { "action": "read", "target": "t", "resource": "https://api/x" } }
        })
    }

    #[test]
    fn dual_proof_roundtrip() {
        let seed = [4u8; 32];
        let ml = MlDsa44KeyPair::generate().unwrap();
        let signed = sign_dual(
            &cred(),
            &seed,
            &ml,
            "did:web:agent.example.com#key-1",
            "did:web:agent.example.com#key-2",
            "2026-04-26T10:00:00Z",
        )
        .unwrap();
        assert!(signed["proof"].is_array());
        let ed_pub = ed25519_public_from_seed(&seed).unwrap();
        assert!(verify_dual(&signed, &ed_pub, &ml.public_key()).unwrap());
    }

    #[test]
    fn dual_proof_tamper_fails() {
        let seed = [4u8; 32];
        let ml = MlDsa44KeyPair::generate().unwrap();
        let mut signed = sign_dual(
            &cred(),
            &seed,
            &ml,
            "did:web:agent.example.com#key-1",
            "did:web:agent.example.com#key-2",
            "2026-04-26T10:00:00Z",
        )
        .unwrap();
        signed["credentialSubject"]["intent"]["action"] = json!("delete");
        let ed_pub = ed25519_public_from_seed(&seed).unwrap();
        assert!(!verify_dual(&signed, &ed_pub, &ml.public_key()).unwrap());
    }

    /// A failing proof cannot be masked by appending a second, valid proof of
    /// the same cryptosuite after it.
    #[test]
    fn appended_valid_proof_cannot_mask_a_failing_one() {
        let seed = [4u8; 32];
        let ml = MlDsa44KeyPair::generate().unwrap();
        let signed = sign_dual(
            &cred(),
            &seed,
            &ml,
            "did:web:agent.example.com#key-1",
            "did:web:agent.example.com#key-2",
            "2026-04-26T10:00:00Z",
        )
        .unwrap();
        let ed_pub = ed25519_public_from_seed(&seed).unwrap();
        let proofs = signed["proof"].as_array().unwrap().clone();

        // Corrupt the classical proof, then append the untouched valid one.
        let mut broken = proofs[0].clone();
        broken["proofValue"] = json!("z2SkKQBFXKcxxHbEnDaZjXPRWzHnbe1ZgArebQmqQ1Rf6H3nJa4vp3rzYaC5nnrFVFTL6wPMuJUAQGf7oEENy4vX");

        let mut attacked = signed.clone();
        attacked["proof"] = json!([broken, proofs[0].clone(), proofs[1].clone()]);
        assert!(
            !verify_dual(&attacked, &ed_pub, &ml.public_key()).unwrap(),
            "a failing proof must fail the set even when a valid proof follows it"
        );
    }

    /// A proof set that drops the post-quantum member must not verify.
    #[test]
    fn proof_set_without_the_post_quantum_member_fails() {
        let seed = [4u8; 32];
        let ml = MlDsa44KeyPair::generate().unwrap();
        let signed = sign_dual(
            &cred(),
            &seed,
            &ml,
            "did:web:agent.example.com#key-1",
            "did:web:agent.example.com#key-2",
            "2026-04-26T10:00:00Z",
        )
        .unwrap();
        let ed_pub = ed25519_public_from_seed(&seed).unwrap();
        let classical_only = signed["proof"].as_array().unwrap()[0].clone();

        let mut stripped = signed.clone();
        stripped["proof"] = json!([classical_only]);
        assert!(!verify_dual(&stripped, &ed_pub, &ml.public_key()).unwrap());
    }
}
