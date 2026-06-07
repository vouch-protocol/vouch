//! WASM bindings for the Vouch Protocol core.
//!
//! A thin wasm-bindgen layer over `vouch-core`. Binary values (keys, messages,
//! signatures) cross the JS boundary as base64 strings; credentials and proofs
//! cross as JSON strings. Every function delegates to the canonical core, so the
//! browser/Node output is byte-identical to the native and other-language SDKs.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use wasm_bindgen::prelude::*;

use vouch_core::{credentials, data_integrity, delegation, hybrid, keys, multikey, pq, status_list};

// --------------------------------------------------------------------------
// small helpers
// --------------------------------------------------------------------------

fn b64d(s: &str) -> Result<Vec<u8>, JsError> {
    STANDARD.decode(s).map_err(|e| JsError::new(&format!("base64: {e}")))
}
fn b64e(b: &[u8]) -> String {
    STANDARD.encode(b)
}
fn parse(s: &str) -> Result<Value, JsError> {
    serde_json::from_str(s).map_err(|e| JsError::new(&format!("json: {e}")))
}
fn jerr<E: std::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}

// --------------------------------------------------------------------------
// JCS
// --------------------------------------------------------------------------

/// RFC 8785 canonicalization of a JSON string.
#[wasm_bindgen]
pub fn canonicalize(json_str: &str) -> Result<String, JsError> {
    Ok(vouch_core::jcs::canonicalize_to_string(&parse(json_str)?))
}

// --------------------------------------------------------------------------
// Ed25519 / multikey / did:key
// --------------------------------------------------------------------------

/// Generate an Ed25519 key pair. Returns {seed_b64, public_b64, multikey, did_key}.
#[wasm_bindgen(js_name = generateEd25519)]
pub fn generate_ed25519() -> Result<String, JsError> {
    let kp = keys::Ed25519KeyPair::generate().map_err(jerr)?;
    Ok(json!({
        "seed_b64": b64e(&kp.seed()),
        "public_b64": b64e(&kp.public_key()),
        "multikey": kp.public_multikey(),
        "did_key": kp.did_key(),
    })
    .to_string())
}

#[wasm_bindgen(js_name = ed25519Sign)]
pub fn ed25519_sign(seed_b64: &str, message_b64: &str) -> Result<String, JsError> {
    let kp = keys::Ed25519KeyPair::from_seed_slice(&b64d(seed_b64)?).map_err(jerr)?;
    Ok(b64e(&kp.sign(&b64d(message_b64)?)))
}

#[wasm_bindgen(js_name = ed25519Verify)]
pub fn ed25519_verify(public_b64: &str, message_b64: &str, signature_b64: &str) -> Result<bool, JsError> {
    keys::verify(&b64d(public_b64)?, &b64d(message_b64)?, &b64d(signature_b64)?).map_err(jerr)
}

#[wasm_bindgen(js_name = encodeEd25519Multikey)]
pub fn encode_ed25519_multikey(public_b64: &str) -> Result<String, JsError> {
    multikey::encode_ed25519_public(&b64d(public_b64)?).map_err(jerr)
}

#[wasm_bindgen(js_name = decodeMultikey)]
pub fn decode_multikey(multikey_str: &str) -> Result<String, JsError> {
    let d = multikey::decode(multikey_str).map_err(jerr)?;
    Ok(json!({ "algorithm": d.algorithm, "raw_b64": b64e(&d.raw_key) }).to_string())
}

#[wasm_bindgen(js_name = didKeyFromEd25519)]
pub fn did_key_from_ed25519(public_b64: &str) -> Result<String, JsError> {
    keys::ed25519_to_did_key(&b64d(public_b64)?).map_err(jerr)
}

#[wasm_bindgen(js_name = ed25519FromDidKey)]
pub fn ed25519_from_did_key(did: &str) -> Result<String, JsError> {
    Ok(b64e(&keys::did_key_to_ed25519(did).map_err(jerr)?))
}

// --------------------------------------------------------------------------
// Data Integrity (eddsa-jcs-2022)
// --------------------------------------------------------------------------

#[wasm_bindgen(js_name = buildProof)]
pub fn build_proof(credential_json: &str, seed_b64: &str, verification_method: &str, created: &str) -> Result<String, JsError> {
    let opts = data_integrity::BuildProofOptions::new(verification_method, created);
    let proof = data_integrity::build_proof(&parse(credential_json)?, &b64d(seed_b64)?, &opts).map_err(jerr)?;
    Ok(proof.to_string())
}

#[wasm_bindgen(js_name = signCredential)]
pub fn sign_credential(credential_json: &str, seed_b64: &str, verification_method: &str, created: &str) -> Result<String, JsError> {
    let opts = data_integrity::BuildProofOptions::new(verification_method, created);
    let signed = data_integrity::sign(&parse(credential_json)?, &b64d(seed_b64)?, &opts).map_err(jerr)?;
    Ok(signed.to_string())
}

#[wasm_bindgen(js_name = verifyProof)]
pub fn verify_proof(credential_json: &str, public_b64: &str) -> Result<bool, JsError> {
    data_integrity::verify_proof(&parse(credential_json)?, &b64d(public_b64)?).map_err(jerr)
}

// --------------------------------------------------------------------------
// Credentials + verification (with temporal window)
// --------------------------------------------------------------------------

#[wasm_bindgen(js_name = verifyCredential)]
pub fn verify_credential(credential_json: &str, public_b64: &str, now_iso: &str, clock_skew_seconds: i32) -> Result<String, JsError> {
    let r = credentials::verify_credential(&parse(credential_json)?, &b64d(public_b64)?, now_iso, clock_skew_seconds as i64).map_err(jerr)?;
    Ok(json!({ "proofValid": r.proof_valid, "timeValid": r.time_valid, "valid": r.is_valid() }).to_string())
}

/// Build a delegation link. Pass null/undefined for the optional validFrom,
/// validUntil, parentProofValue. Returns the link as a JSON string.
#[wasm_bindgen(js_name = buildDelegationLink)]
pub fn build_delegation_link(
    issuer: &str,
    subject: &str,
    intent_json: &str,
    valid_from: Option<String>,
    valid_until: Option<String>,
    parent_proof_value: Option<String>,
) -> Result<String, JsError> {
    let intent = parse(intent_json)?;
    let input = vouch_core::delegation::DelegationLinkInput {
        issuer: issuer.to_string(),
        subject: subject.to_string(),
        intent,
        valid_from,
        valid_until,
        parent_proof_value,
    };
    Ok(vouch_core::delegation::build_delegation_link(&input).to_string())
}

/// Validate the time-bound rule over a delegation chain (JSON array of links).
#[wasm_bindgen(js_name = verifyChainTimeBound)]
pub fn verify_chain_time_bound(chain_json: &str, now_iso: &str, clock_skew_seconds: i32) -> Result<bool, JsError> {
    let chain = parse(chain_json)?;
    let arr = chain.as_array().ok_or_else(|| JsError::new("chain must be a JSON array"))?;
    delegation::verify_chain_time_bound(arr, now_iso, clock_skew_seconds as i64).map_err(jerr)
}

// --------------------------------------------------------------------------
// Post-quantum: ML-DSA-44 and dual proofs
// --------------------------------------------------------------------------

/// Generate an ML-DSA-44 key pair. Returns {secret_b64, public_b64}.
#[wasm_bindgen(js_name = generateMldsa44)]
pub fn generate_mldsa44() -> Result<String, JsError> {
    let kp = pq::MlDsa44KeyPair::generate().map_err(jerr)?;
    Ok(json!({ "secret_b64": b64e(&kp.secret_key()), "public_b64": b64e(&kp.public_key()) }).to_string())
}

#[wasm_bindgen(js_name = mldsa44Sign)]
pub fn mldsa44_sign(secret_b64: &str, public_b64: &str, message_b64: &str) -> Result<String, JsError> {
    let kp = pq::MlDsa44KeyPair::from_bytes(&b64d(secret_b64)?, &b64d(public_b64)?).map_err(jerr)?;
    Ok(b64e(&kp.sign(&b64d(message_b64)?).map_err(jerr)?))
}

#[wasm_bindgen(js_name = mldsa44Verify)]
pub fn mldsa44_verify(public_b64: &str, message_b64: &str, signature_b64: &str) -> Result<bool, JsError> {
    pq::verify(&b64d(public_b64)?, &b64d(message_b64)?, &b64d(signature_b64)?).map_err(jerr)
}

/// Build a dual proof (Ed25519 + ML-DSA-44) and attach it to the credential.
#[wasm_bindgen(js_name = signDual)]
pub fn sign_dual(
    credential_json: &str,
    ed25519_seed_b64: &str,
    mldsa_secret_b64: &str,
    mldsa_public_b64: &str,
    ed25519_vm: &str,
    mldsa_vm: &str,
    created: &str,
) -> Result<String, JsError> {
    let ml = pq::MlDsa44KeyPair::from_bytes(&b64d(mldsa_secret_b64)?, &b64d(mldsa_public_b64)?).map_err(jerr)?;
    let signed = hybrid::sign_dual(&parse(credential_json)?, &b64d(ed25519_seed_b64)?, &ml, ed25519_vm, mldsa_vm, created).map_err(jerr)?;
    Ok(signed.to_string())
}

#[wasm_bindgen(js_name = verifyDual)]
pub fn verify_dual(credential_json: &str, ed25519_public_b64: &str, mldsa_public_b64: &str) -> Result<bool, JsError> {
    hybrid::verify_dual(&parse(credential_json)?, &b64d(ed25519_public_b64)?, &b64d(mldsa_public_b64)?).map_err(jerr)
}

#[wasm_bindgen(js_name = verifyComposite)]
pub fn verify_composite(credential_json: &str, ed25519_public_b64: &str, mldsa_public_b64: &str) -> Result<bool, JsError> {
    hybrid::verify_composite(&parse(credential_json)?, &b64d(ed25519_public_b64)?, &b64d(mldsa_public_b64)?).map_err(jerr)
}

// --------------------------------------------------------------------------
// Revocation (BitstringStatusList)
// --------------------------------------------------------------------------

#[wasm_bindgen(js_name = verifyStatus)]
pub fn verify_status(credential_status_json: &str, status_list_credential_json: &str) -> Result<bool, JsError> {
    status_list::verify_status(&parse(credential_status_json)?, &parse(status_list_credential_json)?).map_err(jerr)
}

/// Library version (matches the crate version).
#[wasm_bindgen(js_name = version)]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
