//! WASM bindings for the Vouch Protocol core.
//!
//! A thin wasm-bindgen layer over `vouch-core`. Binary values (keys, messages,
//! signatures) cross the JS boundary as base64 strings; credentials and proofs
//! cross as JSON strings. Every function delegates to the canonical core, so the
//! browser/Node output is byte-identical to the native and other-language SDKs.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use wasm_bindgen::prelude::*;

use vouch_core::{
    credentials, data_integrity, delegation, hybrid, keys, multikey, pq, robotics_json as rjson,
    status_list,
};

// --------------------------------------------------------------------------
// small helpers
// --------------------------------------------------------------------------

fn b64d(s: &str) -> Result<Vec<u8>, JsError> {
    STANDARD
        .decode(s)
        .map_err(|e| JsError::new(&format!("base64: {e}")))
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
pub fn ed25519_verify(
    public_b64: &str,
    message_b64: &str,
    signature_b64: &str,
) -> Result<bool, JsError> {
    keys::verify(
        &b64d(public_b64)?,
        &b64d(message_b64)?,
        &b64d(signature_b64)?,
    )
    .map_err(jerr)
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
pub fn build_proof(
    credential_json: &str,
    seed_b64: &str,
    verification_method: &str,
    created: &str,
) -> Result<String, JsError> {
    let opts = data_integrity::BuildProofOptions::new(verification_method, created);
    let proof = data_integrity::build_proof(&parse(credential_json)?, &b64d(seed_b64)?, &opts)
        .map_err(jerr)?;
    Ok(proof.to_string())
}

#[wasm_bindgen(js_name = sign)]
pub fn sign(
    credential_json: &str,
    seed_b64: &str,
    verification_method: &str,
    created: &str,
) -> Result<String, JsError> {
    let opts = data_integrity::BuildProofOptions::new(verification_method, created);
    let signed =
        data_integrity::sign(&parse(credential_json)?, &b64d(seed_b64)?, &opts).map_err(jerr)?;
    Ok(signed.to_string())
}

#[wasm_bindgen(js_name = verifyProof)]
pub fn verify_proof(credential_json: &str, public_b64: &str) -> Result<bool, JsError> {
    data_integrity::verify_proof(&parse(credential_json)?, &b64d(public_b64)?).map_err(jerr)
}

// --------------------------------------------------------------------------
// Credentials + verification (with temporal window)
// --------------------------------------------------------------------------

#[wasm_bindgen(js_name = verify)]
pub fn verify(
    credential_json: &str,
    public_b64: &str,
    now_iso: &str,
    clock_skew_seconds: i32,
) -> Result<String, JsError> {
    let r = credentials::verify(
        &parse(credential_json)?,
        &b64d(public_b64)?,
        now_iso,
        clock_skew_seconds as i64,
    )
    .map_err(jerr)?;
    Ok(
        json!({ "proofValid": r.proof_valid, "timeValid": r.time_valid, "valid": r.is_valid() })
            .to_string(),
    )
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
pub fn verify_chain_time_bound(
    chain_json: &str,
    now_iso: &str,
    clock_skew_seconds: i32,
) -> Result<bool, JsError> {
    let chain = parse(chain_json)?;
    let arr = chain
        .as_array()
        .ok_or_else(|| JsError::new("chain must be a JSON array"))?;
    delegation::verify_chain_time_bound(arr, now_iso, clock_skew_seconds as i64).map_err(jerr)
}

// --------------------------------------------------------------------------
// Post-quantum: ML-DSA-44 and dual proofs
// --------------------------------------------------------------------------

/// Generate an ML-DSA-44 key pair. Returns {secret_b64, public_b64}.
#[wasm_bindgen(js_name = generateMldsa44)]
pub fn generate_mldsa44() -> Result<String, JsError> {
    let kp = pq::MlDsa44KeyPair::generate().map_err(jerr)?;
    Ok(
        json!({ "secret_b64": b64e(&kp.secret_key()), "public_b64": b64e(&kp.public_key()) })
            .to_string(),
    )
}

#[wasm_bindgen(js_name = mldsa44Sign)]
pub fn mldsa44_sign(
    secret_b64: &str,
    public_b64: &str,
    message_b64: &str,
) -> Result<String, JsError> {
    let kp =
        pq::MlDsa44KeyPair::from_bytes(&b64d(secret_b64)?, &b64d(public_b64)?).map_err(jerr)?;
    Ok(b64e(&kp.sign(&b64d(message_b64)?).map_err(jerr)?))
}

#[wasm_bindgen(js_name = mldsa44Verify)]
pub fn mldsa44_verify(
    public_b64: &str,
    message_b64: &str,
    signature_b64: &str,
) -> Result<bool, JsError> {
    pq::verify(
        &b64d(public_b64)?,
        &b64d(message_b64)?,
        &b64d(signature_b64)?,
    )
    .map_err(jerr)
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
    let ml = pq::MlDsa44KeyPair::from_bytes(&b64d(mldsa_secret_b64)?, &b64d(mldsa_public_b64)?)
        .map_err(jerr)?;
    let signed = hybrid::sign_dual(
        &parse(credential_json)?,
        &b64d(ed25519_seed_b64)?,
        &ml,
        ed25519_vm,
        mldsa_vm,
        created,
    )
    .map_err(jerr)?;
    Ok(signed.to_string())
}

#[wasm_bindgen(js_name = verifyDual)]
pub fn verify_dual(
    credential_json: &str,
    ed25519_public_b64: &str,
    mldsa_public_b64: &str,
) -> Result<bool, JsError> {
    hybrid::verify_dual(
        &parse(credential_json)?,
        &b64d(ed25519_public_b64)?,
        &b64d(mldsa_public_b64)?,
    )
    .map_err(jerr)
}

#[wasm_bindgen(js_name = verifyComposite)]
pub fn verify_composite(
    credential_json: &str,
    ed25519_public_b64: &str,
    mldsa_public_b64: &str,
) -> Result<bool, JsError> {
    hybrid::verify_composite(
        &parse(credential_json)?,
        &b64d(ed25519_public_b64)?,
        &b64d(mldsa_public_b64)?,
    )
    .map_err(jerr)
}

// --------------------------------------------------------------------------
// Revocation (BitstringStatusList)
// --------------------------------------------------------------------------

#[wasm_bindgen(js_name = verifyStatus)]
pub fn verify_status(
    credential_status_json: &str,
    status_list_credential_json: &str,
) -> Result<bool, JsError> {
    status_list::verify_status(
        &parse(credential_status_json)?,
        &parse(status_list_credential_json)?,
    )
    .map_err(jerr)
}

/// Library version (matches the crate version).
#[wasm_bindgen(js_name = version)]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// --------------------------------------------------------------------------
// Robotics (Phase 5). Keys as base64; everything else as JSON strings, over the
// shared core facades, so the browser gets the same robotics surface.
// --------------------------------------------------------------------------

#[wasm_bindgen(js_name = roboticsMintIdentity)]
pub fn robotics_mint_identity(robot_seed_b64: &str, params_json: &str) -> Result<String, JsError> {
    rjson::mint_robot_identity(&b64d(robot_seed_b64)?, params_json).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsVerifyIdentity)]
pub fn robotics_verify_identity(
    credential_json: &str,
    robot_public_b64: &str,
) -> Result<String, JsError> {
    rjson::verify_robot_identity(credential_json, &b64d(robot_public_b64)?).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsConfigHash)]
pub fn robotics_config_hash(config_json: &str) -> Result<String, JsError> {
    rjson::config_hash(config_json).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsBuildProvenance)]
pub fn robotics_build_provenance(
    signer_seed_b64: &str,
    params_json: &str,
) -> Result<String, JsError> {
    rjson::build_provenance_attestation(&b64d(signer_seed_b64)?, params_json).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsVerifyProvenance)]
pub fn robotics_verify_provenance(
    attestation_json: &str,
    public_b64: &str,
    config_json: Option<String>,
) -> Result<String, JsError> {
    rjson::verify_provenance_attestation(
        attestation_json,
        &b64d(public_b64)?,
        config_json.as_deref(),
    )
    .map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsBuildScope)]
pub fn robotics_build_scope(signer_seed_b64: &str, params_json: &str) -> Result<String, JsError> {
    rjson::build_physical_scope_credential(&b64d(signer_seed_b64)?, params_json).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsCheckAction)]
pub fn robotics_check_action(scope_json: &str, action_json: &str) -> Result<String, JsError> {
    rjson::check_physical_action(scope_json, action_json).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsAttenuates)]
pub fn robotics_attenuates(parent_json: &str, child_json: &str) -> Result<bool, JsError> {
    rjson::attenuates(parent_json, child_json).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsBuildHello)]
pub fn robotics_build_hello(signer_seed_b64: &str, params_json: &str) -> Result<String, JsError> {
    rjson::build_hello(&b64d(signer_seed_b64)?, params_json).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsBuildAccept)]
pub fn robotics_build_accept(
    signer_seed_b64: &str,
    hello_json: &str,
    hello_public_b64: &str,
    policy_json: &str,
    params_json: &str,
) -> Result<String, JsError> {
    rjson::build_accept(
        &b64d(signer_seed_b64)?,
        hello_json,
        &b64d(hello_public_b64)?,
        policy_json,
        params_json,
    )
    .map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsVerifyAccept)]
pub fn robotics_verify_accept(
    accept_json: &str,
    accept_public_b64: &str,
    expected_nonce: &str,
    policy_json: Option<String>,
) -> Result<String, JsError> {
    rjson::verify_accept(
        accept_json,
        &b64d(accept_public_b64)?,
        expected_nonce,
        policy_json.as_deref(),
    )
    .map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsBuildConfirm)]
pub fn robotics_build_confirm(
    signer_seed_b64: &str,
    from_did: &str,
    session_json: &str,
    created: &str,
) -> Result<String, JsError> {
    rjson::build_confirm(&b64d(signer_seed_b64)?, from_did, session_json, created).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsVerifyConfirm)]
pub fn robotics_verify_confirm(
    confirm_json: &str,
    confirm_public_b64: &str,
    session_id: &str,
    expected_nonce: &str,
) -> Result<bool, JsError> {
    rjson::verify_confirm(
        confirm_json,
        &b64d(confirm_public_b64)?,
        session_id,
        expected_nonce,
    )
    .map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsGenesisPrevHash)]
pub fn robotics_genesis_prev_hash() -> String {
    rjson::genesis_prev_hash()
}
#[wasm_bindgen(js_name = roboticsBlackboxAppend)]
pub fn robotics_blackbox_append(
    key_b64: &str,
    seq: u64,
    event: &str,
    payload_json: &str,
    timestamp: &str,
    prev_hash: &str,
) -> Result<String, JsError> {
    rjson::blackbox_append_entry(
        &b64d(key_b64)?,
        seq,
        event,
        payload_json,
        timestamp,
        prev_hash,
    )
    .map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsBlackboxOpen)]
pub fn robotics_blackbox_open(entry_json: &str, key_b64: &str) -> Result<String, JsError> {
    rjson::blackbox_open_entry(entry_json, &b64d(key_b64)?).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsVerifyChain)]
pub fn robotics_verify_chain(
    entries_json: &str,
    genesis_prev_hash: Option<String>,
) -> Result<String, JsError> {
    rjson::verify_blackbox_chain(entries_json, genesis_prev_hash.as_deref()).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsBuildKillswitch)]
pub fn robotics_build_killswitch(
    authority_seed_b64: &str,
    params_json: &str,
) -> Result<String, JsError> {
    rjson::build_killswitch_credential(&b64d(authority_seed_b64)?, params_json).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsVerifyKillswitch)]
pub fn robotics_verify_killswitch(
    credential_json: &str,
    public_b64: &str,
    trusted_authorities_json: Option<String>,
) -> Result<String, JsError> {
    rjson::verify_killswitch_credential(
        credential_json,
        &b64d(public_b64)?,
        trusted_authorities_json.as_deref(),
    )
    .map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsBuildPassport)]
pub fn robotics_build_passport(
    signer_seed_b64: &str,
    params_json: &str,
) -> Result<String, JsError> {
    rjson::build_passport(&b64d(signer_seed_b64)?, params_json).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsEncodePassport)]
pub fn robotics_encode_passport(passport_json: &str) -> Result<String, JsError> {
    rjson::encode_passport(passport_json).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsDecodePassport)]
pub fn robotics_decode_passport(uri: &str) -> Result<String, JsError> {
    rjson::decode_passport(uri).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsVerifyPassport)]
pub fn robotics_verify_passport(
    passport_json: &str,
    public_b64: &str,
    now_iso: &str,
) -> Result<String, JsError> {
    rjson::verify_passport(passport_json, &b64d(public_b64)?, now_iso).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsVerifyPassportUri)]
pub fn robotics_verify_passport_uri(
    uri: &str,
    public_b64: &str,
    now_iso: &str,
) -> Result<String, JsError> {
    rjson::verify_passport_uri(uri, &b64d(public_b64)?, now_iso).map_err(jerr)
}

// Liveness heartbeat (Phase 5.7).
#[wasm_bindgen(js_name = roboticsMotionDigest)]
pub fn robotics_motion_digest(params_json: &str) -> Result<String, JsError> {
    rjson::motion_digest(params_json).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsValidateMotionDigest)]
pub fn robotics_validate_motion_digest(digest_json: &str) -> Result<bool, JsError> {
    rjson::validate_motion_digest(digest_json).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsBuildHeartbeat)]
pub fn robotics_build_heartbeat(
    robot_seed_b64: &str,
    params_json: &str,
) -> Result<String, JsError> {
    rjson::build_robot_heartbeat(&b64d(robot_seed_b64)?, params_json).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsVerifyHeartbeat)]
pub fn robotics_verify_heartbeat(
    credential_json: &str,
    robot_public_b64: &str,
) -> Result<String, JsError> {
    rjson::verify_robot_heartbeat(credential_json, &b64d(robot_public_b64)?).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsIsLive)]
pub fn robotics_is_live(
    credential_json: &str,
    now_iso: &str,
    interval_seconds: Option<i64>,
    grace_intervals: i64,
) -> Result<bool, JsError> {
    rjson::is_live(credential_json, now_iso, interval_seconds, grace_intervals).map_err(jerr)
}

// Per-credential revocation (Phase 5.8).
#[wasm_bindgen(js_name = roboticsBuildStatusEntry)]
pub fn robotics_build_status_entry(
    status_list_credential: &str,
    status_list_index: i64,
    status_purpose: &str,
    entry_id: Option<String>,
) -> Result<String, JsError> {
    rjson::build_status_list_entry(
        status_list_credential,
        status_list_index,
        status_purpose,
        entry_id.as_deref(),
    )
    .map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsAttachStatus)]
pub fn robotics_attach_status(
    credential_json: &str,
    signer_seed_b64: &str,
    params_json: &str,
) -> Result<String, JsError> {
    rjson::attach_credential_status(credential_json, &b64d(signer_seed_b64)?, params_json)
        .map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsCheckStatus)]
pub fn robotics_check_status(
    credential_json: &str,
    status_list_credential_json: &str,
    status_purpose: &str,
) -> Result<bool, JsError> {
    rjson::check_credential_status(credential_json, status_list_credential_json, status_purpose)
        .map_err(jerr)
}

// Accountable safety record (Phase 5.9).
#[wasm_bindgen(js_name = roboticsSafetyAppend)]
pub fn robotics_safety_append(params_json: &str) -> Result<String, JsError> {
    rjson::safety_append_entry(params_json).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsVerifySafetyLog)]
pub fn robotics_verify_safety_log(
    entries_json: &str,
    genesis_prev_hash: Option<String>,
) -> Result<String, JsError> {
    rjson::verify_safety_log(entries_json, genesis_prev_hash.as_deref()).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsSummarizeSafety)]
pub fn robotics_summarize_safety(
    entries_json: &str,
    head: Option<String>,
) -> Result<String, JsError> {
    rjson::summarize_entries(entries_json, head.as_deref()).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsBuildSafetyRecord)]
pub fn robotics_build_safety_record(
    signer_seed_b64: &str,
    params_json: &str,
) -> Result<String, JsError> {
    rjson::build_safety_record(&b64d(signer_seed_b64)?, params_json).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsVerifySafetyRecord)]
pub fn robotics_verify_safety_record(
    credential_json: &str,
    public_b64: &str,
) -> Result<String, JsError> {
    rjson::verify_safety_record(credential_json, &b64d(public_b64)?).map_err(jerr)
}

// Perception provenance (Phase 5.10).
#[wasm_bindgen(js_name = roboticsHashFrame)]
pub fn robotics_hash_frame(frame_b64: &str) -> Result<String, JsError> {
    Ok(rjson::hash_frame(&b64d(frame_b64)?))
}
#[wasm_bindgen(js_name = roboticsPerceptionRecord)]
pub fn robotics_perception_record(params_json: &str) -> Result<String, JsError> {
    rjson::perception_record_entry(params_json).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsVerifyPerceptionLog)]
pub fn robotics_verify_perception_log(
    entries_json: &str,
    genesis_prev_hash: Option<String>,
) -> Result<String, JsError> {
    rjson::verify_perception_log(entries_json, genesis_prev_hash.as_deref()).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsBuildPerception)]
pub fn robotics_build_perception(
    robot_seed_b64: &str,
    params_json: &str,
) -> Result<String, JsError> {
    rjson::build_perception_attestation(&b64d(robot_seed_b64)?, params_json).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsVerifyPerception)]
pub fn robotics_verify_perception(
    credential_json: &str,
    public_b64: &str,
    frame_b64: Option<String>,
) -> Result<String, JsError> {
    rjson::verify_perception_attestation(credential_json, &b64d(public_b64)?, frame_b64.as_deref())
        .map_err(jerr)
}

// Delegation lease (Phase 5.11).
#[wasm_bindgen(js_name = roboticsBuildLease)]
pub fn robotics_build_lease(signer_seed_b64: &str, params_json: &str) -> Result<String, JsError> {
    rjson::build_delegation_lease(&b64d(signer_seed_b64)?, params_json).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsVerifyLease)]
pub fn robotics_verify_lease(
    credential_json: &str,
    public_b64: &str,
    now_iso: Option<String>,
    parent_scope_json: Option<String>,
) -> Result<String, JsError> {
    rjson::verify_delegation_lease(
        credential_json,
        &b64d(public_b64)?,
        now_iso.as_deref(),
        parent_scope_json.as_deref(),
    )
    .map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsLeasePermits)]
pub fn robotics_lease_permits(params_json: &str) -> Result<bool, JsError> {
    rjson::lease_permits(params_json).map_err(jerr)
}

// Physical quorum (Phase 5.12).
#[wasm_bindgen(js_name = roboticsBuildActionApproval)]
pub fn robotics_build_action_approval(
    approver_seed_b64: &str,
    params_json: &str,
) -> Result<String, JsError> {
    rjson::build_action_approval(&b64d(approver_seed_b64)?, params_json).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsVerifyActionAuthorization)]
pub fn robotics_verify_action_authorization(params_json: &str) -> Result<String, JsError> {
    rjson::verify_action_authorization(params_json).map_err(jerr)
}

// Robot lifecycle (Phase 5.13).
#[wasm_bindgen(js_name = roboticsBuildOwnershipTransfer)]
pub fn robotics_build_ownership_transfer(
    current_owner_seed_b64: &str,
    params_json: &str,
) -> Result<String, JsError> {
    rjson::build_ownership_transfer(&b64d(current_owner_seed_b64)?, params_json).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsVerifyOwnershipTransfer)]
pub fn robotics_verify_ownership_transfer(
    credential_json: &str,
    public_b64: &str,
) -> Result<String, JsError> {
    rjson::verify_ownership_transfer(credential_json, &b64d(public_b64)?).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsVerifyCustodyChain)]
pub fn robotics_verify_custody_chain(params_json: &str) -> Result<String, JsError> {
    rjson::verify_custody_chain(params_json).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsBuildKeyRotation)]
pub fn robotics_build_key_rotation(
    old_key_seed_b64: &str,
    params_json: &str,
) -> Result<String, JsError> {
    rjson::build_key_rotation(&b64d(old_key_seed_b64)?, params_json).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsVerifyKeyRotation)]
pub fn robotics_verify_key_rotation(
    credential_json: &str,
    old_public_b64: &str,
) -> Result<String, JsError> {
    rjson::verify_key_rotation(credential_json, &b64d(old_public_b64)?).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsVerifyKeyHistory)]
pub fn robotics_verify_key_history(params_json: &str) -> Result<String, JsError> {
    rjson::verify_key_history(params_json).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsBuildDecommission)]
pub fn robotics_build_decommission(
    signer_seed_b64: &str,
    params_json: &str,
) -> Result<String, JsError> {
    rjson::build_decommission(&b64d(signer_seed_b64)?, params_json).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsVerifyDecommission)]
pub fn robotics_verify_decommission(
    credential_json: &str,
    public_b64: &str,
    trusted_authorities_json: Option<String>,
) -> Result<String, JsError> {
    rjson::verify_decommission(
        credential_json,
        &b64d(public_b64)?,
        trusted_authorities_json.as_deref(),
    )
    .map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsCheckConformance)]
pub fn robotics_check_conformance(
    credentials_json: &str,
    profile_id: &str,
) -> Result<String, JsError> {
    rjson::check_conformance(credentials_json, profile_id).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsReportDigest)]
pub fn robotics_report_digest(report_json: &str) -> Result<String, JsError> {
    rjson::report_digest(report_json).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsBuildConformanceAttestation)]
pub fn robotics_build_conformance_attestation(
    signer_seed_b64: &str,
    params_json: &str,
) -> Result<String, JsError> {
    rjson::build_conformance_attestation(&b64d(signer_seed_b64)?, params_json).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsVerifyConformanceAttestation)]
pub fn robotics_verify_conformance_attestation(
    credential_json: &str,
    public_b64: &str,
) -> Result<String, JsError> {
    rjson::verify_conformance_attestation(credential_json, &b64d(public_b64)?).map_err(jerr)
}

// --------------------------------------------------------------------------
// Robotics: post-quantum robot credentials
// --------------------------------------------------------------------------

#[wasm_bindgen(js_name = roboticsSignPq)]
pub fn robotics_sign_pq(
    credential_json: &str,
    ed25519_seed_b64: &str,
    mldsa_secret_b64: &str,
    mldsa_public_b64: &str,
    created: &str,
) -> Result<String, JsError> {
    rjson::sign_pq(
        credential_json,
        &b64d(ed25519_seed_b64)?,
        &b64d(mldsa_secret_b64)?,
        &b64d(mldsa_public_b64)?,
        created,
    )
    .map_err(jerr)
}

#[wasm_bindgen(js_name = roboticsIsPq)]
pub fn robotics_is_pq(credential_json: &str) -> Result<bool, JsError> {
    rjson::is_pq(credential_json).map_err(jerr)
}

/// Verify a hybrid robot credential. `mldsa44_public_b64` is base64 of raw
/// 1312-byte bytes or of an ML-DSA-44 Multikey string (UTF-8).
#[wasm_bindgen(js_name = roboticsVerifyPq)]
pub fn robotics_verify_pq(
    credential_json: &str,
    ed25519_public_b64: &str,
    mldsa44_public_b64: &str,
) -> Result<bool, JsError> {
    rjson::verify_pq(
        credential_json,
        &b64d(ed25519_public_b64)?,
        &b64d(mldsa44_public_b64)?,
    )
    .map_err(jerr)
}

/// Dual verify auto-detected from the proof. `mldsa44_public_b64`, when present,
/// is base64 of raw 1312-byte bytes or of an ML-DSA-44 Multikey string (UTF-8);
/// a hybrid credential requires it, a classical credential ignores it.
#[wasm_bindgen(js_name = roboticsVerifyRobotCredential)]
pub fn robotics_verify_robot_credential(
    credential_json: &str,
    ed25519_public_b64: &str,
    mldsa44_public_b64: Option<String>,
) -> Result<bool, JsError> {
    let ml = match mldsa44_public_b64 {
        Some(s) => Some(b64d(&s)?),
        None => None,
    };
    rjson::verify_robot_credential(credential_json, &b64d(ed25519_public_b64)?, ml.as_deref())
        .map_err(jerr)
}

#[wasm_bindgen(js_name = roboticsMigrateToPq)]
pub fn robotics_migrate_to_pq(
    credential_json: &str,
    ed25519_seed_b64: &str,
    mldsa_secret_b64: &str,
    mldsa_public_b64: &str,
    created: &str,
) -> Result<String, JsError> {
    rjson::migrate_to_pq(
        credential_json,
        &b64d(ed25519_seed_b64)?,
        &b64d(mldsa_secret_b64)?,
        &b64d(mldsa_public_b64)?,
        created,
    )
    .map_err(jerr)
}

#[wasm_bindgen(js_name = roboticsBuildEmbodiment)]
pub fn robotics_build_embodiment(
    agent_seed_b64: &str,
    params_json: &str,
) -> Result<String, JsError> {
    rjson::build_embodiment(&b64d(agent_seed_b64)?, params_json).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsVerifyEmbodiment)]
pub fn robotics_verify_embodiment(
    credential_json: &str,
    agent_public_b64: &str,
) -> Result<String, JsError> {
    rjson::verify_embodiment(credential_json, &b64d(agent_public_b64)?).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsVerifyContinuityChain)]
pub fn robotics_verify_continuity_chain(
    params_json: &str,
    agent_public_b64: &str,
) -> Result<String, JsError> {
    rjson::verify_continuity_chain(params_json, &b64d(agent_public_b64)?).map_err(jerr)
}
#[wasm_bindgen(js_name = roboticsCheckNoFork)]
pub fn robotics_check_no_fork(params_json: &str) -> Result<String, JsError> {
    rjson::check_no_fork(params_json).map_err(jerr)
}
