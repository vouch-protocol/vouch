//! UniFFI bindings for the Vouch Protocol core.
//!
//! A thin layer over `vouch-core` exposing the protocol primitives to Swift,
//! Kotlin/Java, and (via the generated C header) .NET and C/C++. Binary values
//! are `Vec<u8>`; credentials and proofs are JSON strings. Every function
//! delegates to the canonical core, so all platforms produce identical bytes.

use serde_json::Value;

use vouch_core::{
    credentials, data_integrity, delegation, hybrid, keys, multikey, pq, robotics_json as rjson,
    status_list,
};

// Clean C ABI (cbindgen generates vouch_core.h) for .NET and C/C++ consumers.
pub mod c_api;

/// Flat error surfaced across the FFI boundary; the message carries the detail.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("{0}")]
    Core(String),
}

impl From<vouch_core::CoreError> for CoreError {
    fn from(e: vouch_core::CoreError) -> Self {
        CoreError::Core(e.to_string())
    }
}

fn parse(s: &str) -> Result<Value, CoreError> {
    serde_json::from_str(s).map_err(|e| CoreError::Core(format!("json: {e}")))
}

// Records returned to the foreign side (match the UDL dictionaries).
pub struct Ed25519KeyPair {
    pub seed: Vec<u8>,
    pub public_key: Vec<u8>,
    pub multikey: String,
    pub did_key: String,
}
pub struct MlDsaKeyPair {
    pub secret_key: Vec<u8>,
    pub public_key: Vec<u8>,
}
pub struct DecodedKey {
    pub algorithm: String,
    pub raw_key: Vec<u8>,
}
pub struct VerifyResult {
    pub proof_valid: bool,
    pub time_valid: bool,
    pub valid: bool,
}

pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

pub fn canonicalize(json: String) -> Result<String, CoreError> {
    Ok(vouch_core::jcs::canonicalize_to_string(&parse(&json)?))
}

pub fn generate_ed25519() -> Result<Ed25519KeyPair, CoreError> {
    let kp = keys::Ed25519KeyPair::generate()?;
    Ok(Ed25519KeyPair {
        seed: kp.seed().to_vec(),
        public_key: kp.public_key().to_vec(),
        multikey: kp.public_multikey(),
        did_key: kp.did_key(),
    })
}

pub fn ed25519_sign(seed: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, CoreError> {
    let kp = keys::Ed25519KeyPair::from_seed_slice(&seed)?;
    Ok(kp.sign(&message).to_vec())
}

pub fn ed25519_verify(
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
) -> Result<bool, CoreError> {
    Ok(keys::verify(&public_key, &message, &signature)?)
}

pub fn encode_ed25519_multikey(public_key: Vec<u8>) -> Result<String, CoreError> {
    Ok(multikey::encode_ed25519_public(&public_key)?)
}

pub fn decode_multikey(multikey: String) -> Result<DecodedKey, CoreError> {
    let d = multikey::decode(&multikey)?;
    Ok(DecodedKey {
        algorithm: d.algorithm,
        raw_key: d.raw_key,
    })
}

pub fn did_key_from_ed25519(public_key: Vec<u8>) -> Result<String, CoreError> {
    Ok(keys::ed25519_to_did_key(&public_key)?)
}

pub fn ed25519_from_did_key(did: String) -> Result<Vec<u8>, CoreError> {
    Ok(keys::did_key_to_ed25519(&did)?)
}

pub fn build_proof(
    credential_json: String,
    seed: Vec<u8>,
    verification_method: String,
    created: String,
) -> Result<String, CoreError> {
    let opts = data_integrity::BuildProofOptions::new(verification_method, created);
    Ok(data_integrity::build_proof(&parse(&credential_json)?, &seed, &opts)?.to_string())
}

pub fn sign_credential(
    credential_json: String,
    seed: Vec<u8>,
    verification_method: String,
    created: String,
) -> Result<String, CoreError> {
    let opts = data_integrity::BuildProofOptions::new(verification_method, created);
    Ok(data_integrity::sign(&parse(&credential_json)?, &seed, &opts)?.to_string())
}

pub fn verify_proof(credential_json: String, public_key: Vec<u8>) -> Result<bool, CoreError> {
    Ok(data_integrity::verify_proof(
        &parse(&credential_json)?,
        &public_key,
    )?)
}

pub fn verify_credential(
    credential_json: String,
    public_key: Vec<u8>,
    now_iso: String,
    clock_skew_seconds: i64,
) -> Result<VerifyResult, CoreError> {
    let r = credentials::verify_credential(
        &parse(&credential_json)?,
        &public_key,
        &now_iso,
        clock_skew_seconds,
    )?;
    Ok(VerifyResult {
        proof_valid: r.proof_valid,
        time_valid: r.time_valid,
        valid: r.is_valid(),
    })
}

pub fn verify_chain_time_bound(
    chain_json: String,
    now_iso: String,
    clock_skew_seconds: i64,
) -> Result<bool, CoreError> {
    let chain = parse(&chain_json)?;
    let arr = chain
        .as_array()
        .ok_or_else(|| CoreError::Core("chain must be a JSON array".into()))?;
    Ok(delegation::verify_chain_time_bound(
        arr,
        &now_iso,
        clock_skew_seconds,
    )?)
}

#[allow(clippy::too_many_arguments)]
pub fn build_delegation_link(
    issuer: String,
    subject: String,
    intent_json: String,
    valid_from: Option<String>,
    valid_until: Option<String>,
    parent_proof_value: Option<String>,
) -> Result<String, CoreError> {
    let intent = parse(&intent_json)?;
    let input = delegation::DelegationLinkInput {
        issuer,
        subject,
        intent,
        valid_from,
        valid_until,
        parent_proof_value,
    };
    Ok(delegation::build_delegation_link(&input).to_string())
}

pub fn generate_mldsa44() -> Result<MlDsaKeyPair, CoreError> {
    let kp = pq::MlDsa44KeyPair::generate()?;
    Ok(MlDsaKeyPair {
        secret_key: kp.secret_key().to_vec(),
        public_key: kp.public_key().to_vec(),
    })
}

pub fn mldsa44_sign(
    secret: Vec<u8>,
    public_key: Vec<u8>,
    message: Vec<u8>,
) -> Result<Vec<u8>, CoreError> {
    let kp = pq::MlDsa44KeyPair::from_bytes(&secret, &public_key)?;
    Ok(kp.sign(&message)?)
}

pub fn mldsa44_verify(
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
) -> Result<bool, CoreError> {
    Ok(pq::verify(&public_key, &message, &signature)?)
}

#[allow(clippy::too_many_arguments)]
pub fn sign_dual(
    credential_json: String,
    ed25519_seed: Vec<u8>,
    mldsa_secret: Vec<u8>,
    mldsa_public: Vec<u8>,
    ed25519_vm: String,
    mldsa_vm: String,
    created: String,
) -> Result<String, CoreError> {
    let ml = pq::MlDsa44KeyPair::from_bytes(&mldsa_secret, &mldsa_public)?;
    Ok(hybrid::sign_dual(
        &parse(&credential_json)?,
        &ed25519_seed,
        &ml,
        &ed25519_vm,
        &mldsa_vm,
        &created,
    )?
    .to_string())
}

pub fn verify_dual(
    credential_json: String,
    ed25519_public: Vec<u8>,
    mldsa_public: Vec<u8>,
) -> Result<bool, CoreError> {
    Ok(hybrid::verify_dual(
        &parse(&credential_json)?,
        &ed25519_public,
        &mldsa_public,
    )?)
}

pub fn verify_composite(
    credential_json: String,
    ed25519_public: Vec<u8>,
    mldsa_public: Vec<u8>,
) -> Result<bool, CoreError> {
    Ok(hybrid::verify_composite(
        &parse(&credential_json)?,
        &ed25519_public,
        &mldsa_public,
    )?)
}

pub fn verify_status(
    credential_status_json: String,
    status_list_credential_json: String,
) -> Result<bool, CoreError> {
    Ok(status_list::verify_status(
        &parse(&credential_status_json)?,
        &parse(&status_list_credential_json)?,
    )?)
}

// ---------------------------------------------------------------------------
// Robotics (Phase 5). Thin pass-throughs to the shared JSON facades, so Swift,
// Kotlin/JVM, .NET, and C/C++ get the same robotics surface as Python/TS/Go.
// ---------------------------------------------------------------------------

pub fn robotics_mint_identity(
    robot_seed: Vec<u8>,
    params_json: String,
) -> Result<String, CoreError> {
    Ok(rjson::mint_robot_identity(&robot_seed, &params_json)?)
}
pub fn robotics_verify_identity(
    credential_json: String,
    robot_public_key: Vec<u8>,
) -> Result<String, CoreError> {
    Ok(rjson::verify_robot_identity(
        &credential_json,
        &robot_public_key,
    )?)
}
pub fn robotics_config_hash(config_json: String) -> Result<String, CoreError> {
    Ok(rjson::config_hash(&config_json)?)
}
pub fn robotics_build_provenance(
    signer_seed: Vec<u8>,
    params_json: String,
) -> Result<String, CoreError> {
    Ok(rjson::build_provenance_attestation(
        &signer_seed,
        &params_json,
    )?)
}
pub fn robotics_verify_provenance(
    attestation_json: String,
    public_key: Vec<u8>,
    config_json: Option<String>,
) -> Result<String, CoreError> {
    Ok(rjson::verify_provenance_attestation(
        &attestation_json,
        &public_key,
        config_json.as_deref(),
    )?)
}
pub fn robotics_build_scope(
    signer_seed: Vec<u8>,
    params_json: String,
) -> Result<String, CoreError> {
    Ok(rjson::build_physical_scope_credential(
        &signer_seed,
        &params_json,
    )?)
}
pub fn robotics_check_action(scope_json: String, action_json: String) -> Result<String, CoreError> {
    Ok(rjson::check_physical_action(&scope_json, &action_json)?)
}
pub fn robotics_attenuates(parent_json: String, child_json: String) -> Result<bool, CoreError> {
    Ok(rjson::attenuates(&parent_json, &child_json)?)
}
pub fn robotics_build_hello(
    signer_seed: Vec<u8>,
    params_json: String,
) -> Result<String, CoreError> {
    Ok(rjson::build_hello(&signer_seed, &params_json)?)
}
#[allow(clippy::too_many_arguments)]
pub fn robotics_build_accept(
    signer_seed: Vec<u8>,
    hello_json: String,
    hello_public_key: Vec<u8>,
    policy_json: String,
    params_json: String,
) -> Result<String, CoreError> {
    Ok(rjson::build_accept(
        &signer_seed,
        &hello_json,
        &hello_public_key,
        &policy_json,
        &params_json,
    )?)
}
pub fn robotics_verify_accept(
    accept_json: String,
    accept_public_key: Vec<u8>,
    expected_nonce: String,
    policy_json: Option<String>,
) -> Result<String, CoreError> {
    Ok(rjson::verify_accept(
        &accept_json,
        &accept_public_key,
        &expected_nonce,
        policy_json.as_deref(),
    )?)
}
pub fn robotics_build_confirm(
    signer_seed: Vec<u8>,
    from_did: String,
    session_json: String,
    created: String,
) -> Result<String, CoreError> {
    Ok(rjson::build_confirm(
        &signer_seed,
        &from_did,
        &session_json,
        &created,
    )?)
}
pub fn robotics_verify_confirm(
    confirm_json: String,
    confirm_public_key: Vec<u8>,
    session_id: String,
    expected_nonce: String,
) -> Result<bool, CoreError> {
    Ok(rjson::verify_confirm(
        &confirm_json,
        &confirm_public_key,
        &session_id,
        &expected_nonce,
    )?)
}
pub fn robotics_genesis_prev_hash() -> String {
    rjson::genesis_prev_hash()
}
#[allow(clippy::too_many_arguments)]
pub fn robotics_blackbox_append(
    key: Vec<u8>,
    seq: u64,
    event: String,
    payload_json: String,
    timestamp: String,
    prev_hash: String,
) -> Result<String, CoreError> {
    Ok(rjson::blackbox_append_entry(
        &key,
        seq,
        &event,
        &payload_json,
        &timestamp,
        &prev_hash,
    )?)
}
pub fn robotics_blackbox_open(entry_json: String, key: Vec<u8>) -> Result<String, CoreError> {
    Ok(rjson::blackbox_open_entry(&entry_json, &key)?)
}
pub fn robotics_verify_chain(
    entries_json: String,
    genesis_prev_hash: Option<String>,
) -> Result<String, CoreError> {
    Ok(rjson::verify_blackbox_chain(
        &entries_json,
        genesis_prev_hash.as_deref(),
    )?)
}
pub fn robotics_build_killswitch(
    authority_seed: Vec<u8>,
    params_json: String,
) -> Result<String, CoreError> {
    Ok(rjson::build_killswitch_credential(
        &authority_seed,
        &params_json,
    )?)
}
pub fn robotics_verify_killswitch(
    credential_json: String,
    public_key: Vec<u8>,
    trusted_authorities_json: Option<String>,
) -> Result<String, CoreError> {
    Ok(rjson::verify_killswitch_credential(
        &credential_json,
        &public_key,
        trusted_authorities_json.as_deref(),
    )?)
}
pub fn robotics_build_passport(
    signer_seed: Vec<u8>,
    params_json: String,
) -> Result<String, CoreError> {
    Ok(rjson::build_passport(&signer_seed, &params_json)?)
}
pub fn robotics_encode_passport(passport_json: String) -> Result<String, CoreError> {
    Ok(rjson::encode_passport(&passport_json)?)
}
pub fn robotics_decode_passport(uri: String) -> Result<String, CoreError> {
    Ok(rjson::decode_passport(&uri)?)
}
pub fn robotics_verify_passport(
    passport_json: String,
    public_key: Vec<u8>,
    now_iso: String,
) -> Result<String, CoreError> {
    Ok(rjson::verify_passport(
        &passport_json,
        &public_key,
        &now_iso,
    )?)
}
pub fn robotics_verify_passport_uri(
    uri: String,
    public_key: Vec<u8>,
    now_iso: String,
) -> Result<String, CoreError> {
    Ok(rjson::verify_passport_uri(&uri, &public_key, &now_iso)?)
}

// Liveness heartbeat (Phase 5.7).
pub fn robotics_motion_digest(params_json: String) -> Result<String, CoreError> {
    Ok(rjson::motion_digest(&params_json)?)
}
pub fn robotics_validate_motion_digest(digest_json: String) -> Result<bool, CoreError> {
    Ok(rjson::validate_motion_digest(&digest_json)?)
}
pub fn robotics_build_heartbeat(
    robot_seed: Vec<u8>,
    params_json: String,
) -> Result<String, CoreError> {
    Ok(rjson::build_robot_heartbeat(&robot_seed, &params_json)?)
}
pub fn robotics_verify_heartbeat(
    credential_json: String,
    robot_public_key: Vec<u8>,
) -> Result<String, CoreError> {
    Ok(rjson::verify_robot_heartbeat(
        &credential_json,
        &robot_public_key,
    )?)
}
pub fn robotics_is_live(
    credential_json: String,
    now_iso: String,
    interval_seconds: Option<i64>,
    grace_intervals: i64,
) -> Result<bool, CoreError> {
    Ok(rjson::is_live(
        &credential_json,
        &now_iso,
        interval_seconds,
        grace_intervals,
    )?)
}

// Per-credential revocation (Phase 5.8).
pub fn robotics_build_status_entry(
    status_list_credential: String,
    status_list_index: i64,
    status_purpose: String,
    entry_id: Option<String>,
) -> Result<String, CoreError> {
    Ok(rjson::build_status_list_entry(
        &status_list_credential,
        status_list_index,
        &status_purpose,
        entry_id.as_deref(),
    )?)
}
pub fn robotics_attach_status(
    credential_json: String,
    signer_seed: Vec<u8>,
    params_json: String,
) -> Result<String, CoreError> {
    Ok(rjson::attach_credential_status(
        &credential_json,
        &signer_seed,
        &params_json,
    )?)
}
pub fn robotics_check_status(
    credential_json: String,
    status_list_credential_json: String,
    status_purpose: String,
) -> Result<bool, CoreError> {
    Ok(rjson::check_credential_status(
        &credential_json,
        &status_list_credential_json,
        &status_purpose,
    )?)
}

// Accountable safety record (Phase 5.9).
pub fn robotics_safety_append(params_json: String) -> Result<String, CoreError> {
    Ok(rjson::safety_append_entry(&params_json)?)
}
pub fn robotics_verify_safety_log(
    entries_json: String,
    genesis_prev_hash: Option<String>,
) -> Result<String, CoreError> {
    Ok(rjson::verify_safety_log(
        &entries_json,
        genesis_prev_hash.as_deref(),
    )?)
}
pub fn robotics_summarize_safety(
    entries_json: String,
    head: Option<String>,
) -> Result<String, CoreError> {
    Ok(rjson::summarize_entries(&entries_json, head.as_deref())?)
}
pub fn robotics_build_safety_record(
    signer_seed: Vec<u8>,
    params_json: String,
) -> Result<String, CoreError> {
    Ok(rjson::build_safety_record(&signer_seed, &params_json)?)
}
pub fn robotics_verify_safety_record(
    credential_json: String,
    public_key: Vec<u8>,
) -> Result<String, CoreError> {
    Ok(rjson::verify_safety_record(&credential_json, &public_key)?)
}

// Perception provenance (Phase 5.10).
pub fn robotics_hash_frame(frame: Vec<u8>) -> String {
    rjson::hash_frame(&frame)
}
pub fn robotics_perception_record(params_json: String) -> Result<String, CoreError> {
    Ok(rjson::perception_record_entry(&params_json)?)
}
pub fn robotics_verify_perception_log(
    entries_json: String,
    genesis_prev_hash: Option<String>,
) -> Result<String, CoreError> {
    Ok(rjson::verify_perception_log(
        &entries_json,
        genesis_prev_hash.as_deref(),
    )?)
}
pub fn robotics_build_perception(
    robot_seed: Vec<u8>,
    params_json: String,
) -> Result<String, CoreError> {
    Ok(rjson::build_perception_attestation(
        &robot_seed,
        &params_json,
    )?)
}
pub fn robotics_verify_perception(
    credential_json: String,
    public_key: Vec<u8>,
    frame_mb: Option<String>,
) -> Result<String, CoreError> {
    Ok(rjson::verify_perception_attestation(
        &credential_json,
        &public_key,
        frame_mb.as_deref(),
    )?)
}
pub fn robotics_build_lease(
    signer_seed: Vec<u8>,
    params_json: String,
) -> Result<String, CoreError> {
    Ok(rjson::build_delegation_lease(&signer_seed, &params_json)?)
}
pub fn robotics_verify_lease(
    credential_json: String,
    public_key: Vec<u8>,
    now_iso: Option<String>,
    parent_scope_json: Option<String>,
) -> Result<String, CoreError> {
    Ok(rjson::verify_delegation_lease(
        &credential_json,
        &public_key,
        now_iso.as_deref(),
        parent_scope_json.as_deref(),
    )?)
}
pub fn robotics_lease_permits(params_json: String) -> Result<bool, CoreError> {
    Ok(rjson::lease_permits(&params_json)?)
}
pub fn robotics_build_action_approval(
    approver_seed: Vec<u8>,
    params_json: String,
) -> Result<String, CoreError> {
    Ok(rjson::build_action_approval(&approver_seed, &params_json)?)
}
pub fn robotics_verify_action_authorization(params_json: String) -> Result<String, CoreError> {
    Ok(rjson::verify_action_authorization(&params_json)?)
}
pub fn robotics_build_ownership_transfer(
    current_owner_seed: Vec<u8>,
    params_json: String,
) -> Result<String, CoreError> {
    Ok(rjson::build_ownership_transfer(
        &current_owner_seed,
        &params_json,
    )?)
}
pub fn robotics_verify_ownership_transfer(
    credential_json: String,
    public_key: Vec<u8>,
) -> Result<String, CoreError> {
    Ok(rjson::verify_ownership_transfer(
        &credential_json,
        &public_key,
    )?)
}
pub fn robotics_verify_custody_chain(params_json: String) -> Result<String, CoreError> {
    Ok(rjson::verify_custody_chain(&params_json)?)
}
pub fn robotics_build_key_rotation(
    old_key_seed: Vec<u8>,
    params_json: String,
) -> Result<String, CoreError> {
    Ok(rjson::build_key_rotation(&old_key_seed, &params_json)?)
}
pub fn robotics_verify_key_rotation(
    credential_json: String,
    old_public_key: Vec<u8>,
) -> Result<String, CoreError> {
    Ok(rjson::verify_key_rotation(
        &credential_json,
        &old_public_key,
    )?)
}
pub fn robotics_verify_key_history(params_json: String) -> Result<String, CoreError> {
    Ok(rjson::verify_key_history(&params_json)?)
}
pub fn robotics_build_decommission(
    signer_seed: Vec<u8>,
    params_json: String,
) -> Result<String, CoreError> {
    Ok(rjson::build_decommission(&signer_seed, &params_json)?)
}
pub fn robotics_verify_decommission(
    credential_json: String,
    public_key: Vec<u8>,
    trusted_authorities_json: Option<String>,
) -> Result<String, CoreError> {
    Ok(rjson::verify_decommission(
        &credential_json,
        &public_key,
        trusted_authorities_json.as_deref(),
    )?)
}
pub fn robotics_check_conformance(
    credentials_json: String,
    profile_id: String,
) -> Result<String, CoreError> {
    Ok(rjson::check_conformance(&credentials_json, &profile_id)?)
}
pub fn robotics_report_digest(report_json: String) -> Result<String, CoreError> {
    Ok(rjson::report_digest(&report_json)?)
}
pub fn robotics_build_conformance_attestation(
    signer_seed: Vec<u8>,
    params_json: String,
) -> Result<String, CoreError> {
    Ok(rjson::build_conformance_attestation(
        &signer_seed,
        &params_json,
    )?)
}
pub fn robotics_verify_conformance_attestation(
    credential_json: String,
    public_key: Vec<u8>,
) -> Result<String, CoreError> {
    Ok(rjson::verify_conformance_attestation(
        &credential_json,
        &public_key,
    )?)
}

uniffi::include_scaffolding!("vouch_core");
