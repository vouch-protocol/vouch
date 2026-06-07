//! UniFFI bindings for the Vouch Protocol core.
//!
//! A thin layer over `vouch-core` exposing the protocol primitives to Swift,
//! Kotlin/Java, and (via the generated C header) .NET and C/C++. Binary values
//! are `Vec<u8>`; credentials and proofs are JSON strings. Every function
//! delegates to the canonical core, so all platforms produce identical bytes.

use serde_json::Value;

use vouch_core::{credentials, data_integrity, delegation, hybrid, keys, multikey, pq, status_list};

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
    Ok(data_integrity::verify_proof(&parse(&credential_json)?, &public_key)?)
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
    Ok(delegation::verify_chain_time_bound(arr, &now_iso, clock_skew_seconds)?)
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
    Ok(
        hybrid::sign_dual(&parse(&credential_json)?, &ed25519_seed, &ml, &ed25519_vm, &mldsa_vm, &created)?
            .to_string(),
    )
}

pub fn verify_dual(
    credential_json: String,
    ed25519_public: Vec<u8>,
    mldsa_public: Vec<u8>,
) -> Result<bool, CoreError> {
    Ok(hybrid::verify_dual(&parse(&credential_json)?, &ed25519_public, &mldsa_public)?)
}

pub fn verify_composite(
    credential_json: String,
    ed25519_public: Vec<u8>,
    mldsa_public: Vec<u8>,
) -> Result<bool, CoreError> {
    Ok(hybrid::verify_composite(&parse(&credential_json)?, &ed25519_public, &mldsa_public)?)
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

uniffi::include_scaffolding!("vouch_core");
