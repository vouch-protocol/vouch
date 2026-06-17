//! Robotics primitives (Phase 5), one byte-exact implementation in the core.
//!
//! Mirrors the Python `vouch.robotics` package and the TypeScript/Go SDKs so that
//! a robotics credential built in any language verifies in every other. Exposing
//! this module through the UniFFI and WASM wrappers gives Swift, Kotlin/JVM,
//! .NET, C/C++, and the browser the same robotics surface without re-deriving it.
//!
//! This file covers hardware-rooted robot identity (Phase 5.1). The remaining
//! capabilities (provenance, capability scope, handshake, black box, passport)
//! are added alongside it.
//!
//! Design: the core is hardware-agnostic and deterministic. A robot self-issues
//! its `RobotIdentityCredential` with its own Ed25519 key; the hardware root (a
//! TPM, secure element, or a software root in development) signs a binding over
//! the robot DID and key, supplied to [`mint_robot_identity`] as the attestation
//! bytes. Timestamps are caller-supplied, matching the rest of the core, so the
//! output is reproducible and the wrappers control the clock.

use serde_json::{json, Map, Value};

use crate::data_integrity::{self, BuildProofOptions};
use crate::error::{CoreError, Result};
use crate::keys;
use crate::{jcs, multikey};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

pub const VC_CONTEXT_V2: &str = "https://www.w3.org/ns/credentials/v2";
pub const VOUCH_CONTEXT_V1: &str = "https://vouch-protocol.com/contexts/v1";
pub const ROBOT_IDENTITY_TYPE: &str = "RobotIdentityCredential";

/// Multibase ('u') base64url-no-pad encoding, matching the Python/TS/Go `mb64`.
pub(crate) fn mb64(bytes: &[u8]) -> String {
    format!("u{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// Decode a multibase ('u') base64url-no-pad string.
pub(crate) fn unmb64(s: &str) -> Result<Vec<u8>> {
    let body = s
        .strip_prefix('u')
        .ok_or_else(|| CoreError::Json("expected multibase 'u' prefix".into()))?;
    URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|e| CoreError::Json(format!("bad base64url: {e}")))
}

/// True if `type_field` (a JSON string or array of strings) contains `want`.
pub(crate) fn has_type(type_field: Option<&Value>, want: &str) -> bool {
    match type_field {
        Some(Value::String(s)) => s == want,
        Some(Value::Array(items)) => items.iter().any(|v| v.as_str() == Some(want)),
        _ => false,
    }
}

/// The canonical bytes a hardware root signs to bind a robot's identity key to
/// its hardware: JCS of `{"key": robot_key_multibase, "robotDid": robot_did}`.
pub fn robot_identity_binding(robot_did: &str, robot_key_multibase: &str) -> Vec<u8> {
    jcs::canonicalize(&json!({
        "key": robot_key_multibase,
        "robotDid": robot_did,
    }))
}

/// Parameters for [`mint_robot_identity`]. Timestamps are ISO-8601 strings the
/// caller supplies. `attestation` is the hardware root's signature over
/// [`robot_identity_binding`]; `root_public_multibase` is that root's public key.
#[derive(Debug, Clone)]
pub struct MintRobotIdentity {
    pub robot_did: String,
    pub make: String,
    pub model: String,
    pub serial: String,
    pub owner: Option<String>,
    pub root_kind: String,
    pub root_public_multibase: String,
    pub attestation: Vec<u8>,
    /// Optional explicit lifecycle array; defaults to a single "commissioned" entry.
    pub lifecycle: Option<Value>,
    pub valid_from: String,
    pub valid_until: Option<String>,
}

/// Mint a hardware-attested `RobotIdentityCredential`, signed by the robot's own
/// Ed25519 seed. The hardware-root attestation is embedded as
/// `credentialSubject.hardwareRoot.attestation`.
pub fn mint_robot_identity(robot_seed: &[u8], params: &MintRobotIdentity) -> Result<Value> {
    let lifecycle = params
        .lifecycle
        .clone()
        .unwrap_or_else(|| json!([{ "event": "commissioned", "timestamp": params.valid_from }]));

    let mut subject = Map::new();
    subject.insert("id".into(), json!(params.robot_did));
    subject.insert("make".into(), json!(params.make));
    subject.insert("model".into(), json!(params.model));
    subject.insert("serial".into(), json!(params.serial));
    subject.insert(
        "hardwareRoot".into(),
        json!({
            "kind": params.root_kind,
            "publicKeyMultibase": params.root_public_multibase,
            "attestation": mb64(&params.attestation),
        }),
    );
    subject.insert("lifecycle".into(), lifecycle);
    if let Some(owner) = &params.owner {
        subject.insert("owner".into(), json!(owner));
    }

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert(
        "type".into(),
        json!(["VerifiableCredential", ROBOT_IDENTITY_TYPE]),
    );
    cred.insert("issuer".into(), json!(params.robot_did));
    cred.insert("validFrom".into(), json!(params.valid_from));
    if let Some(vu) = &params.valid_until {
        cred.insert("validUntil".into(), json!(vu));
    }
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(
        format!("{}#key-1", params.robot_did),
        params.valid_from.clone(),
    );
    data_integrity::sign(&Value::Object(cred), robot_seed, &opts)
}

/// Verify a `RobotIdentityCredential`: both the credential proof (under
/// `robot_public_key`) AND the hardware-root attestation binding the robot key to
/// the hardware. Returns the credentialSubject on success, `None` if invalid.
pub fn verify_robot_identity(credential: &Value, robot_public_key: &[u8]) -> Result<Option<Value>> {
    let obj = credential
        .as_object()
        .ok_or_else(|| CoreError::Json("credential must be a JSON object".into()))?;
    if !has_type(obj.get("type"), ROBOT_IDENTITY_TYPE) {
        return Ok(None);
    }
    if !data_integrity::verify_proof(credential, robot_public_key)? {
        return Ok(None);
    }

    let subject = match obj.get("credentialSubject").and_then(|s| s.as_object()) {
        Some(s) => s,
        None => return Ok(None),
    };
    let hw = match subject.get("hardwareRoot").and_then(|h| h.as_object()) {
        Some(h) => h,
        None => return Ok(None),
    };
    let hw_mb = match hw.get("publicKeyMultibase").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return Ok(None),
    };
    let attestation_mb = match hw.get("attestation").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return Ok(None),
    };

    let decoded = match multikey::decode(hw_mb) {
        Ok(d) if d.algorithm == "Ed25519" && d.raw_key.len() == 32 => d,
        _ => return Ok(None),
    };
    let attestation = match unmb64(attestation_mb) {
        Ok(a) => a,
        Err(_) => return Ok(None),
    };

    let robot_key_mb = multikey::encode_ed25519_public(robot_public_key)?;
    let robot_did = subject.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let binding = robot_identity_binding(robot_did, &robot_key_mb);

    if !keys::verify(&decoded.raw_key, &binding, &attestation)? {
        return Ok(None);
    }
    Ok(Some(Value::Object(subject.clone())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Ed25519KeyPair;
    use std::fs;

    fn software_root_attest(root_seed: &[u8], robot_did: &str, robot_key_mb: &str) -> Vec<u8> {
        let kp = Ed25519KeyPair::from_seed_slice(root_seed).unwrap();
        let binding = robot_identity_binding(robot_did, robot_key_mb);
        kp.sign(&binding).to_vec()
    }

    // Cross-language interop: Go and TypeScript verify this same Python-minted
    // credential; the Rust core must too.
    #[test]
    fn verifies_python_interop_vector() {
        let raw = fs::read_to_string("../../test-vectors/robotics/vector.json")
            .expect("interop vector present");
        let vector: Value = serde_json::from_str(&raw).unwrap();
        let jwk_x = vector["robot_public_key_jwk"]["x"].as_str().unwrap();
        let robot_pub = URL_SAFE_NO_PAD.decode(jwk_x).unwrap();
        let cred = vector["robot_identity_credential"].clone();

        let subject = verify_robot_identity(&cred, &robot_pub).unwrap();
        let subject = subject.expect("the Python interop vector must verify in Rust");
        assert_eq!(subject["make"], json!("Acme Robotics"));
    }

    #[test]
    fn mint_verify_roundtrip() {
        let robot_seed = [3u8; 32];
        let root_seed = [7u8; 32];
        let robot_did = "did:web:robot.example.com";
        let robot_kp = Ed25519KeyPair::from_seed(&robot_seed);
        let root_kp = Ed25519KeyPair::from_seed(&root_seed);

        let attestation = software_root_attest(&root_seed, robot_did, &robot_kp.public_multikey());
        let params = MintRobotIdentity {
            robot_did: robot_did.into(),
            make: "Acme".into(),
            model: "AR-7".into(),
            serial: "SN-1".into(),
            owner: Some("did:web:owner.example.com".into()),
            root_kind: "TPM".into(),
            root_public_multibase: root_kp.public_multikey(),
            attestation,
            lifecycle: None,
            valid_from: "2026-01-01T00:00:00Z".into(),
            valid_until: None,
        };
        let cred = mint_robot_identity(&robot_seed, &params).unwrap();
        let subject = verify_robot_identity(&cred, &robot_kp.public_key()).unwrap();
        assert!(subject.is_some(), "round-trip identity must verify");
    }

    #[test]
    fn forged_hardware_root_fails() {
        let robot_seed = [3u8; 32];
        let root_seed = [7u8; 32];
        let attacker_seed = [9u8; 32];
        let robot_did = "did:web:robot.example.com";
        let robot_kp = Ed25519KeyPair::from_seed(&robot_seed);
        let root_kp = Ed25519KeyPair::from_seed(&root_seed);
        let attacker_kp = Ed25519KeyPair::from_seed(&attacker_seed);

        let attestation = software_root_attest(&root_seed, robot_did, &robot_kp.public_multikey());
        let params = MintRobotIdentity {
            robot_did: robot_did.into(),
            make: "Acme".into(),
            model: "AR-7".into(),
            serial: "SN-1".into(),
            owner: None,
            root_kind: "TPM".into(),
            root_public_multibase: root_kp.public_multikey(),
            attestation,
            lifecycle: None,
            valid_from: "2026-01-01T00:00:00Z".into(),
            valid_until: None,
        };
        let mut cred = mint_robot_identity(&robot_seed, &params).unwrap();

        // Point the hardware-root key at an attacker's and re-sign the credential
        // proof; the attestation over the binding no longer matches.
        cred["credentialSubject"]["hardwareRoot"]["publicKeyMultibase"] =
            json!(attacker_kp.public_multikey());
        let resigned = {
            let mut bare = cred.clone();
            bare.as_object_mut().unwrap().remove("proof");
            let opts = BuildProofOptions::new(format!("{robot_did}#key-1"), "2026-01-01T00:00:00Z");
            data_integrity::sign(&bare, &robot_seed, &opts).unwrap()
        };
        assert!(verify_robot_identity(&resigned, &robot_kp.public_key())
            .unwrap()
            .is_none());
    }
}
