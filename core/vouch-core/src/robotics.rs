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
use crate::pq::{MlDsa44KeyPair, MLDSA44_PUBLIC_LEN};
use crate::root_of_trust::{self, ACTION_ISSUE_ROBOT_IDENTITY};
use crate::{hybrid, jcs, multikey};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

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

// ---------------------------------------------------------------------------
// Root of Trust for robot identity (Phase 5.1, authority binding)
// ---------------------------------------------------------------------------
//
// Byte-exact port of the Python reference `vouch/robotics/root_identity.py`.
//
// The Root of Trust for Machine Identity lets one pinned Vouch root recognize
// issuers, and a recognized issuer bind a subject DID to attributes, verified
// offline against that one pinned root. This extends it to robots. A recognized
// manufacturer (an issuer the root granted the `issueRobotIdentity` action)
// issues an identity that binds a robot's DID and its hardware-rooted key to
// attributes such as make, model, serial, and owner. The robot separately holds
// a hardware-attested `RobotIdentityCredential` proving its key is bound to a
// secure element.
//
// [`verify_robot_identity_chain`] closes the loop: from one pinned root a
// verifier confirms both that the robot is a legitimate robot from a recognized
// manufacturer (the authority chain via [`root_of_trust::verify_identity_chain`])
// and that the key the manufacturer vouched for is genuinely hardware-rooted (the
// secure-element attestation via [`verify_robot_identity`]), and that the two
// name the same robot and the same key. It follows the anchor-once model and the
// reason-code style of the underlying root_of_trust.

/// Outcome of [`verify_robot_identity_chain`].
///
/// `ok` is true only if the authority chain verified against the pinned root AND
/// the vouched key is hardware-rooted for the same robot. On failure `reason`
/// carries a structured code matching the Python reference exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RobotIdentityChainResult {
    pub ok: bool,
    pub reason: Option<String>,
    pub robot_did: Option<String>,
    pub issuer_did: Option<String>,
    pub root_did: Option<String>,
    pub attributes: Option<Value>,
    pub hardware_rooted: bool,
}

impl RobotIdentityChainResult {
    /// A failure result carrying the reason code and the pinned root that was in
    /// force when the check failed.
    fn fail(reason: impl Into<String>, root_did: &str) -> Self {
        Self {
            ok: false,
            reason: Some(reason.into()),
            robot_did: None,
            issuer_did: None,
            root_did: Some(root_did.to_string()),
            attributes: None,
            hardware_rooted: false,
        }
    }
}

/// Issue an authority robot identity: a recognized manufacturer binds `robot_did`,
/// its hardware-rooted key (`hardware_key_multibase`, the robot's Ed25519 key as a
/// multikey), and identity `attributes` (make, model, serial, owner). The
/// manufacturer (derived from `issuer_seed`) must be a recognized issuer for the
/// `issueRobotIdentity` action.
///
/// The credential is an `AgentIdentityCredential` so the shared identity-chain
/// verification applies, with a `kind` of "robot" and the hardware key carried in
/// the bound identity attributes.
#[allow(clippy::too_many_arguments)]
pub fn build_robot_identity(
    issuer_seed: &[u8],
    robot_did: &str,
    hardware_key_multibase: &str,
    attributes: &Value,
    valid_seconds: i64,
    valid_from: &str,
    created: &str,
    credential_status: Option<Value>,
    credential_id: &str,
) -> Result<Value> {
    if robot_did.is_empty() {
        return Err(CoreError::Json("robot_did is required".into()));
    }
    if hardware_key_multibase.is_empty() {
        return Err(CoreError::Json("hardware_key_multibase is required".into()));
    }
    let bound = match attributes.as_object() {
        Some(o) if !o.is_empty() => {
            let mut m = o.clone();
            m.insert("kind".into(), json!("robot"));
            m.insert("hardwareKey".into(), json!(hardware_key_multibase));
            Value::Object(m)
        }
        _ => {
            return Err(CoreError::Json(
                "attributes must be a non-empty object".into(),
            ))
        }
    };
    root_of_trust::build_agent_identity(
        issuer_seed,
        robot_did,
        &bound,
        valid_seconds,
        valid_from,
        created,
        credential_status,
        credential_id,
    )
}

/// Verify a robot's identity against a single pinned Vouch root, confirming both
/// provenance and hardware-rooting.
///
/// From `trusted_root`, the pinned root DID:
///
///   1. The authority chain: the recognized manufacturer must be recognized by
///      the pinned root for the `issueRobotIdentity` action, and the authority
///      identity must be signed by that manufacturer (shared identity-chain verify).
///   2. The vouched key: the authority identity must carry a hardware key.
///   3. The hardware root: the robot's own `RobotIdentityCredential` must verify
///      under `robot_public_key` and its secure-element attestation, name the same
///      robot, and its key must equal the key the manufacturer vouched for.
///
/// `robot_public_key` is the robot's raw 32-byte Ed25519 public key. `now_iso` is
/// the current instant used for the temporal window; `clock_skew_seconds` is the
/// allowed drift. Reason codes on failure match the Python reference exactly.
#[allow(clippy::too_many_arguments)]
pub fn verify_robot_identity_chain(
    authority_identity: &Value,
    recognized_issuer_credential: &Value,
    robot_hardware_credential: &Value,
    trusted_root: &str,
    robot_public_key: &[u8],
    root_credential: Option<&Value>,
    now_iso: &str,
    clock_skew_seconds: i64,
) -> RobotIdentityChainResult {
    let chain = root_of_trust::verify_identity_chain(
        authority_identity,
        recognized_issuer_credential,
        trusted_root,
        root_credential,
        None,
        ACTION_ISSUE_ROBOT_IDENTITY,
        now_iso,
        clock_skew_seconds,
    );
    if !chain.ok {
        return RobotIdentityChainResult {
            ok: false,
            reason: chain.reason,
            robot_did: None,
            issuer_did: None,
            root_did: Some(trusted_root.to_string()),
            attributes: None,
            hardware_rooted: false,
        };
    }

    let attributes = match &chain.attributes {
        Some(v @ Value::Object(_)) => v.clone(),
        _ => json!({}),
    };
    let hardware_key = match attributes.get("hardwareKey").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return RobotIdentityChainResult::fail("identity_no_hardware_key", trusted_root),
    };

    let hw_subject = match verify_robot_identity(robot_hardware_credential, robot_public_key) {
        Ok(Some(s)) => s,
        _ => return RobotIdentityChainResult::fail("hardware_root_invalid", trusted_root),
    };
    if hw_subject.get("id").and_then(|v| v.as_str()) != chain.agent_did.as_deref() {
        return RobotIdentityChainResult::fail("hardware_subject_mismatch", trusted_root);
    }

    let robot_key_mb = match multikey::encode_ed25519_public(robot_public_key) {
        Ok(mb) => mb,
        Err(_) => return RobotIdentityChainResult::fail("hardware_key_unresolvable", trusted_root),
    };
    if robot_key_mb != hardware_key {
        return RobotIdentityChainResult::fail("hardware_key_mismatch", trusted_root);
    }

    RobotIdentityChainResult {
        ok: true,
        reason: None,
        robot_did: chain.agent_did,
        issuer_did: chain.issuer_did,
        root_did: Some(trusted_root.to_string()),
        attributes: Some(attributes),
        hardware_rooted: true,
    }
}

// ---------------------------------------------------------------------------
// Model and config provenance (Phase 5.2)
// ---------------------------------------------------------------------------

pub const MODEL_PROVENANCE_TYPE: &str = "ModelProvenanceAttestation";

/// Multibase SHA-256 of the JCS-canonical config object. Python, TypeScript, Go,
/// and Rust all canonicalize identically, so the digest is the same byte string
/// in every language.
pub fn config_hash(config: &Value) -> String {
    let digest = Sha256::digest(jcs::canonicalize(config));
    mb64(&digest)
}

/// Parameters for [`build_provenance_attestation`]. The issuer is the signer (the
/// robot itself or an authority); `robot_did` names the robot the attestation is
/// about.
#[derive(Debug, Clone)]
pub struct BuildProvenance {
    pub issuer_did: String,
    pub robot_did: String,
    pub model_name: String,
    pub weights_hash: String,
    pub safety_policy: String,
    pub config: Option<Value>,
    pub version: Option<String>,
    pub supersedes: Option<String>,
    pub valid_from: String,
    pub valid_until: Option<String>,
}

/// Build a signed `ModelProvenanceAttestation` for the software on a robot.
pub fn build_provenance_attestation(signer_seed: &[u8], params: &BuildProvenance) -> Result<Value> {
    let mut vla = Map::new();
    vla.insert("modelName".into(), json!(params.model_name));
    vla.insert("weightsHash".into(), json!(params.weights_hash));
    vla.insert("safetyPolicy".into(), json!(params.safety_policy));
    if let Some(v) = &params.version {
        vla.insert("version".into(), json!(v));
    }
    if let Some(cfg) = &params.config {
        vla.insert("configHash".into(), json!(config_hash(cfg)));
    }

    let mut subject = Map::new();
    subject.insert("id".into(), json!(params.robot_did));
    subject.insert("vla".into(), Value::Object(vla));
    if let Some(s) = &params.supersedes {
        subject.insert("supersedes".into(), json!(s));
    }

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert(
        "type".into(),
        json!(["VerifiableCredential", MODEL_PROVENANCE_TYPE]),
    );
    cred.insert("issuer".into(), json!(params.issuer_did));
    cred.insert("validFrom".into(), json!(params.valid_from));
    if let Some(vu) = &params.valid_until {
        cred.insert("validUntil".into(), json!(vu));
    }
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(
        format!("{}#key-1", params.issuer_did),
        params.valid_from.clone(),
    );
    data_integrity::sign(&Value::Object(cred), signer_seed, &opts)
}

/// Verify a `ModelProvenanceAttestation`. When `config` is supplied, also check
/// the recorded configHash reproduces. Returns the subject on success, `None`
/// otherwise.
pub fn verify_provenance_attestation(
    attestation: &Value,
    public_key: &[u8],
    config: Option<&Value>,
) -> Result<Option<Value>> {
    let obj = attestation
        .as_object()
        .ok_or_else(|| CoreError::Json("attestation must be a JSON object".into()))?;
    if !has_type(obj.get("type"), MODEL_PROVENANCE_TYPE) {
        return Ok(None);
    }
    if !data_integrity::verify_proof(attestation, public_key)? {
        return Ok(None);
    }
    let subject = match obj.get("credentialSubject").and_then(|s| s.as_object()) {
        Some(s) => s,
        None => return Ok(None),
    };
    if let Some(cfg) = config {
        let want = config_hash(cfg);
        let got = subject
            .get("vla")
            .and_then(|v| v.as_object())
            .and_then(|v| v.get("configHash"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if got != want {
            return Ok(None);
        }
    }
    Ok(Some(Value::Object(subject.clone())))
}

// ---------------------------------------------------------------------------
// Physical capability scope (Phase 5.3)
// ---------------------------------------------------------------------------

pub const PHYSICAL_SCOPE_TYPE: &str = "PhysicalCapabilityScope";

/// An allowed time-of-day window, "HH:MM" start and end.
#[derive(Debug, Clone)]
pub struct ShiftWindow {
    pub start: String,
    pub end: String,
}

/// A proposed actuation to check against a scope. `None` numerics mean "not
/// specified" (a meaningful zero is still `Some(0.0)`).
#[derive(Debug, Clone, Default)]
pub struct PhysicalAction {
    pub force_n: Option<f64>,
    pub speed_mps: Option<f64>,
    pub near_humans: bool,
    pub zone: Option<String>,
    pub time_hm: Option<String>,
}

/// The outcome of [`check_physical_action`].
#[derive(Debug, Clone)]
pub struct CheckResult {
    pub ok: bool,
    pub reasons: Vec<String>,
}

/// Parameters for [`build_physical_scope_credential`]. The issuer is the signer
/// (a fleet authority); `subject_did` is the robot the scope is granted to.
#[derive(Debug, Clone, Default)]
pub struct BuildPhysicalScope {
    pub issuer_did: String,
    pub subject_did: String,
    pub max_force_n: Option<f64>,
    pub max_speed_mps: Option<f64>,
    pub max_speed_near_humans_mps: Option<f64>,
    pub allowed_zones: Option<Vec<String>>,
    pub shift_windows: Option<Vec<ShiftWindow>>,
    pub valid_from: String,
    pub valid_until: Option<String>,
}

/// Build a signed `PhysicalCapabilityScope` credential.
pub fn build_physical_scope_credential(
    signer_seed: &[u8],
    params: &BuildPhysicalScope,
) -> Result<Value> {
    let mut scope = Map::new();
    if let Some(v) = params.max_force_n {
        scope.insert("maxForceN".into(), json!(v));
    }
    if let Some(v) = params.max_speed_mps {
        scope.insert("maxSpeedMps".into(), json!(v));
    }
    if let Some(v) = params.max_speed_near_humans_mps {
        scope.insert("maxSpeedNearHumansMps".into(), json!(v));
    }
    if let Some(zones) = &params.allowed_zones {
        scope.insert("allowedZones".into(), json!(zones));
    }
    if let Some(ws) = &params.shift_windows {
        let arr: Vec<Value> = ws
            .iter()
            .map(|w| json!({"start": w.start, "end": w.end}))
            .collect();
        scope.insert("shiftWindows".into(), Value::Array(arr));
    }

    let mut subject = Map::new();
    subject.insert("id".into(), json!(params.subject_did));
    subject.insert("physicalScope".into(), Value::Object(scope));

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert(
        "type".into(),
        json!(["VerifiableCredential", PHYSICAL_SCOPE_TYPE]),
    );
    cred.insert("issuer".into(), json!(params.issuer_did));
    cred.insert("validFrom".into(), json!(params.valid_from));
    if let Some(vu) = &params.valid_until {
        cred.insert("validUntil".into(), json!(vu));
    }
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(
        format!("{}#key-1", params.issuer_did),
        params.valid_from.clone(),
    );
    data_integrity::sign(&Value::Object(cred), signer_seed, &opts)
}

fn scope_num(scope: &Map<String, Value>, key: &str) -> Option<f64> {
    scope.get(key).and_then(|v| v.as_f64())
}

fn window_bounds(w: &Value) -> (String, String) {
    let start = w
        .get("start")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("00:00")
        .to_string();
    let end = w
        .get("end")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("23:59")
        .to_string();
    (start, end)
}

fn in_window(hm: &str, w: &Value) -> bool {
    let (start, end) = window_bounds(w);
    start.as_str() <= hm && hm <= end.as_str()
}

/// Check a proposed physical action against a physical scope object, returning ok
/// plus a reason for each violated dimension. Accepts both native and
/// JSON-decoded scope shapes.
pub fn check_physical_action(scope: &Value, action: &PhysicalAction) -> CheckResult {
    let empty = Map::new();
    let scope = scope.as_object().unwrap_or(&empty);
    let mut reasons = Vec::new();

    if let Some(force) = action.force_n {
        if let Some(cap) = scope_num(scope, "maxForceN") {
            if force > cap {
                reasons.push(format!("force_exceeded: {force}N > {cap}N"));
            }
        }
    }

    if let Some(speed) = action.speed_mps {
        let mut cap = scope_num(scope, "maxSpeedMps");
        if action.near_humans {
            if let Some(nh) = scope_num(scope, "maxSpeedNearHumansMps") {
                cap = Some(nh);
            }
        }
        if let Some(c) = cap {
            if speed > c {
                let label = if action.near_humans {
                    "near_humans "
                } else {
                    ""
                };
                reasons.push(format!("{label}speed_exceeded: {speed} m/s > {c} m/s"));
            }
        }
    }

    if let Some(zone) = &action.zone {
        if let Some(zones) = scope.get("allowedZones").and_then(|v| v.as_array()) {
            if !zones.iter().any(|z| z.as_str() == Some(zone.as_str())) {
                reasons.push(format!("zone_not_allowed: {zone}"));
            }
        }
    }

    if let Some(time_hm) = &action.time_hm {
        if let Some(windows) = scope.get("shiftWindows").and_then(|v| v.as_array()) {
            if !windows.is_empty() && !windows.iter().any(|w| in_window(time_hm, w)) {
                reasons.push(format!("outside_shift_window: {time_hm}"));
            }
        }
    }

    CheckResult {
        ok: reasons.is_empty(),
        reasons,
    }
}

/// Report whether `child` is a valid attenuation of `parent`: never broader on
/// any physical dimension. The privilege-escalation guard for delegated scopes.
pub fn attenuates(parent: &Value, child: &Value) -> bool {
    let empty = Map::new();
    let p = parent.as_object().unwrap_or(&empty);
    let c = child.as_object().unwrap_or(&empty);

    for key in ["maxForceN", "maxSpeedMps", "maxSpeedNearHumansMps"] {
        if let Some(pv) = scope_num(p, key) {
            match scope_num(c, key) {
                Some(cv) if cv <= pv => {}
                _ => return false,
            }
        }
    }

    if let Some(pz) = p.get("allowedZones").and_then(|v| v.as_array()) {
        let pset: Vec<&str> = pz.iter().filter_map(|z| z.as_str()).collect();
        let cz: Vec<&str> = c
            .get("allowedZones")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|z| z.as_str()).collect())
            .unwrap_or_default();
        if cz.is_empty() || !cz.iter().all(|z| pset.contains(z)) {
            return false;
        }
    }

    if let Some(pw) = p.get("shiftWindows").and_then(|v| v.as_array()) {
        let empty_arr = Vec::new();
        let cw = c
            .get("shiftWindows")
            .and_then(|v| v.as_array())
            .unwrap_or(&empty_arr);
        for cwin in cw {
            let (cs, ce) = window_bounds(cwin);
            let fits = pw.iter().any(|pwin| {
                let (ps, pe) = window_bounds(pwin);
                ps.as_str() <= cs.as_str() && ce.as_str() <= pe.as_str()
            });
            if !fits {
                return false;
            }
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Robot-to-robot trust handshake (Phase 5.4)
// ---------------------------------------------------------------------------

pub const HELLO: &str = "handshake_hello";
pub const ACCEPT: &str = "handshake_accept";
pub const CONFIRM: &str = "handshake_confirm";

/// Decides whether a peer DID is trusted: its did:web domain must be allowed, or
/// `accept_unknown` is set.
#[derive(Debug, Clone, Default)]
pub struct TrustPolicy {
    pub trusted_domains: HashSet<String>,
    pub accept_unknown: bool,
}

impl TrustPolicy {
    pub fn new(domains: impl IntoIterator<Item = String>, accept_unknown: bool) -> Self {
        Self {
            trusted_domains: domains.into_iter().collect(),
            accept_unknown,
        }
    }

    pub fn is_trusted(&self, did: &str) -> bool {
        if self.accept_unknown {
            return true;
        }
        match did_web_domain(did) {
            Some(d) => self.trusted_domains.contains(d),
            None => false,
        }
    }
}

/// The agreed cooperation session after a successful handshake.
#[derive(Debug, Clone)]
pub struct BoundedSession {
    pub session_id: String,
    pub initiator: String,
    pub responder: String,
    pub scope: Vec<String>,
    pub nonce: String,
    pub valid_until: Option<String>,
}

fn did_web_domain(did: &str) -> Option<&str> {
    let rest = did.strip_prefix("did:web:")?;
    let domain = rest.split(':').next().unwrap_or("");
    if domain.is_empty() {
        None
    } else {
        Some(domain)
    }
}

/// Parameters for [`build_hello`]. `nonce` and `issued_at` are caller-supplied so
/// the core stays deterministic; the wrapper SDKs generate them.
#[derive(Debug, Clone, Default)]
pub struct BuildHello {
    pub from_did: String,
    pub proposed_scope: Vec<String>,
    pub nonce: String,
    pub peer_did: Option<String>,
    pub issued_at: String,
}

/// Open the handshake (initiator A): a proposed scope and a fresh nonce, signed.
pub fn build_hello(signer_seed: &[u8], params: &BuildHello) -> Result<Value> {
    let mut hello = Map::new();
    hello.insert("type".into(), json!(HELLO));
    hello.insert("from".into(), json!(params.from_did));
    hello.insert(
        "to".into(),
        match &params.peer_did {
            Some(p) => json!(p),
            None => Value::Null,
        },
    );
    hello.insert("nonce".into(), json!(params.nonce));
    hello.insert("proposedScope".into(), json!(params.proposed_scope));
    hello.insert("issuedAt".into(), json!(params.issued_at));
    let opts = BuildProofOptions::new(format!("{}#key-1", params.from_did), &params.issued_at);
    data_integrity::sign(&Value::Object(hello), signer_seed, &opts)
}

/// Parameters for [`build_accept`].
#[derive(Debug, Clone, Default)]
pub struct BuildAccept {
    pub from_did: String,
    pub offered_scope: Vec<String>,
    pub session_id: String,
    pub valid_until: String,
    pub created: String,
}

/// Verify A's HELLO and identity domain, intersect the scope, and sign an
/// acceptance (responder B). Errors if A is untrusted or the HELLO is invalid.
pub fn build_accept(
    signer_seed: &[u8],
    hello: &Value,
    hello_public_key: &[u8],
    policy: &TrustPolicy,
    params: &BuildAccept,
) -> Result<Value> {
    if hello.get("type").and_then(|v| v.as_str()) != Some(HELLO) {
        return Err(CoreError::Json("not a HELLO message".into()));
    }
    if !data_integrity::verify_proof(hello, hello_public_key)? {
        return Err(CoreError::Json("HELLO signature invalid".into()));
    }
    let initiator = hello.get("from").and_then(|v| v.as_str()).unwrap_or("");
    if !policy.is_trusted(initiator) {
        return Err(CoreError::Json(format!(
            "peer {initiator} is not in this trust domain's policy"
        )));
    }

    let offered: HashSet<&str> = params.offered_scope.iter().map(|s| s.as_str()).collect();
    let empty = Vec::new();
    let proposed = hello
        .get("proposedScope")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);
    let mut seen: HashSet<String> = HashSet::new();
    let mut bounded: Vec<String> = Vec::new();
    for item in proposed {
        if let Some(s) = item.as_str() {
            if offered.contains(s) && seen.insert(s.to_string()) {
                bounded.push(s.to_string());
            }
        }
    }
    bounded.sort();

    let mut accept = Map::new();
    accept.insert("type".into(), json!(ACCEPT));
    accept.insert("from".into(), json!(params.from_did));
    accept.insert("to".into(), json!(initiator));
    accept.insert("sessionId".into(), json!(params.session_id));
    accept.insert(
        "nonce".into(),
        hello.get("nonce").cloned().unwrap_or(Value::Null),
    );
    accept.insert("boundedScope".into(), json!(bounded));
    accept.insert("validUntil".into(), json!(params.valid_until));
    let opts = BuildProofOptions::new(format!("{}#key-1", params.from_did), &params.created);
    data_integrity::sign(&Value::Object(accept), signer_seed, &opts)
}

/// Verify B's ACCEPT (initiator A): signature, nonce echo, and optional responder
/// trust. Returns the bounded session on success.
pub fn verify_accept(
    accept: &Value,
    accept_public_key: &[u8],
    expected_nonce: &str,
    policy: Option<&TrustPolicy>,
) -> Result<Option<BoundedSession>> {
    if accept.get("type").and_then(|v| v.as_str()) != Some(ACCEPT) {
        return Ok(None);
    }
    if !data_integrity::verify_proof(accept, accept_public_key)? {
        return Ok(None);
    }
    if accept.get("nonce").and_then(|v| v.as_str()) != Some(expected_nonce) {
        return Ok(None);
    }
    let responder = accept.get("from").and_then(|v| v.as_str()).unwrap_or("");
    if let Some(p) = policy {
        if !p.is_trusted(responder) {
            return Ok(None);
        }
    }
    let scope = accept
        .get("boundedScope")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    Ok(Some(BoundedSession {
        session_id: accept
            .get("sessionId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        initiator: accept
            .get("to")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        responder: responder.to_string(),
        scope,
        nonce: expected_nonce.to_string(),
        valid_until: accept
            .get("validUntil")
            .and_then(|v| v.as_str())
            .map(String::from),
    }))
}

/// Sign A's confirmation of the bounded session to B.
pub fn build_confirm(
    signer_seed: &[u8],
    from_did: &str,
    session: &BoundedSession,
    created: &str,
) -> Result<Value> {
    let mut confirm = Map::new();
    confirm.insert("type".into(), json!(CONFIRM));
    confirm.insert("from".into(), json!(from_did));
    confirm.insert("to".into(), json!(session.responder));
    confirm.insert("sessionId".into(), json!(session.session_id));
    confirm.insert("nonce".into(), json!(session.nonce));
    confirm.insert("acceptedScope".into(), json!(session.scope));
    let opts = BuildProofOptions::new(format!("{from_did}#key-1"), created);
    data_integrity::sign(&Value::Object(confirm), signer_seed, &opts)
}

/// Verify A's CONFIRM closes the agreed session (responder B): signature plus a
/// matching session id and nonce.
pub fn verify_confirm(
    confirm: &Value,
    confirm_public_key: &[u8],
    session_id: &str,
    expected_nonce: &str,
) -> Result<bool> {
    if confirm.get("type").and_then(|v| v.as_str()) != Some(CONFIRM) {
        return Ok(false);
    }
    if !data_integrity::verify_proof(confirm, confirm_public_key)? {
        return Ok(false);
    }
    let sid = confirm
        .get("sessionId")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let nonce = confirm.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
    Ok(sid == session_id && nonce == expected_nonce)
}

// ---------------------------------------------------------------------------
// Black box and kill switch (Phase 5.5)
// ---------------------------------------------------------------------------

pub const BLACKBOX_VERSION: &str = "1.0";
pub const KILLSWITCH_TYPE: &str = "KillSwitchCredential";
pub const EMERGENCY_STOP: &str = "emergency_stop";

/// The prevHash of the first entry: multibase of 32 zero bytes.
pub fn genesis_prev_hash() -> String {
    mb64(&[0u8; 32])
}

fn entry_hash(body: &Map<String, Value>) -> Result<String> {
    let mut clean = body.clone();
    clean.remove("entryHash");
    let canonical = jcs::canonicalize(&Value::Object(clean));
    Ok(mb64(&Sha256::digest(canonical)))
}

/// Build one black-box entry statelessly: encrypt `payload` under `key`, link it
/// to `prev_hash` at `seq`, and return the entry with its `entryHash`. The
/// stateful [`BlackBoxLog`] and the FFI layer both build on this. The encrypted
/// blob is nonce(12) || ciphertext || tag(16).
pub fn blackbox_append_entry(
    key: &[u8],
    seq: u64,
    event: &str,
    payload: &Value,
    timestamp: &str,
    prev_hash: &str,
) -> Result<Value> {
    if key.len() != 32 {
        return Err(CoreError::Crypto(
            "black box key must be 32 bytes (AES-256)".into(),
        ));
    }
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|e| CoreError::Crypto(format!("rng: {e}")))?;
    let plaintext = jcs::canonicalize(payload);
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| CoreError::Crypto(format!("aes key: {e}")))?;
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|e| CoreError::Crypto(format!("encrypt: {e}")))?;
    let mut blob = Vec::with_capacity(nonce.len() + ct.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);

    let mut body = Map::new();
    body.insert("version".into(), json!(BLACKBOX_VERSION));
    body.insert("seq".into(), json!(seq));
    body.insert("timestamp".into(), json!(timestamp));
    body.insert("event".into(), json!(event));
    body.insert("ciphertext".into(), json!(mb64(&blob)));
    body.insert("prevHash".into(), json!(prev_hash));
    let h = entry_hash(&body)?;
    body.insert("entryHash".into(), json!(h));
    Ok(Value::Object(body))
}

/// An append-only, AES-256-GCM-encrypted, JCS hash-linked event log. The key is
/// 32 bytes. The encrypted blob is nonce(12) || ciphertext || tag(16), matching
/// Python, TypeScript, and Go.
pub struct BlackBoxLog {
    key: Vec<u8>,
    genesis: String,
    entries: Vec<Value>,
    head: String,
}

impl BlackBoxLog {
    /// Build a log. A `None` genesis uses [`genesis_prev_hash`].
    pub fn new(key: &[u8], genesis_prev_hash_override: Option<&str>) -> Result<Self> {
        if key.len() != 32 {
            return Err(CoreError::Crypto(
                "black box key must be 32 bytes (AES-256)".into(),
            ));
        }
        let genesis = genesis_prev_hash_override
            .map(String::from)
            .unwrap_or_else(genesis_prev_hash);
        Ok(Self {
            key: key.to_vec(),
            head: genesis.clone(),
            genesis,
            entries: Vec::new(),
        })
    }

    /// Encrypt `payload`, link it to the chain head, and return the new entry.
    pub fn append(&mut self, event: &str, payload: &Value, timestamp: &str) -> Result<Value> {
        let entry = blackbox_append_entry(
            &self.key,
            self.entries.len() as u64,
            event,
            payload,
            timestamp,
            &self.head,
        )?;
        self.head = entry
            .get("entryHash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        self.entries.push(entry.clone());
        Ok(entry)
    }

    pub fn head(&self) -> &str {
        &self.head
    }

    pub fn genesis(&self) -> &str {
        &self.genesis
    }

    pub fn entries(&self) -> &[Value] {
        &self.entries
    }

    pub fn open(&self, entry: &Value) -> Result<Value> {
        open_entry(entry, &self.key)
    }
}

/// Decrypt a black-box entry payload with the log key.
pub fn open_entry(entry: &Value, key: &[u8]) -> Result<Value> {
    let ct_mb = entry
        .get("ciphertext")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CoreError::Json("entry has no ciphertext".into()))?;
    let blob = unmb64(ct_mb)?;
    if blob.len() < 12 + 16 {
        return Err(CoreError::Crypto("ciphertext too short".into()));
    }
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| CoreError::Crypto(format!("aes key: {e}")))?;
    let (nonce, rest) = blob.split_at(12);
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce), rest)
        .map_err(|_| CoreError::Crypto("decryption failed".into()))?;
    serde_json::from_slice(&pt).map_err(|e| CoreError::Json(format!("payload decode: {e}")))
}

/// The outcome of [`verify_blackbox_chain`].
#[derive(Debug, Clone)]
pub struct ChainResult {
    pub ok: bool,
    pub reason: Option<String>,
}

/// Verify the hash chain over the (still-encrypted) entries. Tamper-evident
/// without the key. A `None` genesis uses [`genesis_prev_hash`].
pub fn verify_blackbox_chain(
    entries: &[Value],
    genesis_prev_hash_override: Option<&str>,
) -> ChainResult {
    let mut prev = genesis_prev_hash_override
        .map(String::from)
        .unwrap_or_else(genesis_prev_hash);
    for (i, entry) in entries.iter().enumerate() {
        if entry.get("seq").and_then(|v| v.as_u64()) != Some(i as u64) {
            return ChainResult {
                ok: false,
                reason: Some(format!("entry {i} seq mismatch")),
            };
        }
        if entry.get("prevHash").and_then(|v| v.as_str()).unwrap_or("") != prev {
            return ChainResult {
                ok: false,
                reason: Some(format!("entry {i} prevHash does not link")),
            };
        }
        let obj = match entry.as_object() {
            Some(o) => o,
            None => {
                return ChainResult {
                    ok: false,
                    reason: Some(format!("entry {i} is not an object")),
                }
            }
        };
        let want = match entry_hash(obj) {
            Ok(w) => w,
            Err(_) => {
                return ChainResult {
                    ok: false,
                    reason: Some(format!("entry {i} hash error")),
                }
            }
        };
        let eh = entry
            .get("entryHash")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if eh != want {
            return ChainResult {
                ok: false,
                reason: Some(format!("entry {i} entryHash mismatch (tampered)")),
            };
        }
        prev = eh.to_string();
    }
    ChainResult {
        ok: true,
        reason: None,
    }
}

/// Parameters for [`build_killswitch_credential`].
#[derive(Debug, Clone, Default)]
pub struct BuildKillswitch {
    pub issuer_did: String,
    pub target: String,
    pub reason: String,
    pub command: Option<String>,
    pub scope: Option<Vec<String>>,
    pub valid_from: String,
    pub valid_until: Option<String>,
}

/// Build a signed `KillSwitchCredential` proving who issued an emergency stop.
pub fn build_killswitch_credential(
    authority_seed: &[u8],
    params: &BuildKillswitch,
) -> Result<Value> {
    let command = params
        .command
        .clone()
        .unwrap_or_else(|| EMERGENCY_STOP.to_string());
    let mut subject = Map::new();
    subject.insert("id".into(), json!(params.target));
    subject.insert("command".into(), json!(command));
    subject.insert("reason".into(), json!(params.reason));
    subject.insert("issuedBy".into(), json!(params.issuer_did));
    if let Some(scope) = &params.scope {
        subject.insert("scope".into(), json!(scope));
    }

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert(
        "type".into(),
        json!(["VerifiableCredential", KILLSWITCH_TYPE]),
    );
    cred.insert("issuer".into(), json!(params.issuer_did));
    cred.insert("validFrom".into(), json!(params.valid_from));
    if let Some(vu) = &params.valid_until {
        cred.insert("validUntil".into(), json!(vu));
    }
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(format!("{}#key-1", params.issuer_did), &params.valid_from);
    data_integrity::sign(&Value::Object(cred), authority_seed, &opts)
}

/// Verify a `KillSwitchCredential`. When `trusted_authorities` is supplied, the
/// issuer DID MUST be in it. Returns the subject on success.
pub fn verify_killswitch_credential(
    credential: &Value,
    public_key: &[u8],
    trusted_authorities: Option<&HashSet<String>>,
) -> Result<Option<Value>> {
    if !has_type(credential.get("type"), KILLSWITCH_TYPE) {
        return Ok(None);
    }
    if !data_integrity::verify_proof(credential, public_key)? {
        return Ok(None);
    }
    if let Some(trusted) = trusted_authorities {
        let issuer = credential
            .get("issuer")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !trusted.contains(issuer) {
            return Ok(None);
        }
    }
    Ok(credential.get("credentialSubject").cloned())
}

// ---------------------------------------------------------------------------
// Halos safety-evidence recorder (NVIDIA Halos integration)
// ---------------------------------------------------------------------------
//
// Byte-exact port of the Python reference `vouch/robotics/halos.py`.
//
// Halos certifies that a robot's stack is functionally safe and secure by design.
// It does not, on its own, produce a verifiable record of what a specific robot
// did or bind that record to the robot's identity. This is the evidence layer
// under a Halos-certified stack: the robot seals its black-box chain head and
// entry count into a signed `HalosSafetyEvidenceCredential` that binds them to its
// identity, to the Halos stack elements it ran on, and to a time window. A
// verifier that holds the credential and the entries confirms, without the
// black-box key, that the record is unaltered, was not truncated or extended since
// it was sealed, and is attributable to that robot. This composes the existing
// black-box and credential primitives and adds no new cryptography.

pub const HALOS_SAFETY_EVIDENCE_TYPE: &str = "HalosSafetyEvidenceCredential";

/// Format Unix epoch seconds as "YYYY-MM-DDTHH:MM:SSZ" for a whole-second UTC
/// instant. Howard Hinnant's civil-from-days algorithm, matching the rest of the
/// core so a `valid_seconds` lifetime renders identically across languages.
fn halos_epoch_to_iso(epoch: i64) -> String {
    let days = epoch.div_euclid(86400);
    let secs = epoch.rem_euclid(86400);
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    let hh = secs / 3600;
    let mm = (secs % 3600) / 60;
    let ss = secs % 60;
    format!("{year:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Parameters for [`build_safety_evidence`]. The robot DID is derived from
/// `signer_seed` (a did:key), mirroring the Python signer. `blackbox_head` and
/// `entry_count` seal the robot's black-box chain; `halos_stack` names the
/// certified configuration; `window` covers the recorded events. Timestamps are
/// caller-supplied ISO-8601 strings.
#[derive(Debug, Clone)]
pub struct BuildSafetyEvidence {
    pub halos_stack: Value,
    pub window_from: String,
    pub window_to: String,
    pub blackbox_head: String,
    pub entry_count: u64,
    pub robot_identity: Option<String>,
    pub valid_seconds: Option<i64>,
    pub valid_from: String,
    pub created: String,
}

/// Seal a robot's Halos safety-event record into a signed
/// `HalosSafetyEvidenceCredential`. The robot signs a credential binding the
/// black-box chain head and entry count to its identity, to the Halos stack
/// elements it ran on, and to the time window.
pub fn build_safety_evidence(signer_seed: &[u8], params: &BuildSafetyEvidence) -> Result<Value> {
    match params.halos_stack.as_object() {
        Some(o) if !o.is_empty() => {}
        _ => return Err(CoreError::Json("halos_stack is required".into())),
    }
    if params.window_from.is_empty() || params.window_to.is_empty() {
        return Err(CoreError::Json(
            "window with 'from' and 'to' is required".into(),
        ));
    }

    let kp = keys::Ed25519KeyPair::from_seed_slice(signer_seed)?;
    let robot_did = keys::ed25519_to_did_key(&kp.public_key())?;

    let mut subject = Map::new();
    subject.insert("id".into(), json!(robot_did));
    subject.insert("blackboxHead".into(), json!(params.blackbox_head));
    subject.insert("entryCount".into(), json!(params.entry_count));
    subject.insert("halosStack".into(), params.halos_stack.clone());
    subject.insert(
        "window".into(),
        json!({ "from": params.window_from, "to": params.window_to }),
    );
    if let Some(robot_identity) = &params.robot_identity {
        subject.insert("robotIdentity".into(), json!(robot_identity));
    }

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert(
        "type".into(),
        json!(["VerifiableCredential", HALOS_SAFETY_EVIDENCE_TYPE]),
    );
    cred.insert("issuer".into(), json!(robot_did));
    cred.insert("validFrom".into(), json!(params.valid_from));
    if let Some(valid_seconds) = params.valid_seconds {
        let from = crate::time::iso_to_epoch_seconds(&params.valid_from)?;
        cred.insert(
            "validUntil".into(),
            json!(halos_epoch_to_iso(from + valid_seconds)),
        );
    }
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(format!("{robot_did}#key-1"), &params.created);
    data_integrity::sign(&Value::Object(cred), signer_seed, &opts)
}

/// Verify a `HalosSafetyEvidenceCredential`: the robot's proof and that the issuer
/// is the robot (`credentialSubject.id`). When `entries` is supplied, also checks
/// that the black-box chain is intact, that its length matches the sealed entry
/// count, and that its head matches the sealed head, so a truncated, extended,
/// reordered, or tampered record is rejected. Returns `(ok, credentialSubject)`.
pub fn verify_safety_evidence(
    credential: &Value,
    robot_public_key: &[u8],
    entries: Option<&[Value]>,
) -> Result<(bool, Option<Value>)> {
    if !has_type(credential.get("type"), HALOS_SAFETY_EVIDENCE_TYPE) {
        return Ok((false, None));
    }
    if !data_integrity::verify_proof(credential, robot_public_key)? {
        return Ok((false, None));
    }

    let subject = match credential.get("credentialSubject") {
        Some(s) if s.is_object() => s.clone(),
        _ => return Ok((false, None)),
    };
    let subject_id = subject.get("id").and_then(|v| v.as_str());
    if subject_id.is_none() || subject_id != credential.get("issuer").and_then(|v| v.as_str()) {
        return Ok((false, None));
    }

    if let Some(entries) = entries {
        if !verify_blackbox_chain(entries, None).ok {
            return Ok((false, None));
        }
        if subject.get("entryCount").and_then(|v| v.as_u64()) != Some(entries.len() as u64) {
            return Ok((false, None));
        }
        let head = match entries.last() {
            Some(last) => last
                .get("entryHash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            None => genesis_prev_hash(),
        };
        if Some(head.as_str()) != subject.get("blackboxHead").and_then(|v| v.as_str()) {
            return Ok((false, None));
        }
    }

    Ok((true, Some(subject)))
}

// ---------------------------------------------------------------------------
// Scannable robot passport (Phase 5.6)
// ---------------------------------------------------------------------------

pub const ROBOT_PASSPORT_TYPE: &str = "RobotPassport";
pub const PASSPORT_URI_SCHEME: &str = "vouch-passport:";
pub const STATUS_ACTIVE: &str = "active";
pub const STATUS_SUSPENDED: &str = "suspended";
pub const STATUS_DECOMMISSIONED: &str = "decommissioned";

/// Parameters for [`build_passport`]. The issuer is the signer (the robot or an
/// authority); `robot_did` is the robot the passport describes.
#[derive(Debug, Clone, Default)]
pub struct BuildPassport {
    pub issuer_did: String,
    pub robot_did: String,
    pub make: String,
    pub model: String,
    pub owner: String,
    pub authorized_actions: Vec<String>,
    pub certification: Option<String>,
    pub status: Option<String>,
    pub valid_from: String,
    pub valid_until: Option<String>,
}

/// Build a signed `RobotPassport` credential.
pub fn build_passport(signer_seed: &[u8], params: &BuildPassport) -> Result<Value> {
    let status = params
        .status
        .clone()
        .unwrap_or_else(|| STATUS_ACTIVE.to_string());
    let mut subject = Map::new();
    subject.insert("id".into(), json!(params.robot_did));
    subject.insert("make".into(), json!(params.make));
    subject.insert("model".into(), json!(params.model));
    subject.insert("owner".into(), json!(params.owner));
    subject.insert("authorizedActions".into(), json!(params.authorized_actions));
    subject.insert("status".into(), json!(status));
    if let Some(c) = &params.certification {
        subject.insert("certification".into(), json!(c));
    }

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert(
        "type".into(),
        json!(["VerifiableCredential", ROBOT_PASSPORT_TYPE]),
    );
    cred.insert("issuer".into(), json!(params.issuer_did));
    cred.insert("validFrom".into(), json!(params.valid_from));
    if let Some(vu) = &params.valid_until {
        cred.insert("validUntil".into(), json!(vu));
    }
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(format!("{}#key-1", params.issuer_did), &params.valid_from);
    data_integrity::sign(&Value::Object(cred), signer_seed, &opts)
}

/// Encode a passport into a compact `vouch-passport:` URI for a QR or NFC tag.
pub fn encode_passport(passport: &Value) -> String {
    format!(
        "{}{}",
        PASSPORT_URI_SCHEME,
        mb64(&jcs::canonicalize(passport))
    )
}

/// Decode a `vouch-passport:` URI back into the passport credential.
pub fn decode_passport(uri: &str) -> Result<Value> {
    let body = uri
        .strip_prefix(PASSPORT_URI_SCHEME)
        .ok_or_else(|| CoreError::Json(format!("not a {PASSPORT_URI_SCHEME} URI")))?;
    let raw = unmb64(body)?;
    serde_json::from_slice(&raw).map_err(|e| CoreError::Json(format!("passport decode: {e}")))
}

/// Verify a passport credential. A suspended or decommissioned status still
/// verifies but is surfaced in the subject so a scanner can refuse; an expired
/// passport fails. `now_iso` is the verifier's clock. Returns the subject.
pub fn verify_passport(
    passport: &Value,
    public_key: &[u8],
    now_iso: &str,
) -> Result<Option<Value>> {
    if !has_type(passport.get("type"), ROBOT_PASSPORT_TYPE) {
        return Ok(None);
    }
    if !data_integrity::verify_proof(passport, public_key)? {
        return Ok(None);
    }
    if let Some(vu) = passport.get("validUntil").and_then(|v| v.as_str()) {
        if let (Ok(vu_e), Ok(now_e)) = (
            crate::time::iso_to_epoch_seconds(vu),
            crate::time::iso_to_epoch_seconds(now_iso),
        ) {
            if now_e > vu_e {
                return Ok(None);
            }
        }
    }
    Ok(passport.get("credentialSubject").cloned())
}

/// Decode a `vouch-passport:` URI and verify it. Returns `None` on a malformed URI.
pub fn verify_passport_uri(uri: &str, public_key: &[u8], now_iso: &str) -> Result<Option<Value>> {
    match decode_passport(uri) {
        Ok(p) => verify_passport(&p, public_key, now_iso),
        Err(_) => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Liveness heartbeat with safety-envelope conformance (Phase 5.7)
// ---------------------------------------------------------------------------

pub const ROBOT_HEARTBEAT_TYPE: &str = "RobotHeartbeatCredential";

/// Default number of missed intervals tolerated before trust is considered stale.
pub const DEFAULT_GRACE_INTERVALS: i64 = 2;

/// One observed motion sample. `None` numerics mean "not specified" (a meaningful
/// zero is still `Some(0.0)`), matching [`PhysicalAction`].
#[derive(Debug, Clone, Default)]
pub struct MotionSample {
    pub force_n: Option<f64>,
    pub speed_mps: Option<f64>,
    pub near_humans: bool,
    pub zone: Option<String>,
    pub time_hm: Option<String>,
}

/// Collector for per-interval motion telemetry. It accumulates aggregates of what
/// the robot physically did over a heartbeat interval and, when given a physical
/// scope, counts how many samples fell outside the declared envelope. The
/// physical analogue of the agent behavioral digest.
///
/// With `scope` set to `None` the digest still reports observed maxima but cannot
/// judge conformance, so it reports `withinEnvelope` true with a zero breach
/// count, mirroring the Python `MotionCollector`.
#[derive(Debug, Clone, Default)]
pub struct MotionCollector {
    scope: Option<Value>,
    samples: u64,
    max_force: f64,
    max_speed: f64,
    max_speed_near: f64,
    zone_breaches: u64,
    breaches: u64,
}

impl MotionCollector {
    /// A collector that judges samples against `scope` (the
    /// `credentialSubject.physicalScope` object). Pass `None` to only aggregate.
    pub fn new(scope: Option<Value>) -> Self {
        Self {
            scope,
            ..Default::default()
        }
    }

    /// Record a single observed motion sample, updating the running aggregates and
    /// (when a scope is set) the breach counts.
    pub fn record(&mut self, sample: &MotionSample) -> Result<()> {
        if let Some(f) = sample.force_n {
            if f < 0.0 {
                return Err(CoreError::Json(format!(
                    "force_n must be non-negative, got {f}"
                )));
            }
        }
        if let Some(s) = sample.speed_mps {
            if s < 0.0 {
                return Err(CoreError::Json(format!(
                    "speed_mps must be non-negative, got {s}"
                )));
            }
        }

        self.samples += 1;
        if let Some(f) = sample.force_n {
            self.max_force = self.max_force.max(f);
        }
        if let Some(s) = sample.speed_mps {
            self.max_speed = self.max_speed.max(s);
            if sample.near_humans {
                self.max_speed_near = self.max_speed_near.max(s);
            }
        }

        if let Some(scope) = &self.scope {
            let action = PhysicalAction {
                force_n: sample.force_n,
                speed_mps: sample.speed_mps,
                near_humans: sample.near_humans,
                zone: sample.zone.clone(),
                time_hm: sample.time_hm.clone(),
            };
            let result = check_physical_action(scope, &action);
            if !result.ok {
                self.breaches += 1;
                if result
                    .reasons
                    .iter()
                    .any(|r| r.starts_with("zone_not_allowed"))
                {
                    self.zone_breaches += 1;
                }
            }
        }
        Ok(())
    }

    /// Return the `motionDigest` object for embedding in a heartbeat credential.
    pub fn digest(&self) -> Value {
        json!({
            "samples": self.samples,
            "maxForceN": self.max_force,
            "maxSpeedMps": self.max_speed,
            "maxSpeedNearHumansMps": self.max_speed_near,
            "zoneBreaches": self.zone_breaches,
            "breachCount": self.breaches,
            "withinEnvelope": self.breaches == 0,
        })
    }

    /// Clear all state. Call after submitting a heartbeat to start fresh.
    pub fn reset(&mut self) {
        self.samples = 0;
        self.max_force = 0.0;
        self.max_speed = 0.0;
        self.max_speed_near = 0.0;
        self.zone_breaches = 0;
        self.breaches = 0;
    }
}

fn digest_non_negative_int(digest: &Map<String, Value>, name: &str) -> Result<()> {
    match digest.get(name) {
        Some(v) if v.is_u64() => Ok(()),
        Some(Value::Number(n)) if n.as_i64().map(|i| i >= 0).unwrap_or(false) => Ok(()),
        Some(_) => Err(CoreError::Json(format!(
            "motionDigest.{name} must be a non-negative integer"
        ))),
        None => Err(CoreError::Json(format!("motionDigest.{name} is required"))),
    }
}

/// Structural validation of a `motionDigest` object. Does not judge whether the
/// values are acceptable; that is policy, expressed through [`is_live`].
pub fn validate_motion_digest(digest: &Value) -> Result<()> {
    let obj = digest
        .as_object()
        .ok_or_else(|| CoreError::Json("motionDigest must be an object".into()))?;

    for name in ["samples", "zoneBreaches", "breachCount"] {
        digest_non_negative_int(obj, name)?;
    }
    for name in ["maxForceN", "maxSpeedMps", "maxSpeedNearHumansMps"] {
        match obj.get(name) {
            Some(Value::Bool(_)) | None => {
                return Err(CoreError::Json(format!("motionDigest.{name} is required")))
            }
            Some(v) => {
                let n = v.as_f64().ok_or_else(|| {
                    CoreError::Json(format!("motionDigest.{name} must be a number"))
                })?;
                if n < 0.0 {
                    return Err(CoreError::Json(format!(
                        "motionDigest.{name} must be non-negative"
                    )));
                }
            }
        }
    }
    match obj.get("withinEnvelope") {
        Some(Value::Bool(_)) => Ok(()),
        Some(_) => Err(CoreError::Json(
            "motionDigest.withinEnvelope must be a boolean".into(),
        )),
        None => Err(CoreError::Json(
            "motionDigest.withinEnvelope is required".into(),
        )),
    }
}

/// Parameters for [`build_robot_heartbeat`]. The robot self-issues the credential
/// with its own Ed25519 seed; `motion_digest` is produced by a [`MotionCollector`]
/// over the interval and `interval_seconds` is the declared heartbeat cadence.
#[derive(Debug, Clone)]
pub struct BuildRobotHeartbeat {
    pub robot_did: String,
    pub session_id: String,
    pub interval_index: i64,
    pub interval_seconds: i64,
    pub motion_digest: Value,
    pub valid_from: String,
}

/// Build a signed `RobotHeartbeatCredential`.
pub fn build_robot_heartbeat(robot_seed: &[u8], params: &BuildRobotHeartbeat) -> Result<Value> {
    if params.interval_index < 0 {
        return Err(CoreError::Json(
            "interval_index must be non-negative".into(),
        ));
    }
    if params.interval_seconds <= 0 {
        return Err(CoreError::Json("interval_seconds must be positive".into()));
    }
    validate_motion_digest(&params.motion_digest)?;

    let mut subject = Map::new();
    subject.insert("id".into(), json!(params.robot_did));
    subject.insert("sessionId".into(), json!(params.session_id));
    subject.insert("intervalIndex".into(), json!(params.interval_index));
    subject.insert("intervalSeconds".into(), json!(params.interval_seconds));
    subject.insert("motionDigest".into(), params.motion_digest.clone());

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert(
        "type".into(),
        json!(["VerifiableCredential", ROBOT_HEARTBEAT_TYPE]),
    );
    cred.insert("issuer".into(), json!(params.robot_did));
    cred.insert("validFrom".into(), json!(params.valid_from));
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(format!("{}#key-1", params.robot_did), &params.valid_from);
    data_integrity::sign(&Value::Object(cred), robot_seed, &opts)
}

/// Verify a `RobotHeartbeatCredential`: the credential proof (robot key) and the
/// structural validity of the embedded motion digest. Returns the subject on
/// success. Whether the robot is currently trusted is a separate, time-dependent
/// question answered by [`is_live`].
pub fn verify_robot_heartbeat(
    credential: &Value,
    robot_public_key: &[u8],
) -> Result<Option<Value>> {
    if !has_type(credential.get("type"), ROBOT_HEARTBEAT_TYPE) {
        return Ok(None);
    }
    if !data_integrity::verify_proof(credential, robot_public_key)? {
        return Ok(None);
    }
    let subject = match credential.get("credentialSubject") {
        Some(s) if s.is_object() => s,
        _ => return Ok(None),
    };
    let digest = subject.get("motionDigest").cloned().unwrap_or(Value::Null);
    if validate_motion_digest(&digest).is_err() {
        return Ok(None);
    }
    Ok(Some(subject.clone()))
}

/// Decide whether a robot is currently trusted, given its most recent heartbeat.
/// A robot is live only if BOTH hold: the digest reports `withinEnvelope` true,
/// and the heartbeat was issued within `grace_intervals` cadence periods of
/// `now_iso`. `interval_seconds` (when `Some`) overrides the heartbeat's
/// self-declared cadence.
pub fn is_live(
    credential: &Value,
    now_iso: &str,
    interval_seconds: Option<i64>,
    grace_intervals: i64,
) -> Result<bool> {
    let subject = credential
        .get("credentialSubject")
        .and_then(|s| s.as_object());
    let digest = subject
        .and_then(|s| s.get("motionDigest"))
        .and_then(|d| d.as_object());
    let within = digest
        .and_then(|d| d.get("withinEnvelope"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !within {
        return Ok(false);
    }

    let cadence = match interval_seconds {
        Some(c) => c,
        None => subject
            .and_then(|s| s.get("intervalSeconds"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0),
    };
    if cadence <= 0 {
        return Ok(false);
    }
    if grace_intervals < 1 {
        return Err(CoreError::Json("grace_intervals must be at least 1".into()));
    }

    let raw = match credential.get("validFrom").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s,
        _ => return Ok(false),
    };
    let issued = match crate::time::iso_to_epoch_seconds(raw) {
        Ok(t) => t,
        Err(_) => return Ok(false),
    };
    let moment = match crate::time::iso_to_epoch_seconds(now_iso) {
        Ok(t) => t,
        Err(_) => return Ok(false),
    };
    let deadline = issued + cadence * grace_intervals;
    // A heartbeat from the future (clock skew beyond one cadence) is not trusted.
    if moment + cadence < issued {
        return Ok(false);
    }
    Ok(moment <= deadline)
}

// ---------------------------------------------------------------------------
// Per-credential revocation (Phase 5.8)
// ---------------------------------------------------------------------------

pub use crate::status_list::{BITSTRING_STATUS_LIST_ENTRY_TYPE, STATUS_PURPOSE_REVOCATION};

/// Build a BitstringStatusList `credentialStatus` entry referencing a bit index in
/// a published status list credential. Mirrors the agent-side
/// `status_list.build_status_list_entry`. `entry_id`, when `None`, defaults to
/// `{status_list_credential}#{status_list_index}`.
pub fn build_status_list_entry(
    status_list_credential: &str,
    status_list_index: i64,
    status_purpose: &str,
    entry_id: Option<&str>,
) -> Result<Value> {
    if !matches!(status_purpose, "revocation" | "suspension" | "message") {
        return Err(CoreError::Json(format!(
            "status_purpose must be one of revocation, suspension, message, got {status_purpose:?}"
        )));
    }
    if status_list_index < 0 {
        return Err(CoreError::Json(
            "status_list_index must be non-negative".into(),
        ));
    }
    if status_list_credential.is_empty() {
        return Err(CoreError::Json(
            "status_list_credential URL is required".into(),
        ));
    }
    let id = entry_id
        .map(String::from)
        .unwrap_or_else(|| format!("{status_list_credential}#{status_list_index}"));
    Ok(json!({
        "id": id,
        "type": BITSTRING_STATUS_LIST_ENTRY_TYPE,
        "statusPurpose": status_purpose,
        "statusListIndex": status_list_index.to_string(),
        "statusListCredential": status_list_credential,
    }))
}

/// Parameters for [`attach_credential_status`].
#[derive(Debug, Clone)]
pub struct AttachCredentialStatus {
    pub status_list_credential: String,
    pub status_list_index: i64,
    pub status_purpose: String,
    pub entry_id: Option<String>,
    /// `validFrom`-style timestamp used as the proof `created` when re-signing.
    pub created: String,
}

/// Add a BitstringStatusList `credentialStatus` entry to a robot credential and
/// re-sign it under `signer_seed`, so the proof covers the status binding. If the
/// credential already carries a `credentialStatus`, the new entry is appended (the
/// field becomes a list), matching the Verifiable Credentials data model. Any
/// pre-existing proof is replaced.
pub fn attach_credential_status(
    credential: &Value,
    signer_seed: &[u8],
    params: &AttachCredentialStatus,
) -> Result<Value> {
    let entry = build_status_list_entry(
        &params.status_list_credential,
        params.status_list_index,
        &params.status_purpose,
        params.entry_id.as_deref(),
    )?;

    let mut obj = credential
        .as_object()
        .ok_or_else(|| CoreError::Json("credential must be a JSON object".into()))?
        .clone();

    match obj.get("credentialStatus").cloned() {
        None => {
            obj.insert("credentialStatus".into(), entry);
        }
        Some(Value::Array(mut existing)) => {
            existing.push(entry);
            obj.insert("credentialStatus".into(), Value::Array(existing));
        }
        Some(existing) => {
            obj.insert("credentialStatus".into(), json!([existing, entry]));
        }
    }

    // Re-sign: the proof must cover the credentialStatus we just added.
    obj.remove("proof");
    let issuer = obj.get("issuer").and_then(|v| v.as_str()).unwrap_or("");
    let opts = BuildProofOptions::new(format!("{issuer}#key-1"), &params.created);
    data_integrity::sign(&Value::Object(obj), signer_seed, &opts)
}

fn status_entries(credential: &Value) -> Result<Vec<Value>> {
    match credential.get("credentialStatus") {
        None => Ok(Vec::new()),
        Some(Value::Array(a)) => Ok(a.iter().filter(|e| e.is_object()).cloned().collect()),
        Some(v) if v.is_object() => Ok(vec![v.clone()]),
        Some(_) => Err(CoreError::Json(
            "credentialStatus must be an object or a list of objects".into(),
        )),
    }
}

/// Return true if the robot credential's status bit for `status_purpose` is set
/// (for example, the credential has been revoked) in the supplied status list. The
/// caller MUST verify the Data Integrity proof on `status_list_credential` first.
/// Returns false when the credential carries no matching status entry.
pub fn check_credential_status(
    credential: &Value,
    status_list_credential: &Value,
    status_purpose: &str,
) -> Result<bool> {
    let referenced_id = status_list_credential.get("id").and_then(|v| v.as_str());
    for entry in status_entries(credential)? {
        if entry.get("statusPurpose").and_then(|v| v.as_str()) != Some(status_purpose) {
            continue;
        }
        if entry.get("statusListCredential").and_then(|v| v.as_str()) != referenced_id {
            continue;
        }
        return crate::status_list::verify_status(&entry, status_list_credential);
    }
    Ok(false)
}

// ---------------------------------------------------------------------------
// Accountable safety record (Phase 5.9)
// ---------------------------------------------------------------------------

pub const SAFETY_RECORD_TYPE: &str = "RobotSafetyRecordCredential";
pub const SAFETY_LOG_VERSION: &str = "1.0";

/// Standard safety event types: the interoperable set a verifier and an insurer
/// can rely on. Implementers MAY use additional types.
pub const EVENT_TYPES: [&str; 6] = [
    "incident",
    "near_miss",
    "manual_override",
    "kill_switch",
    "envelope_breach",
    "maintenance",
];

/// Severity bands, ordered from least to most serious.
pub const SEVERITIES: [&str; 5] = ["info", "low", "medium", "high", "critical"];

/// Append-only, plaintext, hash-linked safety event ledger. Reuses the black-box
/// chain semantics ([`entry_hash`], [`genesis_prev_hash`]) so the two logs verify
/// the same way, but entries are plaintext: a safety record is meant to be read
/// and trusted by third parties.
pub struct SafetyEventLog {
    genesis: String,
    entries: Vec<Value>,
    head: String,
}

impl SafetyEventLog {
    /// Build a log. A `None` genesis uses [`genesis_prev_hash`].
    pub fn new(genesis_prev_hash_override: Option<&str>) -> Self {
        let genesis = genesis_prev_hash_override
            .map(String::from)
            .unwrap_or_else(genesis_prev_hash);
        Self {
            head: genesis.clone(),
            genesis,
            entries: Vec::new(),
        }
    }

    /// Append one safety event, link it to the chain head, and return the entry.
    pub fn append(
        &mut self,
        event_type: &str,
        severity: &str,
        details: Option<&Value>,
        actor: Option<&str>,
        timestamp: &str,
    ) -> Result<Value> {
        if !EVENT_TYPES.contains(&event_type) {
            return Err(CoreError::Json(format!(
                "event_type must be one of {EVENT_TYPES:?}, got {event_type:?}"
            )));
        }
        if !SEVERITIES.contains(&severity) {
            return Err(CoreError::Json(format!(
                "severity must be one of {SEVERITIES:?}, got {severity:?}"
            )));
        }

        let mut body = Map::new();
        body.insert("version".into(), json!(SAFETY_LOG_VERSION));
        body.insert("seq".into(), json!(self.entries.len() as u64));
        body.insert("timestamp".into(), json!(timestamp));
        body.insert("eventType".into(), json!(event_type));
        body.insert("severity".into(), json!(severity));
        body.insert("prevHash".into(), json!(self.head));
        if let Some(d) = details {
            body.insert("details".into(), d.clone());
        }
        if let Some(a) = actor {
            body.insert("actor".into(), json!(a));
        }
        let h = entry_hash(&body)?;
        body.insert("entryHash".into(), json!(h));
        self.head = h;
        let entry = Value::Object(body);
        self.entries.push(entry.clone());
        Ok(entry)
    }

    pub fn head(&self) -> &str {
        &self.head
    }

    pub fn genesis(&self) -> &str {
        &self.genesis
    }

    pub fn entries(&self) -> &[Value] {
        &self.entries
    }

    /// Produce a summary object for embedding in a safety-record credential.
    pub fn summarize(&self) -> Value {
        summarize_entries(&self.entries, Some(&self.head))
    }
}

/// Verify the hash chain over the ledger entries. Tamper-evident. Shares the
/// black-box chain verifier so the two logs verify identically.
pub fn verify_safety_log(
    entries: &[Value],
    genesis_prev_hash_override: Option<&str>,
) -> ChainResult {
    verify_blackbox_chain(entries, genesis_prev_hash_override)
}

/// Summarize ledger entries into counts by event type (sorted) and by severity
/// (info..critical), the total event count, and (when supplied) the ledger head
/// hash that anchors the summary to a specific chain state.
pub fn summarize_entries(entries: &[Value], head: Option<&str>) -> Value {
    let mut sorted_types: Vec<&str> = EVENT_TYPES.to_vec();
    sorted_types.sort_unstable();

    let mut event_counts = Map::new();
    for t in &sorted_types {
        event_counts.insert((*t).to_string(), json!(0));
    }
    let mut severity_counts = Map::new();
    for s in SEVERITIES {
        severity_counts.insert(s.to_string(), json!(0));
    }

    for e in entries {
        if let Some(et) = e.get("eventType").and_then(|v| v.as_str()) {
            if let Some(c) = event_counts.get_mut(et).and_then(|v| v.as_u64()) {
                event_counts.insert(et.to_string(), json!(c + 1));
            }
        }
        if let Some(sv) = e.get("severity").and_then(|v| v.as_str()) {
            if let Some(c) = severity_counts.get_mut(sv).and_then(|v| v.as_u64()) {
                severity_counts.insert(sv.to_string(), json!(c + 1));
            }
        }
    }

    let mut summary = Map::new();
    summary.insert("eventCounts".into(), Value::Object(event_counts));
    summary.insert("severityCounts".into(), Value::Object(severity_counts));
    summary.insert("totalEvents".into(), json!(entries.len() as u64));
    if let Some(h) = head {
        summary.insert("logHead".into(), json!(h));
    }
    Value::Object(summary)
}

/// Structural validation of a safety summary.
pub fn validate_safety_summary(summary: &Value) -> Result<()> {
    let obj = summary
        .as_object()
        .ok_or_else(|| CoreError::Json("summary must be an object".into()))?;
    for name in ["eventCounts", "severityCounts"] {
        let block = obj
            .get(name)
            .and_then(|v| v.as_object())
            .ok_or_else(|| CoreError::Json(format!("summary.{name} must be an object")))?;
        for (k, v) in block {
            let ok = v.is_u64() || v.as_i64().map(|i| i >= 0).unwrap_or(false);
            if v.is_boolean() || !ok {
                return Err(CoreError::Json(format!(
                    "summary.{name}[{k:?}] must be a non-negative integer"
                )));
            }
        }
    }
    let total_ok = obj
        .get("totalEvents")
        .map(|v| (v.is_u64() || v.as_i64().map(|i| i >= 0).unwrap_or(false)) && !v.is_boolean())
        .unwrap_or(false);
    if !total_ok {
        return Err(CoreError::Json(
            "summary.totalEvents must be a non-negative integer".into(),
        ));
    }
    Ok(())
}

/// Parameters for [`build_safety_record`]. The issuer (an owner, an auditor, or
/// the robot itself) attests `summary`, produced by [`SafetyEventLog::summarize`]
/// or [`summarize_entries`].
#[derive(Debug, Clone)]
pub struct BuildSafetyRecord {
    pub issuer_did: String,
    pub robot_did: String,
    pub summary: Value,
    pub period_start: Option<String>,
    pub period_end: Option<String>,
    pub valid_from: String,
    pub valid_until: Option<String>,
}

/// Build a signed `RobotSafetyRecordCredential` summarizing a robot's safety
/// ledger.
pub fn build_safety_record(signer_seed: &[u8], params: &BuildSafetyRecord) -> Result<Value> {
    validate_safety_summary(&params.summary)?;

    let mut subject = Map::new();
    subject.insert("id".into(), json!(params.robot_did));
    if let Some(s) = params.summary.as_object() {
        for (k, v) in s {
            subject.insert(k.clone(), v.clone());
        }
    }
    if params.period_start.is_some() || params.period_end.is_some() {
        let mut period = Map::new();
        if let Some(start) = &params.period_start {
            period.insert("start".into(), json!(start));
        }
        if let Some(end) = &params.period_end {
            period.insert("end".into(), json!(end));
        }
        subject.insert("period".into(), Value::Object(period));
    }

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert(
        "type".into(),
        json!(["VerifiableCredential", SAFETY_RECORD_TYPE]),
    );
    cred.insert("issuer".into(), json!(params.issuer_did));
    cred.insert("validFrom".into(), json!(params.valid_from));
    if let Some(vu) = &params.valid_until {
        cred.insert("validUntil".into(), json!(vu));
    }
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(format!("{}#key-1", params.issuer_did), &params.valid_from);
    data_integrity::sign(&Value::Object(cred), signer_seed, &opts)
}

/// Verify a `RobotSafetyRecordCredential`: the issuer's proof and the structural
/// validity of the embedded summary. Returns the credentialSubject on success.
pub fn verify_safety_record(credential: &Value, public_key: &[u8]) -> Result<Option<Value>> {
    if !has_type(credential.get("type"), SAFETY_RECORD_TYPE) {
        return Ok(None);
    }
    if !data_integrity::verify_proof(credential, public_key)? {
        return Ok(None);
    }
    let subject = match credential.get("credentialSubject") {
        Some(s) if s.is_object() => s,
        _ => return Ok(None),
    };
    if validate_safety_summary(subject).is_err() {
        return Ok(None);
    }
    Ok(Some(subject.clone()))
}

// ---------------------------------------------------------------------------
// Perception provenance (Phase 5.10)
// ---------------------------------------------------------------------------

pub const PERCEPTION_TYPE: &str = "PerceptionProvenanceCredential";
pub const PERCEPTION_LOG_VERSION: &str = "1.0";

/// Standard sensor modalities: the interoperable set a verifier can rely on.
/// Implementers MAY use additional values.
pub const MODALITIES: [&str; 6] = ["camera", "lidar", "radar", "depth", "audio", "thermal"];

/// Multibase (base64url) SHA-256 of a raw sensor frame. Only the hash travels in
/// the log and the attestation; the frame stays wherever the deployment keeps it.
pub fn hash_frame(frame: &[u8]) -> String {
    mb64(&Sha256::digest(frame))
}

/// Append-only, plaintext, hash-linked log of sensor-frame provenance records.
/// Reuses the black-box chain semantics ([`entry_hash`], [`genesis_prev_hash`]),
/// so a perception log verifies the same way as the safety ledger. Each entry
/// binds a sequence number, a timestamp, the sensor id, the modality, the frame
/// hash, and the hash of the previous entry; the frames are not stored.
pub struct PerceptionLog {
    genesis: String,
    entries: Vec<Value>,
    head: String,
}

impl PerceptionLog {
    /// Build a log. A `None` genesis uses [`genesis_prev_hash`].
    pub fn new(genesis_prev_hash_override: Option<&str>) -> Self {
        let genesis = genesis_prev_hash_override
            .map(String::from)
            .unwrap_or_else(genesis_prev_hash);
        Self {
            head: genesis.clone(),
            genesis,
            entries: Vec::new(),
        }
    }

    /// Append one frame-provenance record, link it to the chain head, and return
    /// the entry. Provide either the raw `frame` (it is hashed) or a precomputed
    /// `frame_hash`, not both.
    pub fn record(
        &mut self,
        sensor_id: &str,
        modality: &str,
        frame: Option<&[u8]>,
        frame_hash: Option<&str>,
        timestamp: &str,
    ) -> Result<Value> {
        if !MODALITIES.contains(&modality) {
            return Err(CoreError::Json(format!(
                "modality must be one of {MODALITIES:?}, got {modality:?}"
            )));
        }
        if sensor_id.is_empty() {
            return Err(CoreError::Json("sensor_id is required".into()));
        }
        if frame.is_some() && frame_hash.is_some() {
            return Err(CoreError::Json(
                "provide either frame or frame_hash, not both".into(),
            ));
        }
        let resolved = match (frame, frame_hash) {
            (Some(f), None) => hash_frame(f),
            (None, Some(h)) if !h.is_empty() => h.to_string(),
            _ => return Err(CoreError::Json("frame or frame_hash is required".into())),
        };

        let mut body = Map::new();
        body.insert("version".into(), json!(PERCEPTION_LOG_VERSION));
        body.insert("seq".into(), json!(self.entries.len() as u64));
        body.insert("timestamp".into(), json!(timestamp));
        body.insert("sensorId".into(), json!(sensor_id));
        body.insert("modality".into(), json!(modality));
        body.insert("frameHash".into(), json!(resolved));
        body.insert("prevHash".into(), json!(self.head));
        let h = entry_hash(&body)?;
        body.insert("entryHash".into(), json!(h));
        self.head = h;
        let entry = Value::Object(body);
        self.entries.push(entry.clone());
        Ok(entry)
    }

    pub fn head(&self) -> &str {
        &self.head
    }

    pub fn genesis(&self) -> &str {
        &self.genesis
    }

    pub fn entries(&self) -> &[Value] {
        &self.entries
    }
}

/// Verify the hash chain over the perception log entries. Tamper-evident. Shares
/// the black-box chain verifier so every hash-linked log verifies identically.
pub fn verify_perception_log(
    entries: &[Value],
    genesis_prev_hash_override: Option<&str>,
) -> ChainResult {
    verify_blackbox_chain(entries, genesis_prev_hash_override)
}

/// Parameters for [`build_perception_attestation`]. The robot self-issues the
/// credential with its own Ed25519 seed. `captured_at`, when `None`, defaults to
/// `valid_from`. When `log_head` is supplied, the attestation also anchors the
/// segment of frames up to that chain head.
#[derive(Debug, Clone)]
pub struct BuildPerception {
    pub robot_did: String,
    pub sensor_id: String,
    pub modality: String,
    pub frame_hash: String,
    pub captured_at: Option<String>,
    pub log_head: Option<String>,
    pub valid_from: String,
    pub valid_until: Option<String>,
}

/// Build a signed `PerceptionProvenanceCredential` attesting that a robot's sensor
/// captured a specific frame. Software frame-hash signing: the robot signs the
/// provenance of the captured frame with its own key.
pub fn build_perception_attestation(robot_seed: &[u8], params: &BuildPerception) -> Result<Value> {
    if !MODALITIES.contains(&params.modality.as_str()) {
        return Err(CoreError::Json(format!(
            "modality must be one of {MODALITIES:?}, got {:?}",
            params.modality
        )));
    }
    if params.frame_hash.is_empty() {
        return Err(CoreError::Json("frame_hash is required".into()));
    }

    let captured = params
        .captured_at
        .clone()
        .unwrap_or_else(|| params.valid_from.clone());

    let mut subject = Map::new();
    subject.insert("id".into(), json!(params.robot_did));
    subject.insert("sensorId".into(), json!(params.sensor_id));
    subject.insert("modality".into(), json!(params.modality));
    subject.insert("frameHash".into(), json!(params.frame_hash));
    subject.insert("capturedAt".into(), json!(captured));
    if let Some(head) = &params.log_head {
        subject.insert("logHead".into(), json!(head));
    }

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert(
        "type".into(),
        json!(["VerifiableCredential", PERCEPTION_TYPE]),
    );
    cred.insert("issuer".into(), json!(params.robot_did));
    cred.insert("validFrom".into(), json!(params.valid_from));
    if let Some(vu) = &params.valid_until {
        cred.insert("validUntil".into(), json!(vu));
    }
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(format!("{}#key-1", params.robot_did), &params.valid_from);
    data_integrity::sign(&Value::Object(cred), robot_seed, &opts)
}

/// Verify a `PerceptionProvenanceCredential`: the robot's proof and, when the raw
/// `frame` is supplied, that its hash reproduces the attested `frameHash`. Returns
/// the credentialSubject on success, `None` if invalid.
pub fn verify_perception_attestation(
    credential: &Value,
    public_key: &[u8],
    frame: Option<&[u8]>,
) -> Result<Option<Value>> {
    if !has_type(credential.get("type"), PERCEPTION_TYPE) {
        return Ok(None);
    }
    if !data_integrity::verify_proof(credential, public_key)? {
        return Ok(None);
    }
    let subject = match credential
        .get("credentialSubject")
        .and_then(|s| s.as_object())
    {
        Some(s) => s,
        None => return Ok(None),
    };
    let frame_hash = subject.get("frameHash").and_then(|v| v.as_str());
    let modality = subject.get("modality").and_then(|v| v.as_str());
    match (frame_hash, modality) {
        (Some(fh), Some(m)) if !fh.is_empty() && MODALITIES.contains(&m) => {}
        _ => return Ok(None),
    }
    if let Some(f) = frame {
        if hash_frame(f) != frame_hash.unwrap_or("") {
            return Ok(None);
        }
    }
    Ok(Some(Value::Object(subject.clone())))
}

// ---------------------------------------------------------------------------
// Delegation lease (Phase 5.11)
// ---------------------------------------------------------------------------

pub const DELEGATION_LEASE_TYPE: &str = "DelegationLeaseCredential";

/// Parameters for [`build_delegation_lease`]. The issuer is the signer (an
/// authority or the holder of a parent lease); `robot_did` is the subject the
/// lease is granted to. `scope` is a physicalScope object (the same shape as a
/// `PhysicalCapabilityScope` credentialSubject.physicalScope). Leases are
/// short-lived by design, so the window is bounded by `valid_from`/`valid_until`.
/// Set `parent_lease_id` when sub-granting from another lease.
#[derive(Debug, Clone)]
pub struct BuildDelegationLease {
    pub issuer_did: String,
    pub robot_did: String,
    pub lease_id: String,
    pub scope: Value,
    pub parent_lease_id: Option<String>,
    pub valid_from: String,
    pub valid_until: String,
}

/// Build a signed `DelegationLeaseCredential` granting `robot_did` a bounded
/// physical scope for a fixed window. The window is verifiable entirely offline.
pub fn build_delegation_lease(signer_seed: &[u8], params: &BuildDelegationLease) -> Result<Value> {
    if params.lease_id.is_empty() {
        return Err(CoreError::Json("lease_id is required".into()));
    }
    if !params.scope.is_object() {
        return Err(CoreError::Json(
            "scope must be a physicalScope object".into(),
        ));
    }

    let mut subject = Map::new();
    subject.insert("id".into(), json!(params.robot_did));
    subject.insert("leaseId".into(), json!(params.lease_id));
    subject.insert("physicalScope".into(), params.scope.clone());
    if let Some(parent) = &params.parent_lease_id {
        subject.insert("parentLeaseId".into(), json!(parent));
    }

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert(
        "type".into(),
        json!(["VerifiableCredential", DELEGATION_LEASE_TYPE]),
    );
    cred.insert("issuer".into(), json!(params.issuer_did));
    cred.insert("validFrom".into(), json!(params.valid_from));
    cred.insert("validUntil".into(), json!(params.valid_until));
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(format!("{}#key-1", params.issuer_did), &params.valid_from);
    data_integrity::sign(&Value::Object(cred), signer_seed, &opts)
}

/// True if the credential's `validFrom`/`validUntil` window contains `now_iso`.
/// A `None` clock skips the check (the deterministic core leaves the wall clock
/// to the wrapper), so the window is treated as current.
fn lease_window_current(credential: &Value, now_iso: Option<&str>) -> bool {
    let now = match now_iso {
        Some(n) => n,
        None => return true,
    };
    let moment = match crate::time::iso_to_epoch_seconds(now) {
        Ok(t) => t,
        Err(_) => return false,
    };
    if let Some(vf) = credential.get("validFrom").and_then(|v| v.as_str()) {
        match crate::time::iso_to_epoch_seconds(vf) {
            Ok(t) if moment < t => return false,
            Err(_) => return false,
            _ => {}
        }
    }
    if let Some(vu) = credential.get("validUntil").and_then(|v| v.as_str()) {
        match crate::time::iso_to_epoch_seconds(vu) {
            Ok(t) if moment > t => return false,
            Err(_) => return false,
            _ => {}
        }
    }
    true
}

/// Verify a `DelegationLeaseCredential` offline: the issuer's proof, that the
/// window is current (when `now_iso` is supplied), and (when `parent_scope` is
/// supplied) that this lease's scope attenuates the parent. No network call.
/// Returns the credentialSubject on success, `None` if invalid.
pub fn verify_delegation_lease(
    credential: &Value,
    public_key: &[u8],
    now_iso: Option<&str>,
    parent_scope: Option<&Value>,
) -> Result<Option<Value>> {
    if !has_type(credential.get("type"), DELEGATION_LEASE_TYPE) {
        return Ok(None);
    }
    if !data_integrity::verify_proof(credential, public_key)? {
        return Ok(None);
    }
    if !lease_window_current(credential, now_iso) {
        return Ok(None);
    }

    let subject = match credential
        .get("credentialSubject")
        .and_then(|s| s.as_object())
    {
        Some(s) => s,
        None => return Ok(None),
    };
    let scope = match subject.get("physicalScope") {
        Some(s) if s.is_object() => s,
        _ => return Ok(None),
    };
    if let Some(parent) = parent_scope {
        if !attenuates(parent, scope) {
            return Ok(None);
        }
    }
    Ok(Some(Value::Object(subject.clone())))
}

/// Decide whether a verified lease permits a proposed physical action: the
/// action must fit the lease scope, and (when the full `credential` is supplied)
/// the window must still be current.
pub fn lease_permits(
    subject: &Value,
    action: &PhysicalAction,
    credential: Option<&Value>,
    now_iso: Option<&str>,
) -> bool {
    if let Some(cred) = credential {
        if !lease_window_current(cred, now_iso) {
            return false;
        }
    }
    let empty = json!({});
    let scope = subject.get("physicalScope").unwrap_or(&empty);
    check_physical_action(scope, action).ok
}

// ---------------------------------------------------------------------------
// Physical quorum (Phase 5.12)
// ---------------------------------------------------------------------------

pub const ACTION_APPROVAL_TYPE: &str = "PhysicalActionApprovalCredential";
pub const APPROVE: &str = "approve";
pub const REJECT: &str = "reject";

/// Parameters for [`build_action_approval`]. The approver is the signer; the
/// approval is over a specific physical action `action_id` that `robot_did`
/// would perform. `decision` is "approve" or "reject".
#[derive(Debug, Clone)]
pub struct BuildActionApproval {
    pub approver_did: String,
    pub action_id: String,
    pub robot_did: String,
    pub decision: String,
    pub valid_from: String,
    pub valid_until: Option<String>,
}

/// Build a signed `PhysicalActionApprovalCredential` by one approver for a
/// specific physical action.
pub fn build_action_approval(approver_seed: &[u8], params: &BuildActionApproval) -> Result<Value> {
    if params.decision != APPROVE && params.decision != REJECT {
        return Err(CoreError::Json(format!(
            "decision must be {APPROVE:?} or {REJECT:?}, got {:?}",
            params.decision
        )));
    }
    if params.action_id.is_empty() {
        return Err(CoreError::Json("action_id is required".into()));
    }

    let mut subject = Map::new();
    subject.insert("id".into(), json!(params.approver_did));
    subject.insert("actionId".into(), json!(params.action_id));
    subject.insert("robotDid".into(), json!(params.robot_did));
    subject.insert("decision".into(), json!(params.decision));

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert(
        "type".into(),
        json!(["VerifiableCredential", ACTION_APPROVAL_TYPE]),
    );
    cred.insert("issuer".into(), json!(params.approver_did));
    cred.insert("validFrom".into(), json!(params.valid_from));
    if let Some(vu) = &params.valid_until {
        cred.insert("validUntil".into(), json!(vu));
    }
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(format!("{}#key-1", params.approver_did), &params.valid_from);
    data_integrity::sign(&Value::Object(cred), approver_seed, &opts)
}

/// One approver's public key, looked up by issuer DID, for
/// [`verify_action_authorization`].
#[derive(Debug, Clone)]
pub struct ApproverKey {
    pub did: String,
    pub public_key: Vec<u8>,
}

/// Verify that a high-consequence physical action is authorized by a quorum.
///
/// Each approval must be the right type, carry an in-date proof signed by the
/// approver's key (looked up in `approver_keys` by issuer DID), match `action_id`
/// and `robot_did`, and carry an `approve` decision. When `approver_set` is
/// supplied, the approver must be in it. The action is authorized when at least
/// `threshold` DISTINCT valid approvers have approved; a single approver counts
/// once even if it submits several approvals. Returns `(authorized, sorted list
/// of the distinct approving DIDs)`.
pub fn verify_action_authorization(
    approvals: &[Value],
    action_id: &str,
    robot_did: &str,
    approver_keys: &[ApproverKey],
    threshold: i64,
    approver_set: Option<&HashSet<String>>,
    now_iso: Option<&str>,
) -> Result<(bool, Vec<String>)> {
    if threshold < 1 {
        return Err(CoreError::Json("threshold must be at least 1".into()));
    }

    let mut approvers: HashSet<String> = HashSet::new();
    for approval in approvals {
        if !has_type(approval.get("type"), ACTION_APPROVAL_TYPE) {
            continue;
        }
        let subject = match approval
            .get("credentialSubject")
            .and_then(|s| s.as_object())
        {
            Some(s) => s,
            None => continue,
        };
        let issuer = approval
            .get("issuer")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if subject.get("actionId").and_then(|v| v.as_str()) != Some(action_id)
            || subject.get("robotDid").and_then(|v| v.as_str()) != Some(robot_did)
        {
            continue;
        }
        if subject.get("decision").and_then(|v| v.as_str()) != Some(APPROVE) {
            continue;
        }
        if let Some(set) = approver_set {
            if !set.contains(issuer) {
                continue;
            }
        }
        let key = match approver_keys.iter().find(|k| k.did == issuer) {
            Some(k) => k,
            None => continue,
        };
        if !lease_window_current(approval, now_iso) {
            continue;
        }
        if !data_integrity::verify_proof(approval, &key.public_key)? {
            continue;
        }
        approvers.insert(issuer.to_string());
    }

    let mut sorted: Vec<String> = approvers.into_iter().collect();
    sorted.sort();
    Ok((sorted.len() as i64 >= threshold, sorted))
}

// ---------------------------------------------------------------------------
// Robot lifecycle: ownership transfer, key rotation, decommission (Phase 5.13)
// ---------------------------------------------------------------------------

pub const OWNERSHIP_TRANSFER_TYPE: &str = "RobotOwnershipTransferCredential";
pub const KEY_ROTATION_TYPE: &str = "RobotKeyRotationCredential";
pub const DECOMMISSION_TYPE: &str = "RobotDecommissionCredential";

/// Verify a typed lifecycle credential: the credential carries `expected_type`
/// and its Data Integrity proof verifies under `public_key`. Returns the
/// credentialSubject on success, `None` otherwise. The per-credential rules
/// (issuer equals fromOwner, required subject fields) are applied by the caller.
fn verify_typed(
    credential: &Value,
    public_key: &[u8],
    expected_type: &str,
) -> Result<Option<Value>> {
    if !has_type(credential.get("type"), expected_type) {
        return Ok(None);
    }
    if !data_integrity::verify_proof(credential, public_key)? {
        return Ok(None);
    }
    match credential
        .get("credentialSubject")
        .and_then(|s| s.as_object())
    {
        Some(s) => Ok(Some(Value::Object(s.clone()))),
        None => Ok(None),
    }
}

/// Parameters for [`build_ownership_transfer`]. The signer is the current owner;
/// `from_owner` defaults to `issuer_did` (the current owner's DID). Setting
/// `prev_transfer_id` links this transfer to the previous one, forming a chain.
#[derive(Debug, Clone)]
pub struct BuildOwnershipTransfer {
    pub issuer_did: String,
    pub robot_did: String,
    pub to_owner: String,
    pub from_owner: Option<String>,
    pub prev_transfer_id: Option<String>,
    pub valid_from: String,
}

/// Build a signed transfer of `robot_did` from the current owner to `to_owner`.
/// The signer is the current owner; `from_owner` defaults to `issuer_did`.
pub fn build_ownership_transfer(
    current_owner_seed: &[u8],
    params: &BuildOwnershipTransfer,
) -> Result<Value> {
    if params.robot_did.is_empty() || params.to_owner.is_empty() {
        return Err(CoreError::Json(
            "robot_did and to_owner are required".into(),
        ));
    }
    let seller = params
        .from_owner
        .clone()
        .unwrap_or_else(|| params.issuer_did.clone());

    let mut subject = Map::new();
    subject.insert("id".into(), json!(params.robot_did));
    subject.insert("fromOwner".into(), json!(seller));
    subject.insert("toOwner".into(), json!(params.to_owner));
    if let Some(prev) = &params.prev_transfer_id {
        subject.insert("prevTransferId".into(), json!(prev));
    }

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert(
        "type".into(),
        json!(["VerifiableCredential", OWNERSHIP_TRANSFER_TYPE]),
    );
    cred.insert("issuer".into(), json!(params.issuer_did));
    cred.insert("validFrom".into(), json!(params.valid_from));
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(format!("{}#key-1", params.issuer_did), &params.valid_from);
    data_integrity::sign(&Value::Object(cred), current_owner_seed, &opts)
}

/// Verify a transfer: the current owner's proof and that the issuer is the
/// `fromOwner` (only the current owner can transfer the robot). Returns the
/// credentialSubject on success, `None` if invalid.
pub fn verify_ownership_transfer(
    credential: &Value,
    current_owner_public_key: &[u8],
) -> Result<Option<Value>> {
    let subject = match verify_typed(
        credential,
        current_owner_public_key,
        OWNERSHIP_TRANSFER_TYPE,
    )? {
        Some(s) => s,
        None => return Ok(None),
    };
    let to_owner = subject.get("toOwner").and_then(|v| v.as_str());
    let from_owner = subject.get("fromOwner").and_then(|v| v.as_str());
    match (to_owner, from_owner) {
        (Some(t), Some(f)) if !t.is_empty() && !f.is_empty() => {
            if credential.get("issuer").and_then(|v| v.as_str()) != Some(f) {
                return Ok(None);
            }
        }
        _ => return Ok(None),
    }
    Ok(Some(subject))
}

/// One owner's public key, looked up by owner DID, for [`verify_custody_chain`].
#[derive(Debug, Clone)]
pub struct OwnerKey {
    pub did: String,
    pub public_key: Vec<u8>,
}

/// Verify an ordered list of transfer credentials forms a valid chain of custody:
/// each transfer's proof verifies under the owner who signed it, every link's
/// `toOwner` matches the next link's `fromOwner`, and (when given) the first
/// `fromOwner` is `origin_owner`. `public_keys` maps an owner DID to its key.
/// Returns `(ok, current_owner)`.
pub fn verify_custody_chain(
    transfers: &[Value],
    public_keys: &[OwnerKey],
    origin_owner: Option<&str>,
) -> Result<(bool, Option<String>)> {
    let mut expected_from: Option<String> = origin_owner.map(String::from);
    let mut current_owner: Option<String> = origin_owner.map(String::from);
    for transfer in transfers {
        let issuer = transfer
            .get("issuer")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let key = match public_keys.iter().find(|k| k.did == issuer) {
            Some(k) => k,
            None => return Ok((false, None)),
        };
        let subject = match verify_ownership_transfer(transfer, &key.public_key)? {
            Some(s) => s,
            None => return Ok((false, None)),
        };
        if let Some(expected) = &expected_from {
            if subject.get("fromOwner").and_then(|v| v.as_str()) != Some(expected.as_str()) {
                return Ok((false, None));
            }
        }
        current_owner = subject
            .get("toOwner")
            .and_then(|v| v.as_str())
            .map(String::from);
        expected_from = current_owner.clone();
    }
    Ok((true, current_owner))
}

/// Parameters for [`build_key_rotation`]. The credential is signed by the old key
/// (the `signer_seed`) and issued under `robot_did`; the old key's public multibase
/// is recorded as `previousKey` and `new_key_multibase` as the authorized successor.
#[derive(Debug, Clone)]
pub struct BuildKeyRotation {
    pub robot_did: String,
    pub new_key_multibase: String,
    pub reason: Option<String>,
    pub valid_from: String,
}

/// Build a key-rotation credential in which the robot's current (old) key
/// authorizes a new key. Signed by the old key, so anyone trusting the old key
/// can trust the new one. `old_key_seed` is the seed of the current key.
pub fn build_key_rotation(old_key_seed: &[u8], params: &BuildKeyRotation) -> Result<Value> {
    if params.new_key_multibase.is_empty() {
        return Err(CoreError::Json("new_key_multibase is required".into()));
    }
    let old_kp = keys::Ed25519KeyPair::from_seed_slice(old_key_seed)?;

    let mut subject = Map::new();
    subject.insert("id".into(), json!(params.robot_did));
    subject.insert("previousKey".into(), json!(old_kp.public_multikey()));
    subject.insert("newKey".into(), json!(params.new_key_multibase));
    if let Some(reason) = &params.reason {
        subject.insert("reason".into(), json!(reason));
    }

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert(
        "type".into(),
        json!(["VerifiableCredential", KEY_ROTATION_TYPE]),
    );
    cred.insert("issuer".into(), json!(params.robot_did));
    cred.insert("validFrom".into(), json!(params.valid_from));
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(format!("{}#key-1", params.robot_did), &params.valid_from);
    data_integrity::sign(&Value::Object(cred), old_key_seed, &opts)
}

/// Verify a key rotation: the OLD key signed it, binding the new key. Returns the
/// credentialSubject (with `newKey` the authorized successor) on success.
pub fn verify_key_rotation(credential: &Value, old_public_key: &[u8]) -> Result<Option<Value>> {
    let subject = match verify_typed(credential, old_public_key, KEY_ROTATION_TYPE)? {
        Some(s) => s,
        None => return Ok(None),
    };
    let previous = subject.get("previousKey").and_then(|v| v.as_str());
    let new_key = subject.get("newKey").and_then(|v| v.as_str());
    match (previous, new_key) {
        (Some(p), Some(n)) if !p.is_empty() && !n.is_empty() => {}
        _ => return Ok(None),
    }
    Ok(Some(subject))
}

/// One key's public bytes, looked up by key multibase, for [`verify_key_history`].
#[derive(Debug, Clone)]
pub struct KeyEntry {
    pub multibase: String,
    pub public_key: Vec<u8>,
}

/// Verify an ordered list of key rotations forms a valid key history starting from
/// `origin_key_multibase`: each rotation's `previousKey` matches the current key,
/// and each is signed by the key it rotates from. `public_keys` maps a key
/// multibase to the corresponding public key. Returns `(ok, current_key)`.
pub fn verify_key_history(
    rotations: &[Value],
    origin_key_multibase: &str,
    public_keys: &[KeyEntry],
) -> Result<(bool, Option<String>)> {
    let mut current_key = origin_key_multibase.to_string();
    for rotation in rotations {
        let previous = rotation
            .get("credentialSubject")
            .and_then(|s| s.get("previousKey"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if previous != current_key {
            return Ok((false, None));
        }
        let key = match public_keys.iter().find(|k| k.multibase == current_key) {
            Some(k) => k,
            None => return Ok((false, None)),
        };
        let subject = match verify_key_rotation(rotation, &key.public_key)? {
            Some(s) => s,
            None => return Ok((false, None)),
        };
        current_key = subject
            .get("newKey")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
    }
    Ok((true, Some(current_key)))
}

/// Parameters for [`build_decommission`]. The signer is the owner or an authority;
/// `final_disposition` records the outcome (for example recycled, destroyed, or
/// transferred to parts). When `valid_until` is set it bounds the credential.
#[derive(Debug, Clone)]
pub struct BuildDecommission {
    pub issuer_did: String,
    pub robot_did: String,
    pub reason: String,
    pub final_disposition: Option<String>,
    pub valid_from: String,
    pub valid_until: Option<String>,
}

/// Build a signed decommission credential retiring `robot_did`. After
/// decommissioning, a verifier should refuse to trust the robot. `decommissionedBy`
/// is the issuer DID.
pub fn build_decommission(signer_seed: &[u8], params: &BuildDecommission) -> Result<Value> {
    if params.reason.is_empty() {
        return Err(CoreError::Json("reason is required".into()));
    }
    let mut subject = Map::new();
    subject.insert("id".into(), json!(params.robot_did));
    subject.insert("reason".into(), json!(params.reason));
    subject.insert("decommissionedBy".into(), json!(params.issuer_did));
    if let Some(disposition) = &params.final_disposition {
        subject.insert("finalDisposition".into(), json!(disposition));
    }

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert(
        "type".into(),
        json!(["VerifiableCredential", DECOMMISSION_TYPE]),
    );
    cred.insert("issuer".into(), json!(params.issuer_did));
    cred.insert("validFrom".into(), json!(params.valid_from));
    if let Some(vu) = &params.valid_until {
        cred.insert("validUntil".into(), json!(vu));
    }
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(format!("{}#key-1", params.issuer_did), &params.valid_from);
    data_integrity::sign(&Value::Object(cred), signer_seed, &opts)
}

/// Verify a decommission credential. When `trusted_authorities` is supplied, the
/// issuer DID MUST be in it, so only an attested authority can retire the robot.
/// Returns the credentialSubject on success.
pub fn verify_decommission(
    credential: &Value,
    public_key: &[u8],
    trusted_authorities: Option<&HashSet<String>>,
) -> Result<Option<Value>> {
    let subject = match verify_typed(credential, public_key, DECOMMISSION_TYPE)? {
        Some(s) => s,
        None => return Ok(None),
    };
    if let Some(trusted) = trusted_authorities {
        let issuer = credential
            .get("issuer")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !trusted.contains(issuer) {
            return Ok(None);
        }
    }
    Ok(Some(subject))
}

// ---------------------------------------------------------------------------
// Regulatory conformance profiles (Phase 5.14)
// ---------------------------------------------------------------------------
//
// A conformance profile is a machine-checkable mapping from Vouch robotics
// credentials to the clauses of a public safety or AI regulation. Given the
// credentials a robot presents, the checker reports which clauses are satisfied
// and cites each one, and an issuer can sign a point-in-time conformance
// attestation an auditor or notified body can consume. The profiles are plain
// data so every language reproduces them identically.
//
// This is the open layer: declarative profiles, a deterministic checker, and a
// signed point-in-time attestation over the full report. It is a reference
// crosswalk to make conformance verifiable in the open, not legal advice.

pub const CONFORMANCE_ATTESTATION_TYPE: &str = "RobotConformanceAttestation";

/// One requirement in a profile: a clause of a regulation mapped to the
/// credential type and field paths that satisfy it.
struct ProfileRequirement {
    id: &'static str,
    clause: &'static str,
    title: &'static str,
    credential: &'static str,
    fields: &'static [&'static str],
}

/// A built-in conformance profile: a regime, a version, and its requirements.
struct ConformanceProfile {
    regime: &'static str,
    version: &'static str,
    requirements: &'static [ProfileRequirement],
}

const ISO_10218_REQUIREMENTS: &[ProfileRequirement] = &[
    ProfileRequirement {
        id: "iso10218-identification",
        clause: "ISO 10218-1:2011, 5.2",
        title: "Robot identification bound to its hardware",
        credential: "RobotIdentityCredential",
        fields: &["hardwareRoot.kind"],
    },
    ProfileRequirement {
        id: "iso10218-software-integrity",
        clause: "ISO 10218-1:2011, 5.3",
        title: "Control software and configuration integrity",
        credential: "ModelProvenanceAttestation",
        fields: &["vla.weightsHash"],
    },
    ProfileRequirement {
        id: "iso10218-limits",
        clause: "ISO 10218-1:2011, 5.6",
        title: "Limiting of speed, force, and workspace",
        credential: "PhysicalCapabilityScope",
        fields: &["physicalScope.maxForceN", "physicalScope.maxSpeedMps"],
    },
    ProfileRequirement {
        id: "iso10218-records",
        clause: "ISO 10218-2:2011, 5.2",
        title: "Records of safety-relevant events",
        credential: "RobotSafetyRecordCredential",
        fields: &["totalEvents"],
    },
];

const ISO_TS_15066_REQUIREMENTS: &[ProfileRequirement] = &[
    ProfileRequirement {
        id: "iso15066-power-force-limiting",
        clause: "ISO/TS 15066:2016, 5.5.4",
        title: "Power and force limiting near humans",
        credential: "PhysicalCapabilityScope",
        fields: &[
            "physicalScope.maxSpeedNearHumansMps",
            "physicalScope.maxForceN",
        ],
    },
    ProfileRequirement {
        id: "iso15066-collaborative-workspace",
        clause: "ISO/TS 15066:2016, 5.5.2",
        title: "Defined collaborative workspace",
        credential: "PhysicalCapabilityScope",
        fields: &["physicalScope.allowedZones"],
    },
    ProfileRequirement {
        id: "iso15066-monitoring",
        clause: "ISO/TS 15066:2016, 5.2",
        title: "Continuous monitoring of the collaborative operation",
        credential: "RobotHeartbeatCredential",
        fields: &["motionDigest"],
    },
];

const EU_MACHINERY_REQUIREMENTS: &[ProfileRequirement] = &[
    ProfileRequirement {
        id: "eu-mr-identification",
        clause: "Reg (EU) 2023/1230, Annex III 1.7.4",
        title: "Machinery identification and traceability",
        credential: "RobotIdentityCredential",
        fields: &["make", "model", "serial"],
    },
    ProfileRequirement {
        id: "eu-mr-software-integrity",
        clause: "Reg (EU) 2023/1230, Annex III 1.1.9",
        title: "Protection against corruption of safety software",
        credential: "ModelProvenanceAttestation",
        fields: &["vla.weightsHash", "vla.safetyPolicy"],
    },
    ProfileRequirement {
        id: "eu-mr-safe-limits",
        clause: "Reg (EU) 2023/1230, Annex III 1.2.1",
        title: "Safety and reliability of control systems and limits",
        credential: "PhysicalCapabilityScope",
        fields: &["physicalScope.maxForceN"],
    },
    ProfileRequirement {
        id: "eu-mr-records",
        clause: "Reg (EU) 2023/1230, Annex III 1.2.1",
        title: "Recording of safety-relevant data",
        credential: "RobotSafetyRecordCredential",
        fields: &["totalEvents"],
    },
];

const EU_AI_ACT_REQUIREMENTS: &[ProfileRequirement] = &[
    ProfileRequirement {
        id: "eu-aia-record-keeping",
        clause: "Reg (EU) 2024/1689, Art. 12",
        title: "Automatic recording of events (logging)",
        credential: "RobotSafetyRecordCredential",
        fields: &["logHead"],
    },
    ProfileRequirement {
        id: "eu-aia-transparency",
        clause: "Reg (EU) 2024/1689, Art. 13",
        title: "Model and configuration transparency",
        credential: "ModelProvenanceAttestation",
        fields: &["vla.modelName", "vla.configHash"],
    },
    ProfileRequirement {
        id: "eu-aia-human-oversight",
        clause: "Reg (EU) 2024/1689, Art. 14",
        title: "Human oversight through enforced operating limits",
        credential: "PhysicalCapabilityScope",
        fields: &["physicalScope.maxSpeedNearHumansMps"],
    },
    ProfileRequirement {
        id: "eu-aia-accuracy-robustness",
        clause: "Reg (EU) 2024/1689, Art. 15",
        title: "Accuracy and robustness traceable to a known build",
        credential: "ModelProvenanceAttestation",
        fields: &["vla.weightsHash"],
    },
];

const UL_3300_REQUIREMENTS: &[ProfileRequirement] = &[
    ProfileRequirement {
        id: "ul3300-identity",
        clause: "UL 3300, identification",
        title: "Robot identity bound to its hardware",
        credential: "RobotIdentityCredential",
        fields: &["hardwareRoot.kind"],
    },
    ProfileRequirement {
        id: "ul3300-operating-limits",
        clause: "UL 3300, operating limits",
        title: "Enforced speed and zone limits",
        credential: "PhysicalCapabilityScope",
        fields: &["physicalScope.maxSpeedMps", "physicalScope.allowedZones"],
    },
    ProfileRequirement {
        id: "ul3300-perception-integrity",
        clause: "UL 3300, sensing integrity",
        title: "Integrity of perception used for safe operation",
        credential: "PerceptionProvenanceCredential",
        fields: &["frameHash"],
    },
    ProfileRequirement {
        id: "ul3300-records",
        clause: "UL 3300, incident records",
        title: "Records of safety-relevant incidents",
        credential: "RobotSafetyRecordCredential",
        fields: &["totalEvents"],
    },
];

/// Return a built-in profile by id, or `None` if it is unknown. The five profiles
/// cover ISO 10218-1/-2 (industrial), ISO/TS 15066 (collaborative), the EU
/// Machinery Regulation 2023/1230, the EU AI Act high-risk requirements, and
/// UL 3300 (service and mobile robots).
fn conformance_profile(profile_id: &str) -> Option<ConformanceProfile> {
    match profile_id {
        "iso-10218" => Some(ConformanceProfile {
            regime: "ISO 10218-1/-2 industrial robots",
            version: "2011",
            requirements: ISO_10218_REQUIREMENTS,
        }),
        "iso-ts-15066" => Some(ConformanceProfile {
            regime: "ISO/TS 15066 collaborative robots",
            version: "2016",
            requirements: ISO_TS_15066_REQUIREMENTS,
        }),
        "eu-machinery-2023-1230" => Some(ConformanceProfile {
            regime: "EU Machinery Regulation 2023/1230",
            version: "2023",
            requirements: EU_MACHINERY_REQUIREMENTS,
        }),
        "eu-ai-act-high-risk" => Some(ConformanceProfile {
            regime: "EU AI Act high-risk systems",
            version: "2024",
            requirements: EU_AI_ACT_REQUIREMENTS,
        }),
        "ul-3300" => Some(ConformanceProfile {
            regime: "UL 3300 service, communication, and mobile robots",
            version: "2022",
            requirements: UL_3300_REQUIREMENTS,
        }),
        _ => None,
    }
}

/// The type array of a credential, accepting a JSON string or an array of strings.
fn credential_types(credential: &Value) -> Vec<&str> {
    match credential.get("type") {
        Some(Value::String(s)) => vec![s.as_str()],
        Some(Value::Array(items)) => items.iter().filter_map(|v| v.as_str()).collect(),
        _ => Vec::new(),
    }
}

/// Follow a dot-separated path from the credentialSubject, returning the value at
/// the leaf or `None` if any segment is missing or not an object.
fn path_value<'a>(subject: &'a Value, path: &str) -> Option<&'a Value> {
    let mut node = subject;
    for part in path.split('.') {
        match node {
            Value::Object(map) => match map.get(part) {
                Some(v) => node = v,
                None => return None,
            },
            _ => return None,
        }
    }
    Some(node)
}

/// True when a value is present and non-empty: not null, and not an empty array
/// or empty object. Any other value (including `false`, `0`, or `""`) counts.
fn value_present(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
        _ => true,
    }
}

/// True when `credential` satisfies `requirement`: its type array includes the
/// requirement's credential type and its credentialSubject has a non-null,
/// non-empty value at every field path.
fn credential_satisfies(credential: &Value, requirement: &ProfileRequirement) -> bool {
    if !credential_types(credential).contains(&requirement.credential) {
        return false;
    }
    let empty = Value::Object(Map::new());
    let subject = credential.get("credentialSubject").unwrap_or(&empty);
    for path in requirement.fields {
        match path_value(subject, path) {
            Some(v) if value_present(v) => {}
            _ => return false,
        }
    }
    true
}

/// Check the presented `credentials` against the named profile and return a
/// deterministic report. Each requirement is satisfied when some presented
/// credential matches its type and has every required field. The caller is
/// expected to have verified the credentials' signatures first; this checks
/// structure and coverage, not proofs.
///
/// The report has exactly `{profileId, regime, version, conforms,
/// satisfiedCount, totalCount, requirements:[{id, clause, title, satisfied}]}`.
pub fn check_conformance(credentials: &[Value], profile_id: &str) -> Result<Value> {
    let prof = conformance_profile(profile_id)
        .ok_or_else(|| CoreError::Json(format!("unknown conformance profile: {profile_id}")))?;

    let mut results: Vec<Value> = Vec::with_capacity(prof.requirements.len());
    let mut satisfied = 0i64;
    for requirement in prof.requirements {
        let ok = credentials
            .iter()
            .any(|c| credential_satisfies(c, requirement));
        if ok {
            satisfied += 1;
        }
        results.push(json!({
            "id": requirement.id,
            "clause": requirement.clause,
            "title": requirement.title,
            "satisfied": ok,
        }));
    }
    let total = prof.requirements.len() as i64;

    let mut report = Map::new();
    report.insert("profileId".into(), json!(profile_id));
    report.insert("regime".into(), json!(prof.regime));
    report.insert("version".into(), json!(prof.version));
    report.insert("conforms".into(), json!(satisfied == total));
    report.insert("satisfiedCount".into(), json!(satisfied));
    report.insert("totalCount".into(), json!(total));
    report.insert("requirements".into(), Value::Array(results));
    Ok(Value::Object(report))
}

/// Multibase SHA-256 of the JCS-canonical report, for binding into an
/// attestation. Every language canonicalizes identically, so the digest is the
/// same byte string everywhere.
pub fn report_digest(report: &Value) -> String {
    mb64(&Sha256::digest(jcs::canonicalize(report)))
}

/// Parameters for [`build_conformance_attestation`]. The signer is the robot, its
/// owner, or an assessing authority; `robot_did` names the robot the attestation
/// is about. `report` is produced by [`check_conformance`] and is embedded and
/// bound by digest. When `valid_seconds` is set it bounds the attestation.
#[derive(Debug, Clone)]
pub struct BuildConformanceAttestation {
    pub issuer_did: String,
    pub robot_did: String,
    pub report: Value,
    pub valid_from: String,
    pub valid_until: Option<String>,
}

/// Build a signed point-in-time `RobotConformanceAttestation` for `robot_did`
/// over a `report` produced by [`check_conformance`]. The report is embedded and
/// bound by digest.
pub fn build_conformance_attestation(
    signer_seed: &[u8],
    params: &BuildConformanceAttestation,
) -> Result<Value> {
    if params.robot_did.is_empty() {
        return Err(CoreError::Json("robot_did is required".into()));
    }
    let report = params
        .report
        .as_object()
        .ok_or_else(|| CoreError::Json("report must come from check_conformance".into()))?;
    if !report.contains_key("profileId") || !report.contains_key("conforms") {
        return Err(CoreError::Json(
            "report must come from check_conformance".into(),
        ));
    }

    let mut subject = Map::new();
    subject.insert("id".into(), json!(params.robot_did));
    subject.insert(
        "profileId".into(),
        report.get("profileId").cloned().unwrap_or(Value::Null),
    );
    subject.insert(
        "regime".into(),
        report.get("regime").cloned().unwrap_or(Value::Null),
    );
    subject.insert(
        "conforms".into(),
        report.get("conforms").cloned().unwrap_or(Value::Null),
    );
    subject.insert(
        "satisfiedCount".into(),
        report.get("satisfiedCount").cloned().unwrap_or(Value::Null),
    );
    subject.insert(
        "totalCount".into(),
        report.get("totalCount").cloned().unwrap_or(Value::Null),
    );
    subject.insert("reportDigest".into(), json!(report_digest(&params.report)));
    subject.insert("report".into(), params.report.clone());

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert(
        "type".into(),
        json!(["VerifiableCredential", CONFORMANCE_ATTESTATION_TYPE]),
    );
    cred.insert("issuer".into(), json!(params.issuer_did));
    cred.insert("validFrom".into(), json!(params.valid_from));
    if let Some(vu) = &params.valid_until {
        cred.insert("validUntil".into(), json!(vu));
    }
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(format!("{}#key-1", params.issuer_did), &params.valid_from);
    data_integrity::sign(&Value::Object(cred), signer_seed, &opts)
}

/// Verify a conformance attestation: the issuer's proof, that the embedded report
/// matches its bound digest, and that the subject's `conforms` matches the report.
/// Returns the credentialSubject on success, `None` if invalid.
pub fn verify_conformance_attestation(
    credential: &Value,
    public_key: &[u8],
) -> Result<Option<Value>> {
    if !has_type(credential.get("type"), CONFORMANCE_ATTESTATION_TYPE) {
        return Ok(None);
    }
    if !data_integrity::verify_proof(credential, public_key)? {
        return Ok(None);
    }
    let subject = match credential
        .get("credentialSubject")
        .and_then(|s| s.as_object())
    {
        Some(s) => s,
        None => return Ok(None),
    };
    let embedded = match subject.get("report") {
        Some(r) if r.is_object() => r,
        _ => return Ok(None),
    };
    if subject.get("reportDigest").and_then(|v| v.as_str())
        != Some(report_digest(embedded).as_str())
    {
        return Ok(None);
    }
    if subject.get("conforms") != embedded.get("conforms") {
        return Ok(None);
    }
    Ok(Some(Value::Object(subject.clone())))
}

// ---------------------------------------------------------------------------
// Post-quantum robot credentials (Phase 5.13)
// ---------------------------------------------------------------------------
//
// A robot fielded today lives for ten to twenty years, longer than classical
// Ed25519 is expected to stay safe, so a robot identity signed now could be
// forged once a quantum computer arrives. This section makes the hybrid
// post-quantum cryptosuite (`hybrid-eddsa-mldsa44-jcs-2026`, a classical
// Ed25519 signature alongside an ML-DSA-44 signature) available for robot
// credentials so they stay unforgeable across the robot's whole service life.
//
//   - sign_pq: attach a hybrid proof to a robot credential.
//   - verify_robot_credential: verify a robot credential whether it carries a
//     classical or a hybrid proof, auto-detected from the proof, so a fleet can
//     move to PQ gradually without breaking the classical credentials already in
//     the field.
//   - migrate_to_pq: re-sign a fielded robot's classical credential under PQ.
//
// This is the open layer: hybrid signing, backward-compatible verification, and
// a software re-signing migration path. It reuses the existing hybrid composite
// path ([`crate::hybrid`]) and the ML-DSA-44 and multikey helpers rather than
// re-deriving any cryptography.

/// The classical (Ed25519-only) robot credential cryptosuite.
pub const CLASSICAL_CRYPTOSUITE: &str = data_integrity::CRYPTOSUITE_ID;
/// The hybrid post-quantum robot credential cryptosuite.
pub const HYBRID_CRYPTOSUITE: &str = hybrid::HYBRID_COMPOSITE_CRYPTOSUITE_ID;

/// Coerce an ML-DSA-44 public key supplied either as raw 1312-byte bytes or as a
/// Multikey string into raw bytes. Errors on the wrong length or a non-ML-DSA
/// multikey.
pub fn coerce_mldsa44_public(mldsa44_public: &[u8]) -> Result<Vec<u8>> {
    if mldsa44_public.len() != MLDSA44_PUBLIC_LEN {
        return Err(CoreError::InvalidKeyLength {
            expected: MLDSA44_PUBLIC_LEN,
            got: mldsa44_public.len(),
        });
    }
    Ok(mldsa44_public.to_vec())
}

/// Coerce an ML-DSA-44 Multikey string into raw public-key bytes. Errors if the
/// multikey does not carry an ML-DSA-44 key.
pub fn mldsa44_public_from_multikey(multikey_str: &str) -> Result<Vec<u8>> {
    let decoded = multikey::decode(multikey_str)?;
    if decoded.algorithm != "ML-DSA-44" {
        return Err(CoreError::InvalidMultikey(format!(
            "expected an ML-DSA-44 multikey, got {}",
            decoded.algorithm
        )));
    }
    coerce_mldsa44_public(&decoded.raw_key)
}

fn pq_verification_method(credential: &Value) -> String {
    let issuer = credential
        .as_object()
        .and_then(|o| o.get("issuer"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    format!("{issuer}#key-1")
}

/// Attach a hybrid (classical Ed25519 plus post-quantum ML-DSA-44) Data Integrity
/// proof to a pre-built robot `credential`. Any existing proof is replaced. The
/// robot signs with its Ed25519 seed and its ML-DSA-44 key pair; `created` is the
/// caller-supplied ISO-8601 instant, keeping the core deterministic.
pub fn sign_pq(
    credential: &Value,
    ed25519_seed: &[u8],
    mldsa: &MlDsa44KeyPair,
    created: &str,
) -> Result<Value> {
    let vm = pq_verification_method(credential);
    hybrid::sign_composite(credential, ed25519_seed, mldsa, &vm, created)
}

/// Return true if `credential` carries a hybrid post-quantum proof.
pub fn is_pq(credential: &Value) -> bool {
    credential
        .as_object()
        .and_then(|o| o.get("proof"))
        .and_then(|p| p.as_object())
        .and_then(|p| p.get("cryptosuite"))
        .and_then(|v| v.as_str())
        == Some(HYBRID_CRYPTOSUITE)
}

/// Verify a hybrid robot credential. Both the Ed25519 and the ML-DSA-44 signature
/// MUST validate. `mldsa44_public_key` is raw 1312-byte bytes or an ML-DSA-44
/// Multikey string (pass `mldsa44_multikey` for the string form).
pub fn verify_pq(
    credential: &Value,
    ed25519_public_key: &[u8],
    mldsa44_public_key: &[u8],
) -> Result<bool> {
    let resolved_ml = coerce_mldsa44_public(mldsa44_public_key)?;
    hybrid::verify_composite(credential, ed25519_public_key, &resolved_ml)
}

/// Verify a robot credential whether it carries a classical or a hybrid proof,
/// auto-detected from the proof cryptosuite. A hybrid credential REQUIRES
/// `mldsa44_public_key` (returns Ok(false) if absent); a classical credential
/// ignores it and is verified under `eddsa-jcs-2022`. This is the
/// backward-compatible verify a fleet uses while migrating to PQ.
///
/// `mldsa44_public_key` accepts raw 1312-byte bytes or an ML-DSA-44 Multikey
/// string, matched by length: a 1312-byte input is treated as raw, anything else
/// is parsed as a UTF-8 Multikey string.
pub fn verify_robot_credential(
    credential: &Value,
    ed25519_public_key: &[u8],
    mldsa44_public_key: Option<&[u8]>,
) -> Result<bool> {
    if is_pq(credential) {
        let ml = match mldsa44_public_key {
            Some(k) => k,
            None => return Ok(false),
        };
        let resolved_ml = resolve_mldsa44_public(ml)?;
        return hybrid::verify_composite(credential, ed25519_public_key, &resolved_ml);
    }
    data_integrity::verify_proof(credential, ed25519_public_key)
}

/// Resolve an ML-DSA-44 public key given either raw bytes or a Multikey string.
/// A 1312-byte input is the raw key; otherwise it is parsed as a UTF-8 Multikey.
pub fn resolve_mldsa44_public(mldsa44_public_key: &[u8]) -> Result<Vec<u8>> {
    if mldsa44_public_key.len() == MLDSA44_PUBLIC_LEN {
        return Ok(mldsa44_public_key.to_vec());
    }
    let s = std::str::from_utf8(mldsa44_public_key).map_err(|_| {
        CoreError::InvalidMultikey("ML-DSA-44 key must be raw bytes or a Multikey string".into())
    })?;
    mldsa44_public_from_multikey(s)
}

/// Re-sign a fielded robot's classical `credential` under the hybrid PQ
/// cryptosuite, preserving its body. The robot holds its current Ed25519 seed and
/// an ML-DSA-44 key pair; `created` is the caller-supplied re-signing instant.
pub fn migrate_to_pq(
    credential: &Value,
    ed25519_seed: &[u8],
    mldsa: &MlDsa44KeyPair,
    created: &str,
) -> Result<Value> {
    sign_pq(credential, ed25519_seed, mldsa, created)
}

// ---------------------------------------------------------------------------
// Cross-embodiment identity continuity (Phase 5.15)
// ---------------------------------------------------------------------------
//
// An AI agent (a policy with its own Vouch identity) can run on one robot body
// today and a different body tomorrow. An embodiment credential binds the agent
// identity to a specific body (a hardware-rooted robot identity) and that body's
// hardware root for a period, signed by the agent's own persistent key. Linking
// each embodiment to the previous forms a continuity chain a verifier walks to
// confirm the same accountable agent persisted across bodies, re-binding to each
// body's hardware root as it moved. A fork check confirms the agent was never
// actively embodied in two bodies at once.
//
// This is the inverse of the ownership custody chain: there one body passes
// between owners; here one mind passes between bodies, and the constant that
// signs every link is the agent identity itself.
//
// This is the open layer: plain signed embodiment credentials, continuity-chain
// verification, and software fork detection. It reuses the core proof path
// ([`data_integrity`]) rather than re-deriving any cryptography.

pub const EMBODIMENT_TYPE: &str = "AgentEmbodimentCredential";

/// Parameters for [`build_embodiment`]. The signer is the agent's own persistent
/// key; `agent_did` is both issuer and subject id, so the whole continuity chain
/// is signed by one accountable identity. `from_body`, when set, links this
/// embodiment to the body the agent left, forming the chain. `valid_until`, when
/// set, bounds the active window (used by [`check_no_fork`]).
#[derive(Debug, Clone)]
pub struct BuildEmbodiment {
    pub agent_did: String,
    pub body_did: String,
    pub body_hardware_root: String,
    pub from_body: Option<String>,
    pub embodied_at: String,
    pub valid_until: Option<String>,
}

/// Build a signed embodiment credential: the agent `agent_did` authorizes running
/// on `body_did`, re-binding to that body's hardware root `body_hardware_root`.
/// Signed by the agent's own persistent key. `from_body` links this embodiment to
/// the body the agent left.
pub fn build_embodiment(agent_seed: &[u8], params: &BuildEmbodiment) -> Result<Value> {
    if params.agent_did.is_empty()
        || params.body_did.is_empty()
        || params.body_hardware_root.is_empty()
    {
        return Err(CoreError::Json(
            "agent_did, body_did, and body_hardware_root are required".into(),
        ));
    }

    let mut subject = Map::new();
    subject.insert("id".into(), json!(params.agent_did));
    subject.insert("body".into(), json!(params.body_did));
    subject.insert("bodyHardwareRoot".into(), json!(params.body_hardware_root));
    if let Some(from_body) = &params.from_body {
        subject.insert("fromBody".into(), json!(from_body));
    }

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert(
        "type".into(),
        json!(["VerifiableCredential", EMBODIMENT_TYPE]),
    );
    cred.insert("issuer".into(), json!(params.agent_did));
    cred.insert("validFrom".into(), json!(params.embodied_at));
    if let Some(vu) = &params.valid_until {
        cred.insert("validUntil".into(), json!(vu));
    }
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(format!("{}#key-1", params.agent_did), &params.embodied_at);
    data_integrity::sign(&Value::Object(cred), agent_seed, &opts)
}

/// Verify an embodiment credential: the agent's proof, that the issuer is the
/// agent itself (a mind authorizes its own embodiment), and that the subject
/// carries a `body` and a `bodyHardwareRoot`. Returns the credentialSubject on
/// success, `None` if invalid.
pub fn verify_embodiment(credential: &Value, agent_public_key: &[u8]) -> Result<Option<Value>> {
    let subject = match verify_typed(credential, agent_public_key, EMBODIMENT_TYPE)? {
        Some(s) => s,
        None => return Ok(None),
    };
    let has_body = subject
        .get("body")
        .and_then(|v| v.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    let has_root = subject
        .get("bodyHardwareRoot")
        .and_then(|v| v.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    if !has_body || !has_root {
        return Ok(None);
    }
    let subject_id = subject.get("id").and_then(|v| v.as_str());
    if credential.get("issuer").and_then(|v| v.as_str()) != subject_id {
        return Ok(None);
    }
    Ok(Some(subject))
}

/// Verify an ordered list of embodiment credentials forms a valid continuity chain
/// for one agent: every link verifies under the SAME agent key (the persistent
/// mind), each link's `fromBody` matches the previous link's `body`, and (when
/// given) the first `fromBody` is `origin_body`. Returns `(ok, current_body)`.
pub fn verify_continuity_chain(
    embodiments: &[Value],
    agent_public_key: &[u8],
    origin_body: Option<&str>,
) -> Result<(bool, Option<String>)> {
    let mut expected_from: Option<String> = origin_body.map(String::from);
    let mut current_body: Option<String> = origin_body.map(String::from);
    for embodiment in embodiments {
        let subject = match verify_embodiment(embodiment, agent_public_key)? {
            Some(s) => s,
            None => return Ok((false, None)),
        };
        if let Some(expected) = &expected_from {
            if subject.get("fromBody").and_then(|v| v.as_str()) != Some(expected.as_str()) {
                return Ok((false, None));
            }
        }
        current_body = subject
            .get("body")
            .and_then(|v| v.as_str())
            .map(String::from);
        expected_from = current_body.clone();
    }
    Ok((true, current_body))
}

/// Two conflicting bodies surfaced by [`check_no_fork`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkConflict {
    pub body_a: String,
    pub body_b: String,
}

/// Half-open intervals [start, end); a missing end is open-ended (+infinity). A
/// clean handover sets one window's end to the next window's start, which does not
/// overlap.
fn windows_overlap(start_a: i64, end_a: Option<i64>, start_b: i64, end_b: Option<i64>) -> bool {
    let a_before_b = end_a.map(|e| e <= start_b).unwrap_or(false);
    let b_before_a = end_b.map(|e| e <= start_a).unwrap_or(false);
    !(a_before_b || b_before_a)
}

/// Confirm no two embodiments place the agent in different bodies with overlapping
/// active windows. Each embodiment is active from `validFrom` to `validUntil` (a
/// missing `validUntil` is treated as open-ended). Two embodiments on different
/// bodies whose windows overlap are a fork. Returns `(ok, conflict)` where
/// conflict, when present, names the two conflicting bodies.
pub fn check_no_fork(embodiments: &[Value]) -> Result<(bool, Option<ForkConflict>)> {
    let mut windows: Vec<(String, i64, Option<i64>)> = Vec::with_capacity(embodiments.len());
    for embodiment in embodiments {
        let subject = embodiment
            .get("credentialSubject")
            .and_then(|s| s.as_object());
        let body = subject
            .and_then(|s| s.get("body"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty());
        let start = embodiment
            .get("validFrom")
            .and_then(|v| v.as_str())
            .and_then(|s| crate::time::iso_to_epoch_seconds(s).ok());
        let (body, start) = match (body, start) {
            (Some(b), Some(s)) => (b.to_string(), s),
            _ => return Ok((false, None)),
        };
        let end = embodiment
            .get("validUntil")
            .and_then(|v| v.as_str())
            .and_then(|s| crate::time::iso_to_epoch_seconds(s).ok());
        windows.push((body, start, end));
    }

    for i in 0..windows.len() {
        let (body_i, start_i, end_i) = &windows[i];
        for window_j in windows.iter().skip(i + 1) {
            let (body_j, start_j, end_j) = window_j;
            if body_i == body_j {
                continue;
            }
            if windows_overlap(*start_i, *end_i, *start_j, *end_j) {
                return Ok((
                    false,
                    Some(ForkConflict {
                        body_a: body_i.clone(),
                        body_b: body_j.clone(),
                    }),
                ));
            }
        }
    }
    Ok((true, None))
}

// ---------------------------------------------------------------------------
// Physical custody handoff (Phase 5.16)
// ---------------------------------------------------------------------------
//
// A physical task or object passes across a chain of actors, human and robot: a
// person picks an item, hands it to a robot, that robot hands it to another
// robot, which places it. Each handoff is a signed custody transition, so a
// physical-world event traces to the exact hop and the actor responsible.
//
// A custody handoff credential records that a receiving actor accepted custody
// of a task or object from a releasing actor, signed by the receiver. Linking
// each handoff to the previous forms a chain a verifier walks to establish who
// held the task at any time. A condition attested at each handoff lets a state
// change be localized to the specific hop whose holder was responsible.
//
// This is the open layer: signed handoff credentials, chain verification, a
// holder-at-time helper, and software condition localization. It reuses the core
// proof path ([`data_integrity`]) rather than re-deriving any cryptography.

pub const CUSTODY_HANDOFF_TYPE: &str = "CustodyHandoffCredential";

/// Parameters for [`build_handoff`]. The signer is the receiver (`to_actor`), the
/// party taking responsibility. `condition`, when set, attests the state of the
/// task or object as received (for example a status, a quantity, or a hash of an
/// inspection), which lets a later state change be localized to a hop.
/// `from_actor` and `to_actor` may be human or robot DIDs. `valid_until`, when
/// set, bounds the handoff's active window (the wrapper derives it from a
/// `valid_seconds` lifetime added to `handoff_at`, keeping the core's clock
/// caller-supplied).
#[derive(Debug, Clone)]
pub struct BuildHandoff {
    pub task_id: String,
    pub from_actor: String,
    pub to_actor: String,
    pub condition: Option<String>,
    pub handoff_at: String,
    pub valid_until: Option<String>,
}

/// Build a signed custody handoff: the receiving actor `to_actor` accepts custody
/// of `task_id` from `from_actor`, signed by the receiver. The issuer is the
/// receiver, so a party attests its own acceptance of custody.
pub fn build_handoff(receiver_seed: &[u8], params: &BuildHandoff) -> Result<Value> {
    if params.task_id.is_empty() || params.from_actor.is_empty() || params.to_actor.is_empty() {
        return Err(CoreError::Json(
            "task_id, from_actor, and to_actor are required".into(),
        ));
    }

    let mut subject = Map::new();
    subject.insert("id".into(), json!(params.task_id));
    subject.insert("fromActor".into(), json!(params.from_actor));
    subject.insert("toActor".into(), json!(params.to_actor));
    if let Some(condition) = &params.condition {
        subject.insert("condition".into(), json!(condition));
    }

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert(
        "type".into(),
        json!(["VerifiableCredential", CUSTODY_HANDOFF_TYPE]),
    );
    cred.insert("issuer".into(), json!(params.to_actor));
    cred.insert("validFrom".into(), json!(params.handoff_at));
    if let Some(vu) = &params.valid_until {
        cred.insert("validUntil".into(), json!(vu));
    }
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(format!("{}#key-1", params.to_actor), &params.handoff_at);
    data_integrity::sign(&Value::Object(cred), receiver_seed, &opts)
}

/// Verify a custody handoff: the receiver's proof, that the subject carries both a
/// `fromActor` and a `toActor`, and that the issuer is the receiving actor (a
/// party attests its own acceptance of custody). Returns the credentialSubject on
/// success, `None` if invalid.
pub fn verify_handoff(credential: &Value, receiver_public_key: &[u8]) -> Result<Option<Value>> {
    let subject = match verify_typed(credential, receiver_public_key, CUSTODY_HANDOFF_TYPE)? {
        Some(s) => s,
        None => return Ok(None),
    };
    let from_actor = subject.get("fromActor").and_then(|v| v.as_str());
    let to_actor = subject.get("toActor").and_then(|v| v.as_str());
    match (from_actor, to_actor) {
        (Some(f), Some(t)) if !f.is_empty() && !t.is_empty() => {
            if credential.get("issuer").and_then(|v| v.as_str()) != Some(t) {
                return Ok(None);
            }
        }
        _ => return Ok(None),
    }
    Ok(Some(subject))
}

/// One actor's public key, looked up by actor DID, for [`verify_handoff_chain`].
#[derive(Debug, Clone)]
pub struct ActorKey {
    pub did: String,
    pub public_key: Vec<u8>,
}

/// Verify an ordered list of handoff credentials forms a valid custody chain: each
/// handoff verifies under its receiver's key, every link's `toActor` matches the
/// next link's `fromActor`, and (when given) the first `fromActor` is
/// `origin_actor`. `public_keys` maps an actor DID (human or robot) to its key.
/// Returns `(ok, current_holder)`.
pub fn verify_handoff_chain(
    handoffs: &[Value],
    public_keys: &[ActorKey],
    origin_actor: Option<&str>,
) -> Result<(bool, Option<String>)> {
    let mut expected_from: Option<String> = origin_actor.map(String::from);
    let mut current_holder: Option<String> = origin_actor.map(String::from);
    for handoff in handoffs {
        let receiver = handoff.get("issuer").and_then(|v| v.as_str()).unwrap_or("");
        let key = match public_keys.iter().find(|k| k.did == receiver) {
            Some(k) => k,
            None => return Ok((false, None)),
        };
        let subject = match verify_handoff(handoff, &key.public_key)? {
            Some(s) => s,
            None => return Ok((false, None)),
        };
        if let Some(expected) = &expected_from {
            if subject.get("fromActor").and_then(|v| v.as_str()) != Some(expected.as_str()) {
                return Ok((false, None));
            }
        }
        current_holder = subject
            .get("toActor")
            .and_then(|v| v.as_str())
            .map(String::from);
        expected_from = current_holder.clone();
    }
    Ok((true, current_holder))
}

/// Return the actor holding the task at ISO time `at`: the receiver (`toActor`) of
/// the most recent handoff whose `validFrom` is at or before `at`. Returns `None`
/// if no handoff had occurred yet or `at` is unparseable. `handoffs` is assumed in
/// chain order.
pub fn holder_at(handoffs: &[Value], at: &str) -> Option<String> {
    let when = crate::time::iso_to_epoch_seconds(at).ok()?;
    let mut holder: Option<String> = None;
    for handoff in handoffs {
        let start = handoff
            .get("validFrom")
            .and_then(|v| v.as_str())
            .and_then(|s| crate::time::iso_to_epoch_seconds(s).ok());
        if let Some(start) = start {
            if start <= when {
                holder = handoff
                    .get("credentialSubject")
                    .and_then(|s| s.get("toActor"))
                    .and_then(|v| v.as_str())
                    .map(String::from);
            }
        }
    }
    holder
}

/// A condition change localized to the hop responsible for it, surfaced by
/// [`locate_condition_change`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionChange {
    pub responsible_holder: Option<String>,
    pub from_condition: String,
    pub to_condition: String,
}

/// Find the first hop where the attested condition differs from the previous
/// handoff. The holder responsible for the change is the actor who held the task
/// during it (the previous handoff's receiver). Returns the change, or `None` if
/// the condition never changed. Handoffs without a condition are skipped for the
/// comparison.
pub fn locate_condition_change(handoffs: &[Value]) -> Option<ConditionChange> {
    let mut prev_condition: Option<String> = None;
    let mut prev_holder: Option<String> = None;
    for handoff in handoffs {
        let subject = handoff.get("credentialSubject");
        let condition = subject
            .and_then(|s| s.get("condition"))
            .and_then(|v| v.as_str());
        let condition = match condition {
            Some(c) => c,
            None => continue,
        };
        if let Some(prev) = &prev_condition {
            if condition != prev {
                return Some(ConditionChange {
                    responsible_holder: prev_holder,
                    from_condition: prev.clone(),
                    to_condition: condition.to_string(),
                });
            }
        }
        prev_condition = Some(condition.to_string());
        prev_holder = subject
            .and_then(|s| s.get("toActor"))
            .and_then(|v| v.as_str())
            .map(String::from);
    }
    None
}

// ---------------------------------------------------------------------------
// Robot-to-infrastructure bounded access (Phase 5.17)
// ---------------------------------------------------------------------------
//
// A robot in a warehouse, hospital, or building needs to open doors, call
// elevators, dock at chargers, and operate machines. This gives it a bounded,
// revocable, auditable way to do so. The infrastructure operator issues an access
// grant naming a resource, the permitted operations, an optional zone, and a time
// window, signed by the operator. The robot presents a signed access request for a
// specific operation on a specific resource, and the resource authorizes it
// offline: the grant must be valid and operator-signed, the request valid and
// robot-signed, the operation permitted, and the moment inside the window. The
// grant plus the request is a tamper-evident, attributable record of the access.
//
// This is the open layer: signed grants and requests, an offline authorize
// decision, shrink-only attenuation, and the audit record. Hardware-enforced
// actuation in the resource and managed fleet access-policy orchestration are out
// of scope for the open layer.

pub const ACCESS_GRANT_TYPE: &str = "InfrastructureAccessGrant";
pub const ACCESS_REQUEST_TYPE: &str = "InfrastructureAccessRequest";

/// Parameters for [`build_access_grant`]. The signer is the operator; the grant
/// names the robot, the resource, the permitted operations, an optional zone, and
/// a validity window. `valid_until`, when set, bounds the window (the wrapper
/// derives it from a `valid_seconds` lifetime added to `granted_at`, keeping the
/// core's clock caller-supplied).
#[derive(Debug, Clone)]
pub struct BuildAccessGrant {
    pub operator_did: String,
    pub robot_did: String,
    pub resource: String,
    pub operations: Vec<String>,
    pub zone: Option<String>,
    pub granted_at: String,
    pub valid_until: Option<String>,
}

/// Build a signed access grant: the operator grants `robot_did` permission to
/// perform `operations` on `resource` (optionally within `zone`) for the window.
/// Signed by the operator.
pub fn build_access_grant(operator_seed: &[u8], params: &BuildAccessGrant) -> Result<Value> {
    if params.robot_did.is_empty() || params.resource.is_empty() {
        return Err(CoreError::Json(
            "robot_did and resource are required".into(),
        ));
    }
    if params.operations.is_empty() {
        return Err(CoreError::Json(
            "operations must be a non-empty list".into(),
        ));
    }

    let mut subject = Map::new();
    subject.insert("id".into(), json!(params.robot_did));
    subject.insert("resource".into(), json!(params.resource));
    subject.insert("operations".into(), json!(params.operations));
    if let Some(zone) = &params.zone {
        subject.insert("zone".into(), json!(zone));
    }

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert(
        "type".into(),
        json!(["VerifiableCredential", ACCESS_GRANT_TYPE]),
    );
    cred.insert("issuer".into(), json!(params.operator_did));
    cred.insert("validFrom".into(), json!(params.granted_at));
    if let Some(vu) = &params.valid_until {
        cred.insert("validUntil".into(), json!(vu));
    }
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(format!("{}#key-1", params.operator_did), &params.granted_at);
    data_integrity::sign(&Value::Object(cred), operator_seed, &opts)
}

/// Verify an access grant: the operator's proof, that the subject carries a
/// `resource` and non-empty `operations`, and that the grant is within its window
/// at `now_iso` (a `None` clock skips the window check). Returns the
/// credentialSubject on success, `None` if invalid.
pub fn verify_access_grant(
    credential: &Value,
    operator_public_key: &[u8],
    now_iso: Option<&str>,
) -> Result<Option<Value>> {
    let subject = match verify_typed(credential, operator_public_key, ACCESS_GRANT_TYPE)? {
        Some(s) => s,
        None => return Ok(None),
    };
    let resource = subject.get("resource").and_then(|v| v.as_str());
    let operations = subject.get("operations").and_then(|v| v.as_array());
    match (resource, operations) {
        (Some(r), Some(ops)) if !r.is_empty() && !ops.is_empty() => {}
        _ => return Ok(None),
    }
    if !lease_window_current(credential, now_iso) {
        return Ok(None);
    }
    Ok(Some(subject))
}

/// Parameters for [`build_access_request`]. The signer is the robot; the request
/// names the resource and the single operation the robot wants to perform.
#[derive(Debug, Clone)]
pub struct BuildAccessRequest {
    pub robot_did: String,
    pub resource: String,
    pub operation: String,
    pub requested_at: String,
}

/// Build a signed access request: the robot requests to perform `operation` on
/// `resource`. Signed by the robot.
pub fn build_access_request(robot_seed: &[u8], params: &BuildAccessRequest) -> Result<Value> {
    if params.robot_did.is_empty() || params.resource.is_empty() || params.operation.is_empty() {
        return Err(CoreError::Json(
            "robot_did, resource, and operation are required".into(),
        ));
    }

    let mut subject = Map::new();
    subject.insert("id".into(), json!(params.robot_did));
    subject.insert("resource".into(), json!(params.resource));
    subject.insert("operation".into(), json!(params.operation));

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert(
        "type".into(),
        json!(["VerifiableCredential", ACCESS_REQUEST_TYPE]),
    );
    cred.insert("issuer".into(), json!(params.robot_did));
    cred.insert("validFrom".into(), json!(params.requested_at));
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(format!("{}#key-1", params.robot_did), &params.requested_at);
    data_integrity::sign(&Value::Object(cred), robot_seed, &opts)
}

/// The outcome of an offline access authorization: `ok` plus any reasons it
/// failed. Surfaced by [`authorize_access`].
#[derive(Debug, Clone)]
pub struct AuthorizeResult {
    pub ok: bool,
    pub reasons: Vec<String>,
}

/// Decide, offline, whether to allow the requested access. The grant must verify
/// under the operator's key and be in window, the request must verify under the
/// robot's key and be issued by the robot it names, the grant and request must
/// name the same robot and resource, and the requested operation must be permitted
/// by the grant. Returns an [`AuthorizeResult`] with the reasons for any refusal.
pub fn authorize_access(
    grant: &Value,
    request: &Value,
    operator_public_key: &[u8],
    robot_public_key: &[u8],
    now_iso: Option<&str>,
) -> Result<AuthorizeResult> {
    let mut reasons: Vec<String> = Vec::new();

    let grant_subject = match verify_access_grant(grant, operator_public_key, now_iso)? {
        Some(s) => s,
        None => {
            reasons.push("grant invalid or out of window".into());
            return Ok(AuthorizeResult { ok: false, reasons });
        }
    };

    let req_subject = match verify_typed(request, robot_public_key, ACCESS_REQUEST_TYPE)? {
        Some(s) => s,
        None => {
            reasons.push("request invalid".into());
            return Ok(AuthorizeResult { ok: false, reasons });
        }
    };
    let req_id = req_subject.get("id").and_then(|v| v.as_str());
    if request.get("issuer").and_then(|v| v.as_str()) != req_id {
        reasons.push("request invalid".into());
        return Ok(AuthorizeResult { ok: false, reasons });
    }

    if grant_subject.get("id").and_then(|v| v.as_str()) != req_id {
        reasons.push("grant and request name different robots".into());
    }
    if grant_subject.get("resource").and_then(|v| v.as_str())
        != req_subject.get("resource").and_then(|v| v.as_str())
    {
        reasons.push("grant and request name different resources".into());
    }
    let operation = req_subject.get("operation").and_then(|v| v.as_str());
    let permitted = grant_subject
        .get("operations")
        .and_then(|v| v.as_array())
        .map(|ops| operation.is_some() && ops.iter().any(|o| o.as_str() == operation))
        .unwrap_or(false);
    if !permitted {
        reasons.push("operation not permitted by the grant".into());
    }

    Ok(AuthorizeResult {
        ok: reasons.is_empty(),
        reasons,
    })
}

/// Return true if `child` is a valid attenuation of `parent`: the same resource, a
/// subset of the operations, and the same zone (or the parent had no zone). A
/// sub-grant may only narrow, never widen, the access it inherits.
pub fn attenuates_grant(parent: &Value, child: &Value) -> bool {
    let p = parent.get("credentialSubject");
    let c = child.get("credentialSubject");
    let p_resource = p.and_then(|s| s.get("resource")).and_then(|v| v.as_str());
    let c_resource = c.and_then(|s| s.get("resource")).and_then(|v| v.as_str());
    if p_resource != c_resource {
        return false;
    }
    let p_ops: HashSet<&str> = p
        .and_then(|s| s.get("operations"))
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|o| o.as_str()).collect())
        .unwrap_or_default();
    let c_ops: HashSet<&str> = c
        .and_then(|s| s.get("operations"))
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|o| o.as_str()).collect())
        .unwrap_or_default();
    if !c_ops.is_subset(&p_ops) {
        return false;
    }
    let p_zone = p.and_then(|s| s.get("zone")).and_then(|v| v.as_str());
    let c_zone = c.and_then(|s| s.get("zone")).and_then(|v| v.as_str());
    if p_zone.is_some() && c_zone != p_zone {
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// Fused-sensor provenance (Phase 5.18)
// ---------------------------------------------------------------------------
//
// Perception provenance signs individual sensor frames. A robot rarely acts on
// one frame, though: it fuses many frames, from cameras, lidar, radar, and other
// sensors, into a single world model, an object set, an occupancy grid, or a
// pose estimate, and acts on that. This binds a fused output to the exact set of
// input frames that produced it and the fusion method that produced it, signed by
// the robot, so a manipulated fusion result or a silently dropped or substituted
// input is detectable at the provenance layer.
//
// A fused-perception attestation carries the hash of the fused output, an ordered
// list of the input frame hashes, a digest over those inputs, and a fusion method
// identifier, signed by the robot. A verifier reproduces the input digest from the
// listed inputs and, when it holds the raw fused output, reproduces its hash, so
// the attestation commits to exactly those inputs and that output. Checking each
// listed input against the robot's signed perception log confirms every fused
// input traces to a frame the robot actually recorded.
//
// This is the open layer: the robot signs the binding of a fused output to its
// inputs in software, reusing the perception frame hashes. Hardware sensor
// attestation and managed sensor-fusion orchestration are out of scope for the
// open layer.

pub const FUSED_PERCEPTION_TYPE: &str = "FusedPerceptionAttestation";

/// Multibase (base64url) SHA-256 of a raw fused output. Only the hash travels in
/// the attestation; the fused output stays wherever the deployment keeps it.
pub fn hash_fused_output(output: &[u8]) -> String {
    mb64(&Sha256::digest(output))
}

/// Return a deterministic multibase digest over an ordered list of input frame
/// hashes. The digest commits to the exact inputs and their order, so adding,
/// removing, or reordering an input changes it. Reproduced byte-identically
/// across language SDKs by hashing the input hashes joined with newlines.
pub fn fusion_inputs_digest(input_frame_hashes: &[String]) -> Result<String> {
    if input_frame_hashes.is_empty() {
        return Err(CoreError::Json(
            "input_frame_hashes must be a non-empty list".into(),
        ));
    }
    for h in input_frame_hashes {
        if h.is_empty() {
            return Err(CoreError::Json(
                "each input frame hash must be a non-empty string".into(),
            ));
        }
    }
    let joined = input_frame_hashes.join("\n");
    Ok(mb64(&Sha256::digest(joined.as_bytes())))
}

/// Parameters for [`build_fused_attestation`]. The robot self-issues the
/// credential with its own Ed25519 seed. Provide either the raw `fused_output` (it
/// is hashed) or a precomputed `fused_output_hash`, not both. `captured_at`, when
/// `None`, defaults to `valid_from`.
#[derive(Debug, Clone)]
pub struct BuildFusedAttestation {
    pub robot_did: String,
    pub fusion_method: String,
    pub input_frame_hashes: Vec<String>,
    pub fused_output: Option<Vec<u8>>,
    pub fused_output_hash: Option<String>,
    pub captured_at: Option<String>,
    pub valid_from: String,
    pub valid_until: Option<String>,
}

/// Build a signed `FusedPerceptionAttestation`: the robot attests that a fused
/// output was produced by `fusion_method` from the frames named in
/// `input_frame_hashes`. The attestation carries a digest over the ordered inputs,
/// so the set of inputs is tamper-evident. Signed by the robot.
pub fn build_fused_attestation(robot_seed: &[u8], params: &BuildFusedAttestation) -> Result<Value> {
    if params.robot_did.is_empty() {
        return Err(CoreError::Json("robot_did is required".into()));
    }
    if params.fusion_method.is_empty() {
        return Err(CoreError::Json("fusion_method is required".into()));
    }
    if params.input_frame_hashes.is_empty() {
        return Err(CoreError::Json(
            "input_frame_hashes must be a non-empty list".into(),
        ));
    }
    if params.fused_output.is_some() && params.fused_output_hash.is_some() {
        return Err(CoreError::Json(
            "provide either fused_output or fused_output_hash, not both".into(),
        ));
    }
    let fused_output_hash = match (&params.fused_output, &params.fused_output_hash) {
        (Some(o), None) => hash_fused_output(o),
        (None, Some(h)) if !h.is_empty() => h.clone(),
        _ => {
            return Err(CoreError::Json(
                "fused_output or fused_output_hash is required".into(),
            ))
        }
    };

    let captured = params
        .captured_at
        .clone()
        .unwrap_or_else(|| params.valid_from.clone());

    let mut subject = Map::new();
    subject.insert("id".into(), json!(params.robot_did));
    subject.insert("fusionMethod".into(), json!(params.fusion_method));
    subject.insert("fusedOutputHash".into(), json!(fused_output_hash));
    subject.insert("inputFrameHashes".into(), json!(params.input_frame_hashes));
    subject.insert(
        "inputsDigest".into(),
        json!(fusion_inputs_digest(&params.input_frame_hashes)?),
    );
    subject.insert("capturedAt".into(), json!(captured));

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert(
        "type".into(),
        json!(["VerifiableCredential", FUSED_PERCEPTION_TYPE]),
    );
    cred.insert("issuer".into(), json!(params.robot_did));
    cred.insert("validFrom".into(), json!(params.valid_from));
    if let Some(vu) = &params.valid_until {
        cred.insert("validUntil".into(), json!(vu));
    }
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(format!("{}#key-1", params.robot_did), &params.valid_from);
    data_integrity::sign(&Value::Object(cred), robot_seed, &opts)
}

/// Verify a `FusedPerceptionAttestation`: the robot's proof, that the digest over
/// the listed inputs reproduces the attested `inputsDigest` (so the inputs are
/// internally consistent and tamper-evident), and, when the raw `fused_output` is
/// supplied, that its hash reproduces the attested `fusedOutputHash`. Returns the
/// credentialSubject on success, `None` if invalid.
pub fn verify_fused_attestation(
    credential: &Value,
    public_key: &[u8],
    fused_output: Option<&[u8]>,
) -> Result<Option<Value>> {
    let subject = match verify_typed(credential, public_key, FUSED_PERCEPTION_TYPE)? {
        Some(s) => s,
        None => return Ok(None),
    };
    let fused_output_hash = subject.get("fusedOutputHash").and_then(|v| v.as_str());
    let inputs: Vec<String> = subject
        .get("inputFrameHashes")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|e| e.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    match fused_output_hash {
        Some(h) if !h.is_empty() && !inputs.is_empty() => {}
        _ => return Ok(None),
    }
    match fusion_inputs_digest(&inputs) {
        Ok(d) => {
            if Some(d.as_str()) != subject.get("inputsDigest").and_then(|v| v.as_str()) {
                return Ok(None);
            }
        }
        Err(_) => return Ok(None),
    }
    if let Some(o) = fused_output {
        if hash_fused_output(o) != fused_output_hash.unwrap_or("") {
            return Ok(None);
        }
    }
    Ok(Some(subject))
}

/// The outcome of confirming an attestation's inputs against a perception log:
/// `ok` plus the input frame hashes not found. Surfaced by [`verify_fusion_inputs`].
#[derive(Debug, Clone)]
pub struct FusionInputsResult {
    pub ok: bool,
    pub missing: Vec<String>,
}

/// Confirm every input frame the attestation names was actually recorded in the
/// robot's perception log. Returns `ok` plus `missing`, the input frame hashes that
/// do not appear as a recorded frame, so a dropped or substituted fused input is
/// named rather than hidden.
pub fn verify_fusion_inputs(credential: &Value, log_entries: &[Value]) -> FusionInputsResult {
    let recorded: HashSet<&str> = log_entries
        .iter()
        .filter_map(|e| e.get("frameHash").and_then(|v| v.as_str()))
        .collect();
    let inputs: Vec<String> = credential
        .get("credentialSubject")
        .and_then(|s| s.get("inputFrameHashes"))
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|e| e.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let missing: Vec<String> = inputs
        .into_iter()
        .filter(|h| !recorded.contains(h.as_str()))
        .collect();
    FusionInputsResult {
        ok: missing.is_empty(),
        missing,
    }
}

// ---------------------------------------------------------------------------
// Wear and degradation attestation (Phase 5.19)
// ---------------------------------------------------------------------------
//
// A robot does not stay as capable as it left the factory. Actuators wear, joints
// develop backlash, sensors drift out of calibration, and error rates creep up.
// This lets a robot sign its own degradation state, bound to its identity and
// hash-linked over time so the history is tamper-evident, and derives a narrowed
// physical capability scope from that state, so a worn robot operates inside a
// tighter, verifiable envelope instead of trusting the static limit it shipped
// with.
//
// A wear attestation carries a normalized wear level (0 for as-new, 1 for fully
// worn) and optional detailed metrics, signed by the robot. Linking each
// attestation to the previous one by its proof value forms a chain a verifier
// walks to see how the robot degraded over its life. `attenuate_for_wear` derives
// a physical scope whose numeric caps are scaled down by the wear level, and the
// result is a valid attenuation of the original scope, so the same attenuation
// rule the rest of Vouch uses carries the derating.
//
// This is the open layer: the robot signs its wear state and derives the narrowed
// scope credential in software. Firmware-level enforcement of the narrowed
// envelope and managed predictive-maintenance modeling are out of scope for the
// open layer.

pub const WEAR_ATTESTATION_TYPE: &str = "RobotWearAttestation";

/// Numeric caps that scale down with wear. Zones and shift windows are preserved
/// unchanged, so the derived scope stays a valid attenuation of the original.
const WEAR_DERATED_CAPS: [&str; 3] = ["maxForceN", "maxSpeedMps", "maxSpeedNearHumansMps"];

/// Parameters for [`build_wear_attestation`]. The robot self-issues the credential
/// with its own Ed25519 seed. `metrics`, when present, is carried through into the
/// subject unchanged. `prev_proof`, when present, links this attestation to the
/// previous one, forming a wear history. `attested_at`, when `None`, defaults to
/// `valid_from`.
#[derive(Debug, Clone)]
pub struct BuildWearAttestation {
    pub robot_did: String,
    pub wear_level: f64,
    pub metrics: Option<Value>,
    pub prev_proof: Option<String>,
    pub attested_at: Option<String>,
    pub valid_from: String,
    pub valid_until: Option<String>,
}

/// Build a signed `RobotWearAttestation`: the robot attests its own degradation as
/// a normalized `wear_level` in `[0, 1]`, optionally with detailed `metrics`. When
/// `prev_proof` is the proof value of the previous attestation, the new one links
/// to it, forming a tamper-evident wear history. Signed by the robot.
pub fn build_wear_attestation(robot_seed: &[u8], params: &BuildWearAttestation) -> Result<Value> {
    if params.robot_did.is_empty() {
        return Err(CoreError::Json("robot_did is required".into()));
    }
    if params.wear_level < 0.0 || params.wear_level > 1.0 {
        return Err(CoreError::Json(
            "wear_level must be between 0.0 and 1.0".into(),
        ));
    }

    let attested = params
        .attested_at
        .clone()
        .unwrap_or_else(|| params.valid_from.clone());

    let mut subject = Map::new();
    subject.insert("id".into(), json!(params.robot_did));
    subject.insert("wearLevel".into(), json!(params.wear_level));
    subject.insert("attestedAt".into(), json!(attested));
    if let Some(m) = &params.metrics {
        subject.insert("metrics".into(), m.clone());
    }
    if let Some(prev) = &params.prev_proof {
        subject.insert("prevProof".into(), json!(prev));
    }

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert(
        "type".into(),
        json!(["VerifiableCredential", WEAR_ATTESTATION_TYPE]),
    );
    cred.insert("issuer".into(), json!(params.robot_did));
    cred.insert("validFrom".into(), json!(params.valid_from));
    if let Some(vu) = &params.valid_until {
        cred.insert("validUntil".into(), json!(vu));
    }
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(format!("{}#key-1", params.robot_did), &params.valid_from);
    data_integrity::sign(&Value::Object(cred), robot_seed, &opts)
}

/// Verify a `RobotWearAttestation`: the robot's proof, that the issuer is the
/// robot, and that the wear level is in range. Returns the credentialSubject on
/// success, `None` if invalid.
pub fn verify_wear_attestation(credential: &Value, public_key: &[u8]) -> Result<Option<Value>> {
    let subject = match verify_typed(credential, public_key, WEAR_ATTESTATION_TYPE)? {
        Some(s) => s,
        None => return Ok(None),
    };
    if credential.get("issuer") != subject.get("id") {
        return Ok(None);
    }
    match subject.get("wearLevel").and_then(|v| v.as_f64()) {
        Some(level) if (0.0..=1.0).contains(&level) => {}
        _ => return Ok(None),
    }
    Ok(Some(subject))
}

/// Verify an ordered wear history: each attestation verifies under the robot's
/// key, and each one after the first links to the previous by its proof value.
/// Returns the latest credentialSubject on success, `None` if any link is invalid.
pub fn verify_wear_chain(attestations: &[Value], public_key: &[u8]) -> Result<Option<Value>> {
    if attestations.is_empty() {
        return Ok(None);
    }
    let mut prev_proof: Option<String> = None;
    let mut latest: Option<Value> = None;
    for att in attestations {
        let subject = match verify_wear_attestation(att, public_key)? {
            Some(s) => s,
            None => return Ok(None),
        };
        if let Some(prev) = &prev_proof {
            let linked = subject.get("prevProof").and_then(|v| v.as_str());
            if linked != Some(prev.as_str()) {
                return Ok(None);
            }
        }
        prev_proof = att
            .get("proof")
            .and_then(|p| p.get("proofValue"))
            .and_then(|v| v.as_str())
            .map(String::from);
        latest = Some(subject);
    }
    Ok(latest)
}

/// Derive a physical scope narrowed for the given wear level: each numeric cap is
/// scaled by `(1 - wear_level)`, and the allowed zones and shift windows are
/// carried through unchanged. The result is a valid attenuation of `scope` (never
/// broader on any dimension), so the same attenuation check the rest of Vouch uses
/// accepts it. A wear level of 0 returns the caps unchanged.
pub fn attenuate_for_wear(scope: &Value, wear_level: f64) -> Result<Value> {
    if wear_level < 0.0 || wear_level > 1.0 {
        return Err(CoreError::Json(
            "wear_level must be between 0.0 and 1.0".into(),
        ));
    }
    let factor = 1.0 - wear_level;
    let empty = Map::new();
    let src = scope.as_object().unwrap_or(&empty);
    let mut narrowed = Map::new();
    for (key, value) in src {
        if WEAR_DERATED_CAPS.contains(&key.as_str()) {
            if let Some(n) = value.as_f64() {
                narrowed.insert(key.clone(), json!(n * factor));
                continue;
            }
        }
        narrowed.insert(key.clone(), value.clone());
    }
    Ok(Value::Object(narrowed))
}

// ---------------------------------------------------------------------------
// Bystander-consent evidence (Phase 5.20)
// ---------------------------------------------------------------------------
//
// A robot working in a shared or public space captures people incidentally
// through its cameras and microphones. This lets the robot record, at capture
// time, the basis on which a capture was permitted, bound to the specific capture
// and to the robot's identity, and lets a bystander (or their device) sign a
// consent token bound to that one capture. Only hashes and a consent basis are
// stored, never an image or a bystander's identifying data, so the evidence is
// verifiable without retaining anyone's biometrics.
//
// A bystander consent token is signed by the bystander over the hash of the
// capture and the robot's DID, so it verifies only against the capture it was
// given for and cannot be replayed to a different recording. A bystander-consent
// evidence credential is signed by the robot, binding the capture hash to a
// consent basis (an explicit token, posted notice, a legitimate interest, or a
// redaction that was applied) and, when the basis is explicit consent, to the
// tokens that cover it.
//
// This is the open layer: the cryptographic binding of a consent basis to a
// capture, and its verification, holding only hashes. On-device biometric
// detection and redaction, and managed consent-registry orchestration, are out of
// scope for the open layer.

pub const CONSENT_EVIDENCE_TYPE: &str = "BystanderConsentEvidence";
pub const CONSENT_TOKEN_TYPE: &str = "BystanderConsentToken";

/// Accepted consent bases: the interoperable set a verifier can rely on.
/// Implementers MAY use additional values.
pub const CONSENT_BASES: [&str; 4] = [
    "explicit-consent",
    "posted-notice",
    "legitimate-interest",
    "redacted",
];

/// Multibase (base64url) SHA-256 of a raw capture. Only the hash travels in the
/// token and the evidence; the capture stays wherever the deployment keeps it.
pub fn hash_capture(capture: &[u8]) -> String {
    mb64(&Sha256::digest(capture))
}

/// Parameters for [`build_consent_token`]. The signer is the bystander; the token
/// binds their consent to one capture (named by `capture_hash`) by one robot
/// (`robot_did`). `valid_until`, when set, bounds the window (the wrapper derives
/// it from a `valid_seconds` lifetime added to `granted_at`, keeping the core's
/// clock caller-supplied). `scope`, when set, records what the consent covers.
#[derive(Debug, Clone)]
pub struct BuildConsentToken {
    pub bystander_did: String,
    pub capture_hash: String,
    pub robot_did: String,
    pub scope: Option<String>,
    pub granted_at: String,
    pub valid_until: Option<String>,
}

/// Build a signed `BystanderConsentToken`: a bystander grants consent for a
/// specific capture (named by `capture_hash`) by a specific robot (`robot_did`),
/// signed by the bystander. Binding the token to the capture hash means it cannot
/// be replayed to a different recording. Signed by the bystander.
pub fn build_consent_token(bystander_seed: &[u8], params: &BuildConsentToken) -> Result<Value> {
    if params.bystander_did.is_empty()
        || params.capture_hash.is_empty()
        || params.robot_did.is_empty()
    {
        return Err(CoreError::Json(
            "bystander_did, capture_hash, and robot_did are required".into(),
        ));
    }

    let mut subject = Map::new();
    subject.insert("id".into(), json!(params.bystander_did));
    subject.insert("captureHash".into(), json!(params.capture_hash));
    subject.insert("robotDid".into(), json!(params.robot_did));
    if let Some(scope) = &params.scope {
        subject.insert("scope".into(), json!(scope));
    }

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert(
        "type".into(),
        json!(["VerifiableCredential", CONSENT_TOKEN_TYPE]),
    );
    cred.insert("issuer".into(), json!(params.bystander_did));
    cred.insert("validFrom".into(), json!(params.granted_at));
    if let Some(vu) = &params.valid_until {
        cred.insert("validUntil".into(), json!(vu));
    }
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(
        format!("{}#key-1", params.bystander_did),
        &params.granted_at,
    );
    data_integrity::sign(&Value::Object(cred), bystander_seed, &opts)
}

/// Verify a `BystanderConsentToken`: the bystander's proof, that the issuer is the
/// bystander, that the token is bound to this capture and this robot, and that it
/// is within its window at `now_iso` (a `None` clock skips the window check).
/// Returns the credentialSubject on success, `None` if invalid.
pub fn verify_consent_token(
    token: &Value,
    bystander_public_key: &[u8],
    capture_hash: &str,
    robot_did: &str,
    now_iso: Option<&str>,
) -> Result<Option<Value>> {
    let subject = match verify_typed(token, bystander_public_key, CONSENT_TOKEN_TYPE)? {
        Some(s) => s,
        None => return Ok(None),
    };
    if token.get("issuer") != subject.get("id") {
        return Ok(None);
    }
    if subject.get("captureHash").and_then(|v| v.as_str()) != Some(capture_hash)
        || subject.get("robotDid").and_then(|v| v.as_str()) != Some(robot_did)
    {
        return Ok(None);
    }
    if !lease_window_current(token, now_iso) {
        return Ok(None);
    }
    Ok(Some(subject))
}

/// Parameters for [`build_consent_evidence`]. The signer is the robot; the
/// evidence records that a capture (named by `capture_hash`) was permitted on
/// `basis`, one of [`CONSENT_BASES`]. `consent_tokens`, when the basis is explicit
/// consent, are the bystander tokens that cover it, committed by their proof value.
/// `redaction_hash`, when set, records that a redacted output was produced.
/// `valid_until`, when set, bounds the window.
#[derive(Debug, Clone)]
pub struct BuildConsentEvidence {
    pub robot_did: String,
    pub capture_hash: String,
    pub basis: String,
    pub consent_tokens: Vec<Value>,
    pub redaction_hash: Option<String>,
    pub valid_from: String,
    pub valid_until: Option<String>,
}

/// A privacy-preserving reference to a token: its proof value. Never embeds a
/// bystander's identifying data.
fn consent_token_ref(token: &Value) -> Result<String> {
    token
        .get("proof")
        .and_then(|p| p.get("proofValue"))
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| CoreError::Json("consent token is missing a proof value".into()))
}

/// Build a signed `BystanderConsentEvidence` credential: the robot records that a
/// capture (named by `capture_hash`) was permitted on `basis`, one of
/// [`CONSENT_BASES`]. When the basis is explicit consent, the `consent_tokens` are
/// the bystander tokens that cover it, and the evidence commits to them by their
/// proof value (never embedding a bystander's identifying data). Signed by the
/// robot.
pub fn build_consent_evidence(robot_seed: &[u8], params: &BuildConsentEvidence) -> Result<Value> {
    if params.robot_did.is_empty() || params.capture_hash.is_empty() {
        return Err(CoreError::Json(
            "robot_did and capture_hash are required".into(),
        ));
    }
    if !CONSENT_BASES.contains(&params.basis.as_str()) {
        return Err(CoreError::Json(format!(
            "basis must be one of {:?}, got {:?}",
            CONSENT_BASES, params.basis
        )));
    }
    if params.basis == "explicit-consent" && params.consent_tokens.is_empty() {
        return Err(CoreError::Json(
            "explicit-consent basis requires at least one consent token".into(),
        ));
    }

    let mut subject = Map::new();
    subject.insert("id".into(), json!(params.robot_did));
    subject.insert("captureHash".into(), json!(params.capture_hash));
    subject.insert("basis".into(), json!(params.basis));
    if !params.consent_tokens.is_empty() {
        let mut refs = Vec::with_capacity(params.consent_tokens.len());
        for t in &params.consent_tokens {
            refs.push(consent_token_ref(t)?);
        }
        subject.insert("consentTokenRefs".into(), json!(refs));
    }
    if let Some(rh) = &params.redaction_hash {
        subject.insert("redactionHash".into(), json!(rh));
    }

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert(
        "type".into(),
        json!(["VerifiableCredential", CONSENT_EVIDENCE_TYPE]),
    );
    cred.insert("issuer".into(), json!(params.robot_did));
    cred.insert("validFrom".into(), json!(params.valid_from));
    if let Some(vu) = &params.valid_until {
        cred.insert("validUntil".into(), json!(vu));
    }
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(format!("{}#key-1", params.robot_did), &params.valid_from);
    data_integrity::sign(&Value::Object(cred), robot_seed, &opts)
}

/// One bystander's public key, looked up by bystander DID, for
/// [`verify_consent_evidence`].
#[derive(Debug, Clone)]
pub struct BystanderKey {
    pub did: String,
    pub public_key: Vec<u8>,
}

/// Verify a `BystanderConsentEvidence` credential: the robot's proof, that the
/// issuer is the robot, and that the basis is accepted. When `capture` is supplied,
/// its hash must reproduce the attested capture hash. When `consent_tokens` and
/// `bystander_keys` are supplied, every token must verify, be bound to this capture
/// and this robot, and match a committed reference, and an explicit-consent
/// evidence must carry at least one token. Returns the credentialSubject on
/// success, `None` if invalid.
pub fn verify_consent_evidence(
    evidence: &Value,
    robot_public_key: &[u8],
    capture: Option<&[u8]>,
    consent_tokens: Option<&[Value]>,
    bystander_keys: Option<&[BystanderKey]>,
    now_iso: Option<&str>,
) -> Result<Option<Value>> {
    let subject = match verify_typed(evidence, robot_public_key, CONSENT_EVIDENCE_TYPE)? {
        Some(s) => s,
        None => return Ok(None),
    };
    if evidence.get("issuer") != subject.get("id") {
        return Ok(None);
    }
    let basis = subject.get("basis").and_then(|v| v.as_str());
    match basis {
        Some(b) if CONSENT_BASES.contains(&b) => {}
        _ => return Ok(None),
    }
    let capture_hash = match subject.get("captureHash").and_then(|v| v.as_str()) {
        Some(h) if !h.is_empty() => h,
        _ => return Ok(None),
    };

    if let Some(c) = capture {
        if hash_capture(c) != capture_hash {
            return Ok(None);
        }
    }

    let refs: HashSet<&str> = subject
        .get("consentTokenRefs")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|r| r.as_str()).collect())
        .unwrap_or_default();
    if basis == Some("explicit-consent") && refs.is_empty() {
        return Ok(None);
    }

    if let (Some(tokens), Some(keys)) = (consent_tokens, bystander_keys) {
        let robot_did = subject.get("id").and_then(|v| v.as_str()).unwrap_or("");
        for token in tokens {
            let issuer = token.get("issuer").and_then(|v| v.as_str());
            let key = match issuer.and_then(|i| keys.iter().find(|k| k.did == i)) {
                Some(k) => &k.public_key,
                None => return Ok(None),
            };
            let tok_ok =
                verify_consent_token(token, key, capture_hash, robot_did, now_iso)?.is_some();
            let committed = consent_token_ref(token)
                .map(|r| refs.contains(r.as_str()))
                .unwrap_or(false);
            if !tok_ok || !committed {
                return Ok(None);
            }
        }
    }

    Ok(Some(subject))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Ed25519KeyPair;
    use std::fs;

    fn load_vector() -> Value {
        let raw = fs::read_to_string("../../test-vectors/robotics/vector.json")
            .expect("interop vector present");
        serde_json::from_str(&raw).unwrap()
    }

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

    // Cross-language interop: this HalosSafetyEvidenceCredential, its black-box
    // entries, and the robot public key were produced by the Python reference
    // (vouch/robotics/halos.py) from a fixed Ed25519 seed (0x05 x32), a fixed
    // black-box key, and a fixed `created` timestamp. The Rust verify must accept
    // it, and must reject a tampered entry or a wrong entry count.
    const PY_HALOS_CREDENTIAL: &str = r#"{"@context":["https://www.w3.org/ns/credentials/v2","https://vouch-protocol.com/contexts/v1"],"type":["VerifiableCredential","HalosSafetyEvidenceCredential"],"issuer":"did:key:z6MkmtWtY63GQVBrpMyRJWEzsnxfsGkemu6CtMDwGTv4RYj2","validFrom":"2026-01-01T00:00:00Z","credentialSubject":{"id":"did:key:z6MkmtWtY63GQVBrpMyRJWEzsnxfsGkemu6CtMDwGTv4RYj2","blackboxHead":"utfv4sSWc6TH-n0HrNqB35Hacy3lYVksU0QYz6gbHol8","entryCount":3,"halosStack":{"igxSom":"IGX-Orin-64","halosCore":"1.4.0","blueprint":["SAIM","SEI","SDM"]},"window":{"from":"2026-01-01T00:00:00Z","to":"2026-01-01T00:00:10Z"},"robotIdentity":"urn:uuid:robot-identity-1"},"proof":{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2026-01-01T00:00:00Z","verificationMethod":"did:key:z6MkmtWtY63GQVBrpMyRJWEzsnxfsGkemu6CtMDwGTv4RYj2#key-1","proofPurpose":"assertionMethod","proofValue":"z5FjYsg9oQ543K8jtAsaYyYS3YG53ixoUYnhYop8oJWuLCoZp45uYos4416i13JR2bkt4tPtKB9hTk5xG9s8mQoQd"}}"#;

    const PY_HALOS_ENTRIES: &str = r#"[{"version":"1.0","seq":0,"timestamp":"2026-01-01T00:00:01Z","event":"hazard_detected","ciphertext":"uzhrB2FNU_UNfM5ey2Dx1ogaX4_IuPx-0ylXC7022a7TqQ5ktnB9GmFqmrv9VzRx7ecoSyCAC6b6pcp1r7K2nQLSsDnmX2oar","prevHash":"uAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","entryHash":"uZm_cIGAA1kuQio4QWWwbE27xBVZE9QSuvAGweybxZZk"},{"version":"1.0","seq":1,"timestamp":"2026-01-01T00:00:02Z","event":"slow_stop","ciphertext":"ulQY1i5OnYlWdSJOS0Rp4esqwLIyh_4TM4WO-apHKoJde3AgFaGHgPIZ2GIb8q5sYKjtB9Az6kUnajkhzYA7VPQ6ChvF_3yQGfHuIM1lnaF5JEg","prevHash":"uZm_cIGAA1kuQio4QWWwbE27xBVZE9QSuvAGweybxZZk","entryHash":"uPulCLvRvEs_zV1R3koher2EMjyBZy5Rfe-Sv0Y64Tfk"},{"version":"1.0","seq":2,"timestamp":"2026-01-01T00:00:03Z","event":"cleared","ciphertext":"us7pdRfPVAGSeKCQU7RgEb1ee_2358wbs_P4epd4gPJoUUx9bw3hJSiVPGKwc2Xc3PjZySEaWKgK_F0h5mU2sxb0pEZ-E_FwwQQk3","prevHash":"uPulCLvRvEs_zV1R3koher2EMjyBZy5Rfe-Sv0Y64Tfk","entryHash":"utfv4sSWc6TH-n0HrNqB35Hacy3lYVksU0QYz6gbHol8"}]"#;

    // Robot public key (raw 32-byte Ed25519) as base64url-no-pad.
    const PY_HALOS_ROBOT_PUB: &str = "bnoc3Smwt4_ROvTFWY_v9O8qlxZuPKby5Pv8zYBQW_E";

    #[test]
    fn build_verify_safety_evidence_roundtrip() {
        let robot_seed = [5u8; 32];
        let robot_kp = Ed25519KeyPair::from_seed(&robot_seed);

        // A black-box chain the robot recorded.
        let mut log = BlackBoxLog::new(&[9u8; 32], None).unwrap();
        log.append(
            "hazard_detected",
            &json!({"zone": "cell-3"}),
            "2026-01-01T00:00:01Z",
        )
        .unwrap();
        log.append(
            "slow_stop",
            &json!({"reason": "human"}),
            "2026-01-01T00:00:02Z",
        )
        .unwrap();
        let entries: Vec<Value> = log.entries().to_vec();

        let params = BuildSafetyEvidence {
            halos_stack: json!({"igxSom": "IGX-Orin-64", "halosCore": "1.4.0"}),
            window_from: "2026-01-01T00:00:00Z".into(),
            window_to: "2026-01-01T00:00:10Z".into(),
            blackbox_head: log.head().to_string(),
            entry_count: entries.len() as u64,
            robot_identity: Some("urn:uuid:robot-identity-1".into()),
            valid_seconds: Some(3600),
            valid_from: "2026-01-01T00:00:00Z".into(),
            created: "2026-01-01T00:00:00Z".into(),
        };
        let cred = build_safety_evidence(&robot_seed, &params).unwrap();

        // The issuer is the did:key derived from the seed and the validUntil is
        // rendered from the valid_seconds lifetime.
        assert_eq!(
            cred["issuer"],
            json!("did:key:z6MkmtWtY63GQVBrpMyRJWEzsnxfsGkemu6CtMDwGTv4RYj2")
        );
        assert_eq!(cred["validUntil"], json!("2026-01-01T01:00:00Z"));

        let (ok, subject) =
            verify_safety_evidence(&cred, &robot_kp.public_key(), Some(&entries)).unwrap();
        assert!(ok, "a Rust-built evidence credential must verify in Rust");
        assert_eq!(subject.unwrap()["entryCount"], json!(2));

        // A credential whose issuer is not the subject id is rejected.
        let mut forged = cred.clone();
        forged["issuer"] = json!("did:key:z6Mkother");
        let (ok_forged, _) = verify_safety_evidence(&forged, &robot_kp.public_key(), None).unwrap();
        assert!(!ok_forged, "issuer must equal credentialSubject.id");
    }

    #[test]
    fn verifies_python_halos_evidence() {
        let credential: Value = serde_json::from_str(PY_HALOS_CREDENTIAL).unwrap();
        let entries: Vec<Value> = serde_json::from_str(PY_HALOS_ENTRIES).unwrap();
        let robot_pub = URL_SAFE_NO_PAD.decode(PY_HALOS_ROBOT_PUB).unwrap();

        // The Python-produced credential and its entries verify in Rust.
        let (ok, subject) =
            verify_safety_evidence(&credential, &robot_pub, Some(&entries)).unwrap();
        assert!(ok, "the Python Halos evidence must verify in Rust");
        let subject = subject.expect("subject present on success");
        assert_eq!(subject["entryCount"], json!(3));
        assert_eq!(
            subject["blackboxHead"],
            json!("utfv4sSWc6TH-n0HrNqB35Hacy3lYVksU0QYz6gbHol8")
        );

        // The proof and issuer binding hold even without the entries.
        let (ok_no_entries, _) = verify_safety_evidence(&credential, &robot_pub, None).unwrap();
        assert!(
            ok_no_entries,
            "proof and issuer binding verify without entries"
        );

        // Tampering one entry breaks the chain, so verification fails.
        let mut tampered = entries.clone();
        tampered[1]["ciphertext"] = json!("utampered_ciphertext_value_that_does_not_match_hash");
        let (ok_tampered, subj_tampered) =
            verify_safety_evidence(&credential, &robot_pub, Some(&tampered)).unwrap();
        assert!(!ok_tampered, "a tampered entry must be rejected");
        assert!(subj_tampered.is_none());

        // A wrong entry count (here a truncated log) is rejected against the seal.
        let truncated = entries[..2].to_vec();
        let (ok_truncated, _) =
            verify_safety_evidence(&credential, &robot_pub, Some(&truncated)).unwrap();
        assert!(!ok_truncated, "a wrong entry count must be rejected");
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

    // Cross-language interop: Rust reproduces the exact configHash Python pinned.
    #[test]
    fn config_hash_matches_interop_vector() {
        let vector = load_vector();
        let got = config_hash(&vector["config"]);
        assert_eq!(got, vector["expected_config_hash"].as_str().unwrap());
        assert_eq!(got, "uMh9_H2Lk51-m9SpBhiEa1oqIwwwA7yT27e2QFS0YKUs");
    }

    #[test]
    fn provenance_roundtrip_and_config_tamper() {
        let seed = [4u8; 32];
        let kp = Ed25519KeyPair::from_seed(&seed);
        let config = load_vector()["config"].clone();
        let params = BuildProvenance {
            issuer_did: "did:web:robot.example.com".into(),
            robot_did: "did:web:robot.example.com".into(),
            model_name: "openvla-7b".into(),
            weights_hash: "uABCDEF".into(),
            safety_policy: "did:web:authority.example.com#policy-v3".into(),
            config: Some(config.clone()),
            version: Some("2026.06".into()),
            supersedes: None,
            valid_from: "2026-01-01T00:00:00Z".into(),
            valid_until: None,
        };
        let att = build_provenance_attestation(&seed, &params).unwrap();
        assert!(
            verify_provenance_attestation(&att, &kp.public_key(), Some(&config))
                .unwrap()
                .is_some()
        );
        // A different config than the one signed must be rejected.
        let tampered = json!({"temperature": 1.0, "max_torque": 99.0});
        assert!(
            verify_provenance_attestation(&att, &kp.public_key(), Some(&tampered))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn capability_build_check_attenuate() {
        let seed = [6u8; 32];
        let kp = Ed25519KeyPair::from_seed(&seed);
        let params = BuildPhysicalScope {
            issuer_did: "did:web:fleet.example.com".into(),
            subject_did: "did:web:robot.example.com".into(),
            max_force_n: Some(80.0),
            max_speed_mps: Some(2.0),
            max_speed_near_humans_mps: Some(0.5),
            allowed_zones: Some(vec!["warehouse-a".into(), "dock-3".into()]),
            shift_windows: Some(vec![ShiftWindow {
                start: "08:00".into(),
                end: "18:00".into(),
            }]),
            valid_from: "2026-01-01T00:00:00Z".into(),
            valid_until: None,
        };
        let cred = build_physical_scope_credential(&seed, &params).unwrap();
        assert!(has_type(cred.get("type"), PHYSICAL_SCOPE_TYPE));
        assert!(data_integrity::verify_proof(&cred, &kp.public_key()).unwrap());

        let scope = cred["credentialSubject"]["physicalScope"].clone();
        let within = check_physical_action(
            &scope,
            &PhysicalAction {
                force_n: Some(50.0),
                speed_mps: Some(1.5),
                zone: Some("warehouse-a".into()),
                time_hm: Some("09:30".into()),
                ..Default::default()
            },
        );
        assert!(within.ok, "within-scope action: {:?}", within.reasons);
        assert!(
            !check_physical_action(
                &scope,
                &PhysicalAction {
                    force_n: Some(120.0),
                    ..Default::default()
                }
            )
            .ok
        );
        // Near humans the 0.5 m/s cap applies; 1.5 is fine away from them.
        assert!(
            !check_physical_action(
                &scope,
                &PhysicalAction {
                    speed_mps: Some(1.5),
                    near_humans: true,
                    ..Default::default()
                }
            )
            .ok
        );
        assert!(
            check_physical_action(
                &scope,
                &PhysicalAction {
                    speed_mps: Some(1.5),
                    near_humans: false,
                    ..Default::default()
                }
            )
            .ok
        );
        assert!(
            !check_physical_action(
                &scope,
                &PhysicalAction {
                    zone: Some("loading-bay-9".into()),
                    ..Default::default()
                }
            )
            .ok
        );
        assert!(
            !check_physical_action(
                &scope,
                &PhysicalAction {
                    time_hm: Some("23:00".into()),
                    ..Default::default()
                }
            )
            .ok
        );
    }

    #[test]
    fn attenuation_rules() {
        let parent = json!({
            "maxForceN": 80.0, "maxSpeedMps": 2.0, "maxSpeedNearHumansMps": 0.5,
            "allowedZones": ["warehouse-a", "dock-3"],
            "shiftWindows": [{"start": "08:00", "end": "18:00"}]
        });
        let narrower = json!({
            "maxForceN": 50.0, "maxSpeedMps": 1.0, "maxSpeedNearHumansMps": 0.3,
            "allowedZones": ["warehouse-a"],
            "shiftWindows": [{"start": "09:00", "end": "17:00"}]
        });
        assert!(attenuates(&parent, &narrower));
        assert!(!attenuates(
            &parent,
            &json!({"maxForceN": 100.0, "maxSpeedMps": 1.0, "maxSpeedNearHumansMps": 0.3, "allowedZones": ["warehouse-a"]})
        ));
        assert!(!attenuates(
            &parent,
            &json!({"maxForceN": 50.0, "allowedZones": ["warehouse-a"]})
        ));
        assert!(!attenuates(
            &parent,
            &json!({"maxForceN": 50.0, "maxSpeedMps": 1.0, "maxSpeedNearHumansMps": 0.3, "allowedZones": ["loading-bay-9"]})
        ));
        assert!(!attenuates(
            &parent,
            &json!({"maxForceN": 50.0, "maxSpeedMps": 1.0, "maxSpeedNearHumansMps": 0.3, "allowedZones": ["warehouse-a"], "shiftWindows": [{"start": "06:00", "end": "20:00"}]})
        ));
    }

    #[test]
    fn handshake_full_flow() {
        let a_seed = [11u8; 32];
        let b_seed = [12u8; 32];
        let a = Ed25519KeyPair::from_seed(&a_seed);
        let b = Ed25519KeyPair::from_seed(&b_seed);
        let a_did = "did:web:robot-a.example.com";
        let b_did = "did:web:robot-b.example.com";
        let policy_b = TrustPolicy::new(["robot-a.example.com".to_string()], false);

        let hello = build_hello(
            &a_seed,
            &BuildHello {
                from_did: a_did.into(),
                proposed_scope: vec!["lift".into(), "carry".into(), "scan".into()],
                nonce: "abc123".into(),
                peer_did: Some(b_did.into()),
                issued_at: "2026-01-01T00:00:00Z".into(),
            },
        )
        .unwrap();

        let accept = build_accept(
            &b_seed,
            &hello,
            &a.public_key(),
            &policy_b,
            &BuildAccept {
                from_did: b_did.into(),
                offered_scope: vec!["carry".into(), "scan".into(), "weld".into()],
                session_id: "urn:uuid:sess-1".into(),
                valid_until: "2026-01-01T00:05:00Z".into(),
                created: "2026-01-01T00:00:01Z".into(),
            },
        )
        .unwrap();

        let session = verify_accept(&accept, &b.public_key(), "abc123", None)
            .unwrap()
            .expect("accept verifies");
        assert_eq!(session.scope, vec!["carry".to_string(), "scan".to_string()]);
        assert_eq!(session.initiator, a_did);
        assert_eq!(session.responder, b_did);

        let confirm = build_confirm(&a_seed, a_did, &session, "2026-01-01T00:00:02Z").unwrap();
        assert!(verify_confirm(&confirm, &a.public_key(), &session.session_id, "abc123").unwrap());
    }

    #[test]
    fn handshake_untrusted_tamper_and_nonce() {
        let a_seed = [11u8; 32];
        let b_seed = [12u8; 32];
        let a = Ed25519KeyPair::from_seed(&a_seed);
        let b = Ed25519KeyPair::from_seed(&b_seed);
        let a_did = "did:web:robot-a.example.com";
        let b_did = "did:web:robot-b.example.com";

        let hello = build_hello(
            &a_seed,
            &BuildHello {
                from_did: a_did.into(),
                proposed_scope: vec!["lift".into()],
                nonce: "n1".into(),
                peer_did: None,
                issued_at: "2026-01-01T00:00:00Z".into(),
            },
        )
        .unwrap();

        // Untrusted initiator.
        let strict = TrustPolicy::new(["someone-else.example.com".to_string()], false);
        assert!(build_accept(
            &b_seed,
            &hello,
            &a.public_key(),
            &strict,
            &BuildAccept {
                from_did: b_did.into(),
                offered_scope: vec!["lift".into()],
                session_id: "s".into(),
                valid_until: "2026-01-01T00:05:00Z".into(),
                created: "2026-01-01T00:00:01Z".into(),
            },
        )
        .is_err());

        // Tampered HELLO (scope broadened after signing) fails signature check.
        let open = TrustPolicy::new(Vec::<String>::new(), true);
        let mut tampered = hello.clone();
        tampered["proposedScope"] = json!(["lift", "weld"]);
        assert!(build_accept(
            &b_seed,
            &tampered,
            &a.public_key(),
            &open,
            &BuildAccept {
                from_did: b_did.into(),
                offered_scope: vec!["lift".into(), "weld".into()],
                session_id: "s".into(),
                valid_until: "2026-01-01T00:05:00Z".into(),
                created: "2026-01-01T00:00:01Z".into(),
            },
        )
        .is_err());

        // Nonce mismatch on a valid ACCEPT.
        let accept = build_accept(
            &b_seed,
            &hello,
            &a.public_key(),
            &open,
            &BuildAccept {
                from_did: b_did.into(),
                offered_scope: vec!["lift".into()],
                session_id: "s".into(),
                valid_until: "2026-01-01T00:05:00Z".into(),
                created: "2026-01-01T00:00:01Z".into(),
            },
        )
        .unwrap();
        assert!(verify_accept(&accept, &b.public_key(), "wrong-nonce", None)
            .unwrap()
            .is_none());
    }

    #[test]
    fn did_web_domain_parsing() {
        assert_eq!(did_web_domain("did:web:example.com"), Some("example.com"));
        assert_eq!(
            did_web_domain("did:web:robot.example.com:agent"),
            Some("robot.example.com")
        );
        assert_eq!(did_web_domain("did:key:z6Mk"), None);
    }

    #[test]
    fn blackbox_append_open_and_chain() {
        let key = [0x11u8; 32];
        let mut log = BlackBoxLog::new(&key, None).unwrap();
        let e0 = log
            .append(
                "motion",
                &json!({"speed": 1.5, "joint": "elbow"}),
                "2026-01-01T00:00:00Z",
            )
            .unwrap();
        log.append("stop", &json!({"reason": "human"}), "2026-01-01T00:00:01Z")
            .unwrap();

        // Round-trip decrypt.
        let opened = log.open(&e0).unwrap();
        assert_eq!(opened["joint"], json!("elbow"));

        // Chain verifies, in memory and after a JSON round trip.
        assert!(verify_blackbox_chain(log.entries(), None).ok);
        let wire: Vec<Value> =
            serde_json::from_str(&serde_json::to_string(log.entries()).unwrap()).unwrap();
        assert!(verify_blackbox_chain(&wire, None).ok);
        assert_eq!(open_entry(&wire[0], &key).unwrap()["joint"], json!("elbow"));

        // Tamper detection.
        let mut tampered = wire.clone();
        tampered[1]["event"] = json!("tampered");
        assert!(!verify_blackbox_chain(&tampered, None).ok);

        // Wrong key fails decryption; bad key length rejected.
        assert!(open_entry(&e0, &[0x22u8; 32]).is_err());
        assert!(BlackBoxLog::new(&[0u8; 16], None).is_err());

        // Genesis constant matches the multibase of 32 zero bytes.
        assert_eq!(genesis_prev_hash(), format!("u{}", "A".repeat(43)));
    }

    #[test]
    fn killswitch_build_verify_and_trust() {
        let seed = [13u8; 32];
        let kp = Ed25519KeyPair::from_seed(&seed);
        let cred = build_killswitch_credential(
            &seed,
            &BuildKillswitch {
                issuer_did: "did:web:safety.example.com".into(),
                target: "did:web:robot.example.com".into(),
                reason: "human in path".into(),
                command: None,
                scope: Some(vec!["arm".into(), "drive".into()]),
                valid_from: "2026-01-01T00:00:00Z".into(),
                valid_until: None,
            },
        )
        .unwrap();

        let mut trusted = HashSet::new();
        trusted.insert("did:web:safety.example.com".to_string());
        let subject = verify_killswitch_credential(&cred, &kp.public_key(), Some(&trusted))
            .unwrap()
            .expect("trusted authority verifies");
        assert_eq!(subject["command"], json!(EMERGENCY_STOP));

        // Untrusted issuer rejected though the signature is valid.
        let mut other = HashSet::new();
        other.insert("did:web:someone-else.example.com".to_string());
        assert!(
            verify_killswitch_credential(&cred, &kp.public_key(), Some(&other))
                .unwrap()
                .is_none()
        );

        // Wrong type rejected.
        let mut wrong = cred.clone();
        wrong["type"] = json!(["VerifiableCredential"]);
        assert!(verify_killswitch_credential(&wrong, &kp.public_key(), None)
            .unwrap()
            .is_none());
    }

    #[test]
    fn passport_build_encode_verify() {
        let seed = [14u8; 32];
        let kp = Ed25519KeyPair::from_seed(&seed);
        let did = "did:web:robot.example.com";
        let pass = build_passport(
            &seed,
            &BuildPassport {
                issuer_did: did.into(),
                robot_did: did.into(),
                make: "Acme Robotics".into(),
                model: "AR-7".into(),
                owner: "did:web:owner.example.com".into(),
                authorized_actions: vec!["lift".into(), "carry".into()],
                certification: Some("ISO-10218".into()),
                status: None,
                valid_from: "2026-01-01T00:00:00Z".into(),
                valid_until: None,
            },
        )
        .unwrap();

        // Direct verify.
        let subject = verify_passport(&pass, &kp.public_key(), "2026-06-01T00:00:00Z")
            .unwrap()
            .expect("passport verifies");
        assert_eq!(subject["owner"], json!("did:web:owner.example.com"));
        assert_eq!(subject["status"], json!(STATUS_ACTIVE));

        // Encode to a URI, decode, and verify the offline-scan path.
        let uri = encode_passport(&pass);
        assert!(uri.starts_with("vouch-passport:u"));
        let decoded = decode_passport(&uri).unwrap();
        assert!(
            verify_passport(&decoded, &kp.public_key(), "2026-06-01T00:00:00Z")
                .unwrap()
                .is_some()
        );
        assert!(
            verify_passport_uri(&uri, &kp.public_key(), "2026-06-01T00:00:00Z")
                .unwrap()
                .is_some()
        );

        // Tamper and wrong type rejected.
        let mut tampered = pass.clone();
        tampered["credentialSubject"]["owner"] = json!("did:web:attacker.example.com");
        assert!(
            verify_passport(&tampered, &kp.public_key(), "2026-06-01T00:00:00Z")
                .unwrap()
                .is_none()
        );

        // Malformed URI.
        assert!(decode_passport("https://example.com/x").is_err());
    }

    #[test]
    fn passport_expiry_and_suspended() {
        let seed = [15u8; 32];
        let kp = Ed25519KeyPair::from_seed(&seed);
        let did = "did:web:robot.example.com";

        // Expiry: valid inside the window, expired past validUntil.
        let timed = build_passport(
            &seed,
            &BuildPassport {
                issuer_did: did.into(),
                robot_did: did.into(),
                make: "Acme".into(),
                model: "AR-7".into(),
                owner: "did:web:owner.example.com".into(),
                authorized_actions: vec!["lift".into()],
                certification: None,
                status: None,
                valid_from: "2026-01-01T00:00:00Z".into(),
                valid_until: Some("2026-01-01T00:01:00Z".into()),
            },
        )
        .unwrap();
        assert!(
            verify_passport(&timed, &kp.public_key(), "2026-01-01T00:00:30Z")
                .unwrap()
                .is_some()
        );
        assert!(
            verify_passport(&timed, &kp.public_key(), "2026-01-01T00:02:00Z")
                .unwrap()
                .is_none()
        );

        // Suspended still verifies but the status is surfaced.
        let suspended = build_passport(
            &seed,
            &BuildPassport {
                issuer_did: did.into(),
                robot_did: did.into(),
                make: "Acme".into(),
                model: "AR-7".into(),
                owner: "did:web:owner.example.com".into(),
                authorized_actions: vec!["lift".into()],
                certification: None,
                status: Some(STATUS_SUSPENDED.into()),
                valid_from: "2026-01-01T00:00:00Z".into(),
                valid_until: None,
            },
        )
        .unwrap();
        let subject = verify_passport(&suspended, &kp.public_key(), "2026-06-01T00:00:00Z")
            .unwrap()
            .expect("a suspended passport still verifies");
        assert_eq!(subject["status"], json!(STATUS_SUSPENDED));
    }

    // Cross-language interop: Rust reproduces the exact motion digest Python
    // pinned from the same fixed samples against the same physical scope.
    #[test]
    fn motion_digest_matches_interop_vector() {
        let vector = load_vector();
        let scope = vector["physical_scope"].clone();
        let mut collector = MotionCollector::new(Some(scope));
        collector
            .record(&MotionSample {
                force_n: Some(12.0),
                speed_mps: Some(0.4),
                near_humans: false,
                zone: Some("cell-3".into()),
                time_hm: None,
            })
            .unwrap();
        collector
            .record(&MotionSample {
                force_n: Some(20.0),
                speed_mps: Some(0.2),
                near_humans: true,
                zone: Some("cell-3".into()),
                time_hm: None,
            })
            .unwrap();
        assert_eq!(collector.digest(), vector["expected_motion_digest"]);
    }

    #[test]
    fn heartbeat_build_verify_and_liveness() {
        let seed = [21u8; 32];
        let kp = Ed25519KeyPair::from_seed(&seed);
        let did = "did:web:robot.example.com";
        let digest = json!({
            "samples": 2, "maxForceN": 20.0, "maxSpeedMps": 0.4,
            "maxSpeedNearHumansMps": 0.2, "zoneBreaches": 0, "breachCount": 0,
            "withinEnvelope": true
        });
        let hb = build_robot_heartbeat(
            &seed,
            &BuildRobotHeartbeat {
                robot_did: did.into(),
                session_id: "urn:uuid:sess-1".into(),
                interval_index: 0,
                interval_seconds: 60,
                motion_digest: digest,
                valid_from: "2026-01-01T00:00:00Z".into(),
            },
        )
        .unwrap();

        let subject = verify_robot_heartbeat(&hb, &kp.public_key())
            .unwrap()
            .expect("heartbeat verifies");
        assert_eq!(subject["sessionId"], json!("urn:uuid:sess-1"));

        // Fresh and in-envelope: live. Stale: not live.
        assert!(is_live(&hb, "2026-01-01T00:01:00Z", None, DEFAULT_GRACE_INTERVALS).unwrap());
        assert!(!is_live(&hb, "2026-01-01T01:00:00Z", None, DEFAULT_GRACE_INTERVALS).unwrap());

        // Out-of-envelope heartbeat is never live, even when fresh.
        let breached = json!({
            "samples": 1, "maxForceN": 99.0, "maxSpeedMps": 0.4,
            "maxSpeedNearHumansMps": 0.2, "zoneBreaches": 0, "breachCount": 1,
            "withinEnvelope": false
        });
        let hb2 = build_robot_heartbeat(
            &seed,
            &BuildRobotHeartbeat {
                robot_did: did.into(),
                session_id: "s".into(),
                interval_index: 1,
                interval_seconds: 60,
                motion_digest: breached,
                valid_from: "2026-01-01T00:00:00Z".into(),
            },
        )
        .unwrap();
        assert!(!is_live(&hb2, "2026-01-01T00:00:30Z", None, DEFAULT_GRACE_INTERVALS).unwrap());

        // Tamper and wrong type rejected.
        let mut tampered = hb.clone();
        tampered["credentialSubject"]["sessionId"] = json!("urn:uuid:other");
        assert!(verify_robot_heartbeat(&tampered, &kp.public_key())
            .unwrap()
            .is_none());
    }

    // Cross-language interop: Rust reproduces the exact hash-linked ledger and
    // the summary Python pinned from the same fixed events and timestamps.
    #[test]
    fn safety_log_matches_interop_vector() {
        let vector = load_vector();
        let mut log = SafetyEventLog::new(None);
        log.append(
            "near_miss",
            "low",
            Some(&json!({"zone": "cell-3"})),
            None,
            "2026-01-01T00:00:00Z",
        )
        .unwrap();
        log.append(
            "envelope_breach",
            "high",
            None,
            None,
            "2026-01-01T00:01:00Z",
        )
        .unwrap();

        assert_eq!(
            Value::Array(log.entries().to_vec()),
            vector["safety_log_entries"]
        );
        assert_eq!(
            log.head(),
            vector["expected_safety_log_head"].as_str().unwrap()
        );
        assert_eq!(log.summarize(), vector["expected_safety_summary"]);
        assert!(verify_safety_log(log.entries(), None).ok);
    }

    #[test]
    fn safety_record_build_verify_and_tamper() {
        let seed = [22u8; 32];
        let kp = Ed25519KeyPair::from_seed(&seed);
        let mut log = SafetyEventLog::new(None);
        log.append("near_miss", "low", None, None, "2026-01-01T00:00:00Z")
            .unwrap();
        let summary = log.summarize();

        let record = build_safety_record(
            &seed,
            &BuildSafetyRecord {
                issuer_did: "did:web:owner.example.com".into(),
                robot_did: "did:web:robot.example.com".into(),
                summary,
                period_start: Some("2026-01-01T00:00:00Z".into()),
                period_end: Some("2026-01-31T00:00:00Z".into()),
                valid_from: "2026-02-01T00:00:00Z".into(),
                valid_until: None,
            },
        )
        .unwrap();

        let subject = verify_safety_record(&record, &kp.public_key())
            .unwrap()
            .expect("safety record verifies");
        assert_eq!(subject["totalEvents"], json!(1));
        assert_eq!(subject["period"]["start"], json!("2026-01-01T00:00:00Z"));

        let mut tampered = record.clone();
        tampered["credentialSubject"]["totalEvents"] = json!(99);
        assert!(verify_safety_record(&tampered, &kp.public_key())
            .unwrap()
            .is_none());

        // Tamper detection in the ledger itself.
        let mut entries = log.entries().to_vec();
        entries[0]["severity"] = json!("critical");
        assert!(!verify_safety_log(&entries, None).ok);
    }

    // Cross-language interop: Rust reproduces the exact credentialStatus entry.
    #[test]
    fn status_entry_matches_interop_vector() {
        let vector = load_vector();
        let entry = build_status_list_entry(
            "https://fleet.example.com/status/1",
            42,
            STATUS_PURPOSE_REVOCATION,
            None,
        )
        .unwrap();
        assert_eq!(entry, vector["expected_credential_status_entry"]);
    }

    #[test]
    fn attach_and_check_credential_status() {
        let seed = [23u8; 32];
        let kp = Ed25519KeyPair::from_seed(&seed);
        let did = "did:web:robot.example.com";

        // Mint a passport, then attach a revocation status and re-sign.
        let pass = build_passport(
            &seed,
            &BuildPassport {
                issuer_did: did.into(),
                robot_did: did.into(),
                make: "Acme".into(),
                model: "AR-7".into(),
                owner: "did:web:owner.example.com".into(),
                authorized_actions: vec!["lift".into()],
                certification: None,
                status: None,
                valid_from: "2026-01-01T00:00:00Z".into(),
                valid_until: None,
            },
        )
        .unwrap();

        let with_status = attach_credential_status(
            &pass,
            &seed,
            &AttachCredentialStatus {
                status_list_credential: "https://fleet.example.com/status/1".into(),
                status_list_index: 42,
                status_purpose: STATUS_PURPOSE_REVOCATION.into(),
                entry_id: None,
                created: "2026-01-01T00:00:00Z".into(),
            },
        )
        .unwrap();

        // The re-signed credential still verifies and now carries the entry.
        assert!(data_integrity::verify_proof(&with_status, &kp.public_key()).unwrap());
        assert_eq!(
            with_status["credentialStatus"]["statusListIndex"],
            json!("42")
        );

        // Build a status list with bit 42 set, then check the entry resolves.
        let mut bits = vec![0u8; crate::status_list::DEFAULT_BITSTRING_LENGTH / 8];
        crate::status_list::set_status(&mut bits, 42, true).unwrap();
        let encoded = crate::status_list::encode_bitstring(&bits).unwrap();
        let status_list = json!({
            "id": "https://fleet.example.com/status/1",
            "type": ["VerifiableCredential", "BitstringStatusListCredential"],
            "credentialSubject": {
                "type": "BitstringStatusList",
                "statusPurpose": "revocation",
                "encodedList": encoded,
            }
        });
        assert!(
            check_credential_status(&with_status, &status_list, STATUS_PURPOSE_REVOCATION).unwrap()
        );

        // A credential with no status entry is not revoked.
        assert!(!check_credential_status(&pass, &status_list, STATUS_PURPOSE_REVOCATION).unwrap());

        // A list with the bit clear reports not-revoked.
        let clear_bits = vec![0u8; crate::status_list::DEFAULT_BITSTRING_LENGTH / 8];
        let clear_encoded = crate::status_list::encode_bitstring(&clear_bits).unwrap();
        let mut clear_list = status_list.clone();
        clear_list["credentialSubject"]["encodedList"] = json!(clear_encoded);
        assert!(
            !check_credential_status(&with_status, &clear_list, STATUS_PURPOSE_REVOCATION).unwrap()
        );
    }

    // Cross-language interop: Rust reproduces the exact frame hash Python pinned.
    #[test]
    fn frame_hash_matches_interop_vector() {
        let vector = load_vector();
        let sample_frame: Vec<u8> = (0u8..64).collect();
        let got = hash_frame(&sample_frame);
        assert_eq!(got, vector["expected_frame_hash"].as_str().unwrap());
        assert_eq!(got, "u_eq5rPNxA2K9JljNyaKej5x1f8-YEWA6jER80dkVEQg");
    }

    // Cross-language interop: Rust reproduces the exact hash-linked perception log
    // Python pinned from the same fixed frames and timestamps.
    #[test]
    fn perception_log_matches_interop_vector() {
        let vector = load_vector();
        let sample_frame: Vec<u8> = (0u8..64).collect();
        let mut log = PerceptionLog::new(None);
        log.record(
            "cam-front",
            "camera",
            Some(&sample_frame),
            None,
            "2026-01-01T00:00:00Z",
        )
        .unwrap();
        log.record(
            "lidar-top",
            "lidar",
            None,
            Some(&hash_frame(b"scan-0")),
            "2026-01-01T00:00:01Z",
        )
        .unwrap();

        assert_eq!(
            Value::Array(log.entries().to_vec()),
            vector["perception_log_entries"]
        );
        assert_eq!(
            log.head(),
            vector["expected_perception_log_head"].as_str().unwrap()
        );
        assert!(verify_perception_log(log.entries(), None).ok);
    }

    #[test]
    fn perception_record_validation_and_tamper() {
        let mut log = PerceptionLog::new(None);
        // Unknown modality rejected.
        assert!(log
            .record("cam", "sonar", Some(b"x"), None, "2026-01-01T00:00:00Z")
            .is_err());
        // Both frame and frame_hash rejected.
        assert!(log
            .record(
                "cam",
                "camera",
                Some(b"x"),
                Some("uABC"),
                "2026-01-01T00:00:00Z"
            )
            .is_err());
        // Neither frame nor frame_hash rejected.
        assert!(log
            .record("cam", "camera", None, None, "2026-01-01T00:00:00Z")
            .is_err());
        // Empty sensor id rejected.
        assert!(log
            .record("", "camera", Some(b"x"), None, "2026-01-01T00:00:00Z")
            .is_err());

        log.record(
            "cam",
            "camera",
            Some(b"frame-0"),
            None,
            "2026-01-01T00:00:00Z",
        )
        .unwrap();
        log.record(
            "cam",
            "camera",
            Some(b"frame-1"),
            None,
            "2026-01-01T00:00:01Z",
        )
        .unwrap();
        assert!(verify_perception_log(log.entries(), None).ok);

        // Tamper detection in the chain.
        let mut entries = log.entries().to_vec();
        entries[0]["frameHash"] = json!("uTAMPERED");
        assert!(!verify_perception_log(&entries, None).ok);
    }

    #[test]
    fn perception_attestation_build_verify_and_tamper() {
        let seed = [24u8; 32];
        let kp = Ed25519KeyPair::from_seed(&seed);
        let did = "did:web:robot.example.com";
        let frame = b"sensor-frame-bytes";
        let frame_hash = hash_frame(frame);

        let cred = build_perception_attestation(
            &seed,
            &BuildPerception {
                robot_did: did.into(),
                sensor_id: "cam-front".into(),
                modality: "camera".into(),
                frame_hash: frame_hash.clone(),
                captured_at: Some("2026-01-01T00:00:00Z".into()),
                log_head: Some("uHEAD".into()),
                valid_from: "2026-01-01T00:00:00Z".into(),
                valid_until: None,
            },
        )
        .unwrap();

        // Verify the proof and the embedded provenance, and recompute the frame.
        let subject = verify_perception_attestation(&cred, &kp.public_key(), Some(frame))
            .unwrap()
            .expect("perception attestation verifies");
        assert_eq!(subject["sensorId"], json!("cam-front"));
        assert_eq!(subject["frameHash"], json!(frame_hash));
        assert_eq!(subject["logHead"], json!("uHEAD"));

        // Verify without the raw frame still passes (proof only).
        assert!(verify_perception_attestation(&cred, &kp.public_key(), None)
            .unwrap()
            .is_some());

        // A different frame than the one attested is rejected.
        assert!(
            verify_perception_attestation(&cred, &kp.public_key(), Some(b"other-frame"))
                .unwrap()
                .is_none()
        );

        // Tampered subject fails the proof.
        let mut tampered = cred.clone();
        tampered["credentialSubject"]["sensorId"] = json!("cam-rear");
        assert!(
            verify_perception_attestation(&tampered, &kp.public_key(), None)
                .unwrap()
                .is_none()
        );

        // Wrong type rejected.
        let mut wrong = cred.clone();
        wrong["type"] = json!(["VerifiableCredential"]);
        assert!(
            verify_perception_attestation(&wrong, &kp.public_key(), None)
                .unwrap()
                .is_none()
        );

        // Bad modality and missing frame_hash rejected at build time.
        assert!(build_perception_attestation(
            &seed,
            &BuildPerception {
                robot_did: did.into(),
                sensor_id: "s".into(),
                modality: "sonar".into(),
                frame_hash: frame_hash.clone(),
                captured_at: None,
                log_head: None,
                valid_from: "2026-01-01T00:00:00Z".into(),
                valid_until: None,
            },
        )
        .is_err());
        assert!(build_perception_attestation(
            &seed,
            &BuildPerception {
                robot_did: did.into(),
                sensor_id: "s".into(),
                modality: "camera".into(),
                frame_hash: String::new(),
                captured_at: None,
                log_head: None,
                valid_from: "2026-01-01T00:00:00Z".into(),
                valid_until: None,
            },
        )
        .is_err());
    }

    fn jwk_pub(jwk: &Value) -> Vec<u8> {
        URL_SAFE_NO_PAD
            .decode(jwk["x"].as_str().unwrap())
            .expect("base64url JWK x")
    }

    // Cross-language interop: Go and TypeScript verify this same Python-signed
    // delegation lease; the Rust core must too.
    #[test]
    fn verifies_python_lease_interop_vector() {
        let vector = load_vector();
        let robot_pub = jwk_pub(&vector["robot_public_key_jwk"]);
        let lease = vector["delegation_lease_credential"].clone();

        let subject = verify_delegation_lease(&lease, &robot_pub, None, None)
            .unwrap()
            .expect("the Python lease interop vector must verify in Rust");
        assert_eq!(subject["leaseId"], json!("lease-vector-1"));
    }

    // Cross-language interop: Rust authorizes the Python-signed quorum with the
    // same two approver keys and a threshold of 2.
    #[test]
    fn verifies_python_quorum_interop_vector() {
        let vector = load_vector();
        let approvals = vector["quorum_approvals"].as_array().unwrap().clone();
        let action_id = vector["quorum_action_id"].as_str().unwrap();
        let keys: Vec<ApproverKey> = vector["quorum_approver_keys"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(did, jwk)| ApproverKey {
                did: did.clone(),
                public_key: jwk_pub(jwk),
            })
            .collect();

        let (ok, approvers) = verify_action_authorization(
            &approvals,
            action_id,
            "did:web:robot.example.com",
            &keys,
            2,
            None,
            None,
        )
        .unwrap();
        assert!(
            ok,
            "the Python quorum interop vector must authorize in Rust"
        );
        assert_eq!(approvers.len(), 2);
        assert_eq!(approvers[0], "did:web:approver-1.example.com");
        assert_eq!(approvers[1], "did:web:approver-2.example.com");
    }

    #[test]
    fn lease_build_verify_permits_and_expiry() {
        let seed = [31u8; 32];
        let kp = Ed25519KeyPair::from_seed(&seed);
        let did = "did:web:robot.example.com";
        let scope = json!({
            "maxForceN": 80.0, "maxSpeedMps": 2.0, "maxSpeedNearHumansMps": 0.5,
            "allowedZones": ["warehouse-a", "dock-3"]
        });
        let lease = build_delegation_lease(
            &seed,
            &BuildDelegationLease {
                issuer_did: did.into(),
                robot_did: did.into(),
                lease_id: "lease-1".into(),
                scope: scope.clone(),
                parent_lease_id: None,
                valid_from: "2026-01-01T00:00:00Z".into(),
                valid_until: "2026-01-01T01:00:00Z".into(),
            },
        )
        .unwrap();

        // Round-trip verify, in-window.
        let subject =
            verify_delegation_lease(&lease, &kp.public_key(), Some("2026-01-01T00:30:00Z"), None)
                .unwrap()
                .expect("lease verifies in window");
        assert_eq!(subject["leaseId"], json!("lease-1"));

        // Permits a within-scope action, denies an out-of-scope one.
        assert!(lease_permits(
            &subject,
            &PhysicalAction {
                force_n: Some(50.0),
                zone: Some("warehouse-a".into()),
                ..Default::default()
            },
            Some(&lease),
            Some("2026-01-01T00:30:00Z"),
        ));
        assert!(!lease_permits(
            &subject,
            &PhysicalAction {
                force_n: Some(120.0),
                ..Default::default()
            },
            Some(&lease),
            Some("2026-01-01T00:30:00Z"),
        ));

        // Expired window: verify fails and the lease no longer permits.
        assert!(verify_delegation_lease(
            &lease,
            &kp.public_key(),
            Some("2026-01-01T02:00:00Z"),
            None,
        )
        .unwrap()
        .is_none());
        assert!(!lease_permits(
            &subject,
            &PhysicalAction {
                force_n: Some(50.0),
                ..Default::default()
            },
            Some(&lease),
            Some("2026-01-01T02:00:00Z"),
        ));

        // Tamper and wrong type rejected.
        let mut tampered = lease.clone();
        tampered["credentialSubject"]["leaseId"] = json!("lease-other");
        assert!(
            verify_delegation_lease(&tampered, &kp.public_key(), None, None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn lease_sub_grant_attenuation() {
        let parent_seed = [32u8; 32];
        let child_seed = [33u8; 32];
        let parent_kp = Ed25519KeyPair::from_seed(&parent_seed);
        let child_kp = Ed25519KeyPair::from_seed(&child_seed);
        let parent_scope = json!({
            "maxForceN": 80.0, "maxSpeedMps": 2.0,
            "allowedZones": ["warehouse-a", "dock-3"]
        });

        // A narrower sub-lease attenuates the parent: accepted.
        let narrower = build_delegation_lease(
            &child_seed,
            &BuildDelegationLease {
                issuer_did: "did:web:integrator.example.com".into(),
                robot_did: "did:web:robot.example.com".into(),
                lease_id: "lease-2".into(),
                scope: json!({
                    "maxForceN": 50.0, "maxSpeedMps": 1.0,
                    "allowedZones": ["warehouse-a"]
                }),
                parent_lease_id: Some("lease-1".into()),
                valid_from: "2026-01-01T00:00:00Z".into(),
                valid_until: "2026-01-01T01:00:00Z".into(),
            },
        )
        .unwrap();
        assert!(verify_delegation_lease(
            &narrower,
            &child_kp.public_key(),
            None,
            Some(&parent_scope),
        )
        .unwrap()
        .is_some());

        // A widening sub-lease (force above the parent) is rejected against the
        // parent scope.
        let wider = build_delegation_lease(
            &parent_seed,
            &BuildDelegationLease {
                issuer_did: "did:web:integrator.example.com".into(),
                robot_did: "did:web:robot.example.com".into(),
                lease_id: "lease-3".into(),
                scope: json!({
                    "maxForceN": 200.0, "maxSpeedMps": 1.0,
                    "allowedZones": ["warehouse-a"]
                }),
                parent_lease_id: Some("lease-1".into()),
                valid_from: "2026-01-01T00:00:00Z".into(),
                valid_until: "2026-01-01T01:00:00Z".into(),
            },
        )
        .unwrap();
        assert!(verify_delegation_lease(
            &wider,
            &parent_kp.public_key(),
            None,
            Some(&parent_scope),
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn quorum_threshold_and_distinct_counting() {
        let s1 = [41u8; 32];
        let s2 = [42u8; 32];
        let k1 = Ed25519KeyPair::from_seed(&s1);
        let k2 = Ed25519KeyPair::from_seed(&s2);
        let a1 = "did:web:approver-1.example.com";
        let a2 = "did:web:approver-2.example.com";
        let robot = "did:web:robot.example.com";
        let action = "action-x";

        let build = |seed: &[u8], did: &str, decision: &str| {
            build_action_approval(
                seed,
                &BuildActionApproval {
                    approver_did: did.into(),
                    action_id: action.into(),
                    robot_did: robot.into(),
                    decision: decision.into(),
                    valid_from: "2026-01-01T00:00:00Z".into(),
                    valid_until: None,
                },
            )
            .unwrap()
        };

        let ap1 = build(&s1, a1, APPROVE);
        let ap2 = build(&s2, a2, APPROVE);
        let keys = vec![
            ApproverKey {
                did: a1.into(),
                public_key: k1.public_key().to_vec(),
            },
            ApproverKey {
                did: a2.into(),
                public_key: k2.public_key().to_vec(),
            },
        ];

        // Two distinct approvers meet a threshold of 2.
        let (ok, approvers) =
            verify_action_authorization(&[ap1.clone(), ap2], action, robot, &keys, 2, None, None)
                .unwrap();
        assert!(ok);
        assert_eq!(approvers, vec![a1.to_string(), a2.to_string()]);

        // Duplicate approvals from one approver count once: threshold 2 not met.
        let dup = build(&s1, a1, APPROVE);
        let (ok2, approvers2) =
            verify_action_authorization(&[ap1.clone(), dup], action, robot, &keys, 2, None, None)
                .unwrap();
        assert!(!ok2);
        assert_eq!(approvers2, vec![a1.to_string()]);

        // A single valid approver does not meet a threshold of 2.
        let (ok3, _) =
            verify_action_authorization(&[ap1], action, robot, &keys, 2, None, None).unwrap();
        assert!(!ok3);

        // A rejection is never counted as an approval.
        let rej = build(&s1, a1, REJECT);
        let approve2 = build(&s2, a2, APPROVE);
        let (ok4, approvers4) =
            verify_action_authorization(&[rej, approve2], action, robot, &keys, 2, None, None)
                .unwrap();
        assert!(!ok4);
        assert_eq!(approvers4, vec![a2.to_string()]);
    }

    // Cross-language interop: Rust verifies the Python-signed ownership transfer
    // under the owner's key from the vector.
    #[test]
    fn verifies_python_ownership_transfer_interop_vector() {
        let vector = load_vector();
        let owner_pub = jwk_pub(&vector["ownership_transfer_owner_key"]);
        let cred = vector["ownership_transfer_credential"].clone();

        let subject = verify_ownership_transfer(&cred, &owner_pub)
            .unwrap()
            .expect("the Python ownership-transfer interop vector must verify in Rust");
        assert_eq!(subject["toOwner"], json!("did:web:owner-b.example.com"));
    }

    // Cross-language interop: Rust verifies the Python-signed key rotation under
    // the robot key from robot_public_key_jwk.
    #[test]
    fn verifies_python_key_rotation_interop_vector() {
        let vector = load_vector();
        let robot_pub = jwk_pub(&vector["robot_public_key_jwk"]);
        let cred = vector["key_rotation_credential"].clone();

        let subject = verify_key_rotation(&cred, &robot_pub)
            .unwrap()
            .expect("the Python key-rotation interop vector must verify in Rust");
        assert_eq!(
            subject["newKey"],
            json!("z6MkmtWtY63GQVBrpMyRJWEzsnxfsGkemu6CtMDwGTv4RYj2")
        );
    }

    // Cross-language interop: Rust verifies the Python-signed decommission under
    // the authority key from the vector.
    #[test]
    fn verifies_python_decommission_interop_vector() {
        let vector = load_vector();
        let authority_pub = jwk_pub(&vector["decommission_authority_key"]);
        let cred = vector["decommission_credential"].clone();

        let subject = verify_decommission(&cred, &authority_pub, None)
            .unwrap()
            .expect("the Python decommission interop vector must verify in Rust");
        assert_eq!(subject["reason"], json!("end of service life"));
        assert_eq!(subject["finalDisposition"], json!("recycled"));
    }

    #[test]
    fn ownership_transfer_roundtrip_and_issuer_rule() {
        let owner_a_seed = [51u8; 32];
        let owner_b_seed = [52u8; 32];
        let a = Ed25519KeyPair::from_seed(&owner_a_seed);
        let b = Ed25519KeyPair::from_seed(&owner_b_seed);
        let owner_a = "did:web:owner-a.example.com";
        let owner_b = "did:web:owner-b.example.com";
        let robot = "did:web:robot.example.com";

        let transfer = build_ownership_transfer(
            &owner_a_seed,
            &BuildOwnershipTransfer {
                issuer_did: owner_a.into(),
                robot_did: robot.into(),
                to_owner: owner_b.into(),
                from_owner: None,
                prev_transfer_id: None,
                valid_from: "2026-01-01T00:00:00Z".into(),
            },
        )
        .unwrap();

        let subject = verify_ownership_transfer(&transfer, &a.public_key())
            .unwrap()
            .expect("transfer verifies under the current owner key");
        assert_eq!(subject["fromOwner"], json!(owner_a));
        assert_eq!(subject["toOwner"], json!(owner_b));

        // Wrong type rejected.
        let mut wrong = transfer.clone();
        wrong["type"] = json!(["VerifiableCredential"]);
        assert!(verify_ownership_transfer(&wrong, &a.public_key())
            .unwrap()
            .is_none());

        // The issuer must equal fromOwner: forge a transfer whose issuer is not the
        // declared seller and re-sign it. It must be rejected even with a valid
        // proof under the signing key.
        let forged = build_ownership_transfer(
            &owner_b_seed,
            &BuildOwnershipTransfer {
                issuer_did: owner_b.into(),
                robot_did: robot.into(),
                to_owner: "did:web:owner-c.example.com".into(),
                // Claim the robot was sold by owner A while owner B signs.
                from_owner: Some(owner_a.into()),
                prev_transfer_id: None,
                valid_from: "2026-01-01T00:00:00Z".into(),
            },
        )
        .unwrap();
        assert!(verify_ownership_transfer(&forged, &b.public_key())
            .unwrap()
            .is_none());
    }

    #[test]
    fn custody_chain_links_and_rejects() {
        let owner_a_seed = [51u8; 32];
        let owner_b_seed = [52u8; 32];
        let owner_c_seed = [53u8; 32];
        let a = Ed25519KeyPair::from_seed(&owner_a_seed);
        let b = Ed25519KeyPair::from_seed(&owner_b_seed);
        let c = Ed25519KeyPair::from_seed(&owner_c_seed);
        let owner_a = "did:web:owner-a.example.com";
        let owner_b = "did:web:owner-b.example.com";
        let owner_c = "did:web:owner-c.example.com";
        let robot = "did:web:robot.example.com";

        let t1 = build_ownership_transfer(
            &owner_a_seed,
            &BuildOwnershipTransfer {
                issuer_did: owner_a.into(),
                robot_did: robot.into(),
                to_owner: owner_b.into(),
                from_owner: None,
                prev_transfer_id: None,
                valid_from: "2026-01-01T00:00:00Z".into(),
            },
        )
        .unwrap();
        let t2 = build_ownership_transfer(
            &owner_b_seed,
            &BuildOwnershipTransfer {
                issuer_did: owner_b.into(),
                robot_did: robot.into(),
                to_owner: owner_c.into(),
                from_owner: None,
                prev_transfer_id: Some("transfer-1".into()),
                valid_from: "2026-02-01T00:00:00Z".into(),
            },
        )
        .unwrap();

        let keys = vec![
            OwnerKey {
                did: owner_a.into(),
                public_key: a.public_key().to_vec(),
            },
            OwnerKey {
                did: owner_b.into(),
                public_key: b.public_key().to_vec(),
            },
            OwnerKey {
                did: owner_c.into(),
                public_key: c.public_key().to_vec(),
            },
        ];

        // A clean two-link chain rooted at owner A ends at owner C.
        let (ok, current) =
            verify_custody_chain(&[t1.clone(), t2.clone()], &keys, Some(owner_a)).unwrap();
        assert!(ok);
        assert_eq!(current.as_deref(), Some(owner_c));

        // A wrong declared origin breaks the first link.
        let (bad_origin, _) =
            verify_custody_chain(&[t1.clone(), t2.clone()], &keys, Some(owner_c)).unwrap();
        assert!(!bad_origin);

        // A gap (link two without link one) breaks the toOwner -> fromOwner join.
        let (gap, _) =
            verify_custody_chain(std::slice::from_ref(&t2), &keys, Some(owner_a)).unwrap();
        assert!(!gap);

        // A missing key for an issuer fails the chain.
        let partial = vec![OwnerKey {
            did: owner_a.into(),
            public_key: a.public_key().to_vec(),
        }];
        let (no_key, _) = verify_custody_chain(&[t1, t2], &partial, Some(owner_a)).unwrap();
        assert!(!no_key);
    }

    #[test]
    fn key_rotation_roundtrip_and_history() {
        let k1_seed = [61u8; 32];
        let k2_seed = [62u8; 32];
        let k3_seed = [63u8; 32];
        let k1 = Ed25519KeyPair::from_seed(&k1_seed);
        let k2 = Ed25519KeyPair::from_seed(&k2_seed);
        let k3 = Ed25519KeyPair::from_seed(&k3_seed);
        let robot = "did:web:robot.example.com";

        // Rotate k1 -> k2, signed by k1.
        let r1 = build_key_rotation(
            &k1_seed,
            &BuildKeyRotation {
                robot_did: robot.into(),
                new_key_multibase: k2.public_multikey(),
                reason: Some("scheduled rotation".into()),
                valid_from: "2026-01-01T00:00:00Z".into(),
            },
        )
        .unwrap();

        let subject = verify_key_rotation(&r1, &k1.public_key())
            .unwrap()
            .expect("rotation verifies under the old key");
        assert_eq!(subject["previousKey"], json!(k1.public_multikey()));
        assert_eq!(subject["newKey"], json!(k2.public_multikey()));

        // The new key cannot verify a rotation that the old key signed.
        assert!(verify_key_rotation(&r1, &k2.public_key())
            .unwrap()
            .is_none());

        // Wrong type rejected.
        let mut wrong = r1.clone();
        wrong["type"] = json!(["VerifiableCredential"]);
        assert!(verify_key_rotation(&wrong, &k1.public_key())
            .unwrap()
            .is_none());

        // Rotate k2 -> k3, signed by k2, forming a history.
        let r2 = build_key_rotation(
            &k2_seed,
            &BuildKeyRotation {
                robot_did: robot.into(),
                new_key_multibase: k3.public_multikey(),
                reason: None,
                valid_from: "2026-02-01T00:00:00Z".into(),
            },
        )
        .unwrap();

        let public_keys = vec![
            KeyEntry {
                multibase: k1.public_multikey(),
                public_key: k1.public_key().to_vec(),
            },
            KeyEntry {
                multibase: k2.public_multikey(),
                public_key: k2.public_key().to_vec(),
            },
            KeyEntry {
                multibase: k3.public_multikey(),
                public_key: k3.public_key().to_vec(),
            },
        ];

        let (ok, current) = verify_key_history(
            &[r1.clone(), r2.clone()],
            &k1.public_multikey(),
            &public_keys,
        )
        .unwrap();
        assert!(ok);
        assert_eq!(current.as_deref(), Some(k3.public_multikey().as_str()));

        // A wrong origin key breaks the first previousKey match.
        let (bad_origin, _) =
            verify_key_history(&[r1, r2], &k3.public_multikey(), &public_keys).unwrap();
        assert!(!bad_origin);
    }

    #[test]
    fn decommission_roundtrip_and_trusted_authority() {
        let seed = [71u8; 32];
        let kp = Ed25519KeyPair::from_seed(&seed);
        let authority = "did:web:authority.example.com";
        let robot = "did:web:robot.example.com";

        let cred = build_decommission(
            &seed,
            &BuildDecommission {
                issuer_did: authority.into(),
                robot_did: robot.into(),
                reason: "end of service life".into(),
                final_disposition: Some("recycled".into()),
                valid_from: "2026-01-01T00:00:00Z".into(),
                valid_until: None,
            },
        )
        .unwrap();

        let mut trusted = HashSet::new();
        trusted.insert(authority.to_string());
        let subject = verify_decommission(&cred, &kp.public_key(), Some(&trusted))
            .unwrap()
            .expect("a trusted authority decommission verifies");
        assert_eq!(subject["decommissionedBy"], json!(authority));

        // An untrusted issuer is rejected even with a valid proof.
        let mut other = HashSet::new();
        other.insert("did:web:someone-else.example.com".to_string());
        assert!(verify_decommission(&cred, &kp.public_key(), Some(&other))
            .unwrap()
            .is_none());

        // No trusted-authority set: a valid proof verifies.
        assert!(verify_decommission(&cred, &kp.public_key(), None)
            .unwrap()
            .is_some());

        // Wrong type rejected.
        let mut wrong = cred.clone();
        wrong["type"] = json!(["VerifiableCredential"]);
        assert!(verify_decommission(&wrong, &kp.public_key(), None)
            .unwrap()
            .is_none());

        // reason is required at build time.
        assert!(build_decommission(
            &seed,
            &BuildDecommission {
                issuer_did: authority.into(),
                robot_did: robot.into(),
                reason: String::new(),
                final_disposition: None,
                valid_from: "2026-01-01T00:00:00Z".into(),
                valid_until: None,
            },
        )
        .is_err());
    }

    // Cross-language interop: Rust reproduces the exact conformance report and
    // digest Python pinned, from the same credential set and profile.
    #[test]
    fn conformance_matches_interop_vector() {
        let vector = load_vector();
        let credentials: Vec<Value> = vector["conformance_credentials"]
            .as_array()
            .expect("conformance_credentials present")
            .clone();
        let profile_id = vector["conformance_profile_id"].as_str().unwrap();

        let report = check_conformance(&credentials, profile_id).unwrap();
        assert_eq!(report, vector["expected_conformance_report"]);

        let digest = report_digest(&report);
        assert_eq!(
            digest,
            vector["expected_conformance_report_digest"]
                .as_str()
                .unwrap()
        );
    }

    #[test]
    fn conformance_unknown_profile_and_missing_field() {
        assert!(check_conformance(&[], "no-such-profile").is_err());

        // An empty credential set satisfies nothing.
        let empty = check_conformance(&[], "eu-ai-act-high-risk").unwrap();
        assert_eq!(empty["conforms"], json!(false));
        assert_eq!(empty["satisfiedCount"], json!(0));
        assert_eq!(empty["totalCount"], json!(4));

        // A safety record with no logHead does not satisfy the record-keeping
        // requirement (a missing field counts as unsatisfied).
        let creds = vec![json!({
            "type": ["VerifiableCredential", "RobotSafetyRecordCredential"],
            "credentialSubject": { "id": "did:web:robot.example.com", "totalEvents": 2 }
        })];
        let report = check_conformance(&creds, "eu-ai-act-high-risk").unwrap();
        let record_keeping = report["requirements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == json!("eu-aia-record-keeping"))
            .unwrap();
        assert_eq!(record_keeping["satisfied"], json!(false));

        // An empty allowedZones array is also unsatisfied.
        let zone_creds = vec![json!({
            "type": ["VerifiableCredential", "PhysicalCapabilityScope"],
            "credentialSubject": {
                "id": "did:web:robot.example.com",
                "physicalScope": { "maxSpeedMps": 1.5, "allowedZones": [] }
            }
        })];
        let ul = check_conformance(&zone_creds, "ul-3300").unwrap();
        let limits = ul["requirements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == json!("ul3300-operating-limits"))
            .unwrap();
        assert_eq!(limits["satisfied"], json!(false));
    }

    #[test]
    fn conformance_attestation_roundtrip_and_rejections() {
        let seed = [77u8; 32];
        let kp = Ed25519KeyPair::from_seed(&seed);
        let vector = load_vector();
        let credentials: Vec<Value> = vector["conformance_credentials"]
            .as_array()
            .unwrap()
            .clone();
        let report = check_conformance(&credentials, "eu-ai-act-high-risk").unwrap();

        let att = build_conformance_attestation(
            &seed,
            &BuildConformanceAttestation {
                issuer_did: "did:web:authority.example.com".into(),
                robot_did: "did:web:robot.example.com".into(),
                report: report.clone(),
                valid_from: "2026-01-01T00:00:00Z".into(),
                valid_until: Some("2027-01-01T00:00:00Z".into()),
            },
        )
        .unwrap();

        // Round-trip: a well-formed attestation verifies and surfaces the subject.
        let subject = verify_conformance_attestation(&att, &kp.public_key())
            .unwrap()
            .expect("a valid conformance attestation verifies");
        assert_eq!(subject["profileId"], json!("eu-ai-act-high-risk"));
        assert_eq!(subject["conforms"], json!(true));
        assert_eq!(
            subject["reportDigest"],
            vector["expected_conformance_report_digest"]
        );

        // Wrong key is rejected.
        let wrong_kp = Ed25519KeyPair::from_seed(&[88u8; 32]);
        assert!(verify_conformance_attestation(&att, &wrong_kp.public_key())
            .unwrap()
            .is_none());

        // A tampered embedded report no longer matches the bound digest.
        let mut tampered = att.clone();
        tampered["credentialSubject"]["report"]["conforms"] = json!(false);
        assert!(verify_conformance_attestation(&tampered, &kp.public_key())
            .unwrap()
            .is_none());

        // Wrong type is rejected.
        let mut wrong_type = att.clone();
        wrong_type["type"] = json!(["VerifiableCredential"]);
        assert!(
            verify_conformance_attestation(&wrong_type, &kp.public_key())
                .unwrap()
                .is_none()
        );

        // robot_did is required at build time.
        assert!(build_conformance_attestation(
            &seed,
            &BuildConformanceAttestation {
                issuer_did: "did:web:authority.example.com".into(),
                robot_did: String::new(),
                report,
                valid_from: "2026-01-01T00:00:00Z".into(),
                valid_until: None,
            },
        )
        .is_err());
    }

    // -- post-quantum robot credentials ------------------------------------

    fn classical_robot_credential(issuer: &str, seed: &[u8]) -> Value {
        let cred = json!({
            "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
            "type": ["VerifiableCredential", ROBOT_IDENTITY_TYPE],
            "issuer": issuer,
            "validFrom": "2026-01-01T00:00:00Z",
            "credentialSubject": {
                "id": issuer,
                "make": "Acme Robotics",
                "model": "AR-7",
                "serial": "SN-000123"
            }
        });
        let opts = BuildProofOptions::new(format!("{issuer}#key-1"), "2026-01-01T00:00:00Z");
        data_integrity::sign(&cred, seed, &opts).unwrap()
    }

    // Cross-language interop: Rust verifies the Python-signed hybrid PQ robot
    // identity under the Ed25519 key and the ML-DSA-44 multikey from the vector.
    #[test]
    fn verifies_python_pq_robot_identity_interop_vector() {
        let vector = load_vector();
        let ed_pub = jwk_pub(&vector["robot_public_key_jwk"]);
        let ml_multikey = vector["robot_mldsa44_public_multikey"].as_str().unwrap();
        let cred = vector["pq_robot_identity_credential"].clone();

        // (b) the credential is detected as post-quantum.
        assert!(is_pq(&cred));

        // (a) dual verify auto-detected from the proof, with the ML-DSA multikey.
        let ok = verify_robot_credential(&cred, &ed_pub, Some(ml_multikey.as_bytes()))
            .expect("the Python hybrid PQ interop vector must verify in Rust");
        assert!(ok);

        // verify_pq accepts the multikey string form directly.
        let resolved = mldsa44_public_from_multikey(ml_multikey).unwrap();
        assert!(verify_pq(&cred, &ed_pub, &resolved).unwrap());
    }

    #[test]
    fn pq_sign_verify_roundtrip_and_rejects() {
        let issuer = "did:web:robot.example.com";
        let seed = [21u8; 32];
        let kp = Ed25519KeyPair::from_seed(&seed);
        let ml = MlDsa44KeyPair::generate().unwrap();

        let classical = classical_robot_credential(issuer, &seed);
        assert!(!is_pq(&classical));

        // Sign hybrid; any prior proof is replaced by exactly one hybrid proof.
        let signed = sign_pq(&classical, &seed, &ml, "2026-02-01T00:00:00Z").unwrap();
        assert!(is_pq(&signed));
        assert!(signed["proof"].is_object());
        assert_eq!(signed["proof"]["cryptosuite"], json!(HYBRID_CRYPTOSUITE));

        // Round-trip: both signatures validate under the correct keys.
        assert!(verify_pq(&signed, &kp.public_key(), &ml.public_key()).unwrap());
        assert!(
            verify_robot_credential(&signed, &kp.public_key(), Some(&ml.public_key())).unwrap()
        );

        // The multikey string form is accepted too (as UTF-8 bytes).
        let ml_mk = multikey::encode_mldsa44_public(&ml.public_key()).unwrap();
        assert!(
            verify_robot_credential(&signed, &kp.public_key(), Some(ml_mk.as_bytes())).unwrap()
        );

        // Tampering the body breaks verification.
        let mut tampered = signed.clone();
        tampered["credentialSubject"]["model"] = json!("AR-9");
        assert!(!verify_pq(&tampered, &kp.public_key(), &ml.public_key()).unwrap());

        // Wrong Ed25519 key is rejected.
        let other_ed = Ed25519KeyPair::from_seed(&[99u8; 32]);
        assert!(!verify_pq(&signed, &other_ed.public_key(), &ml.public_key()).unwrap());

        // Wrong ML-DSA-44 key is rejected.
        let other_ml = MlDsa44KeyPair::generate().unwrap();
        assert!(!verify_pq(&signed, &kp.public_key(), &other_ml.public_key()).unwrap());

        // A hybrid credential without the ML-DSA key returns false, not true.
        assert!(!verify_robot_credential(&signed, &kp.public_key(), None).unwrap());
    }

    #[test]
    fn classical_credential_passes_dual_verify_without_pq_key() {
        let issuer = "did:web:robot.example.com";
        let seed = [22u8; 32];
        let kp = Ed25519KeyPair::from_seed(&seed);
        let classical = classical_robot_credential(issuer, &seed);

        assert!(!is_pq(&classical));
        // A classical credential verifies through the dual path with no ML-DSA key.
        assert!(verify_robot_credential(&classical, &kp.public_key(), None).unwrap());

        // A wrong key still fails.
        let other = Ed25519KeyPair::from_seed(&[7u8; 32]);
        assert!(!verify_robot_credential(&classical, &other.public_key(), None).unwrap());
    }

    #[test]
    fn migrate_to_pq_resigns_classical_credential() {
        let issuer = "did:web:robot.example.com";
        let seed = [23u8; 32];
        let kp = Ed25519KeyPair::from_seed(&seed);
        let ml = MlDsa44KeyPair::generate().unwrap();

        let classical = classical_robot_credential(issuer, &seed);
        assert!(verify_robot_credential(&classical, &kp.public_key(), None).unwrap());

        let migrated = migrate_to_pq(&classical, &seed, &ml, "2026-03-01T00:00:00Z").unwrap();
        assert!(is_pq(&migrated));
        // The body is preserved across migration.
        assert_eq!(
            migrated["credentialSubject"],
            classical["credentialSubject"]
        );
        assert!(
            verify_robot_credential(&migrated, &kp.public_key(), Some(&ml.public_key())).unwrap()
        );
    }

    // Cross-language interop: Rust verifies the Python-signed embodiment continuity
    // chain under the one agent key from the vector, ending on body-b, with no fork.
    #[test]
    fn verifies_python_embodiment_interop_vector() {
        let vector = load_vector();
        let agent_pub = jwk_pub(&vector["embodiment_agent_key"]);
        let chain: Vec<Value> = vector["embodiment_chain"]
            .as_array()
            .expect("embodiment_chain array")
            .clone();

        let (ok, current) = verify_continuity_chain(&chain, &agent_pub, None).unwrap();
        assert!(ok, "the Python embodiment chain must verify in Rust");
        assert_eq!(
            current.as_deref(),
            Some("did:web:body-b.example.com"),
            "the chain ends on body-b"
        );

        let (no_fork, conflict) = check_no_fork(&chain).unwrap();
        assert!(no_fork, "the Python embodiment chain has no fork");
        assert!(conflict.is_none());
    }

    #[test]
    fn embodiment_roundtrip_and_issuer_rule() {
        let agent_seed = [61u8; 32];
        let other_seed = [62u8; 32];
        let agent = Ed25519KeyPair::from_seed(&agent_seed);
        let other = Ed25519KeyPair::from_seed(&other_seed);
        let agent_did = "did:web:agent.example.com";
        let body_a = "did:web:body-a.example.com";

        let cred = build_embodiment(
            &agent_seed,
            &BuildEmbodiment {
                agent_did: agent_did.into(),
                body_did: body_a.into(),
                body_hardware_root: "uROOTA".into(),
                from_body: None,
                embodied_at: "2026-01-01T00:00:00Z".into(),
                valid_until: None,
            },
        )
        .unwrap();

        let subject = verify_embodiment(&cred, &agent.public_key())
            .unwrap()
            .expect("embodiment verifies under the agent key");
        assert_eq!(subject["body"], json!(body_a));
        assert_eq!(subject["bodyHardwareRoot"], json!("uROOTA"));

        // The issuer must equal the subject id: forge a credential issued by an
        // impostor over an unchanged subject (still the agent) and re-sign it. It
        // must be rejected even with a valid proof under the signing key, because a
        // mind only authorizes its own embodiment.
        let forged = {
            let mut bare = cred.clone();
            bare.as_object_mut().unwrap().remove("proof");
            bare["issuer"] = json!("did:web:impostor.example.com");
            let opts = BuildProofOptions::new(
                "did:web:impostor.example.com#key-1".to_string(),
                "2026-01-01T00:00:00Z",
            );
            data_integrity::sign(&bare, &other_seed, &opts).unwrap()
        };
        assert!(verify_embodiment(&forged, &other.public_key())
            .unwrap()
            .is_none());
    }

    #[test]
    fn continuity_chain_links_and_rejects() {
        let agent_seed = [61u8; 32];
        let stranger_seed = [63u8; 32];
        let agent = Ed25519KeyPair::from_seed(&agent_seed);
        let stranger = Ed25519KeyPair::from_seed(&stranger_seed);
        let agent_did = "did:web:agent.example.com";
        let body_a = "did:web:body-a.example.com";
        let body_b = "did:web:body-b.example.com";

        let e1 = build_embodiment(
            &agent_seed,
            &BuildEmbodiment {
                agent_did: agent_did.into(),
                body_did: body_a.into(),
                body_hardware_root: "uROOTA".into(),
                from_body: None,
                embodied_at: "2026-01-01T00:00:00Z".into(),
                valid_until: Some("2026-01-01T01:00:00Z".into()),
            },
        )
        .unwrap();
        let e2 = build_embodiment(
            &agent_seed,
            &BuildEmbodiment {
                agent_did: agent_did.into(),
                body_did: body_b.into(),
                body_hardware_root: "uROOTB".into(),
                from_body: Some(body_a.into()),
                embodied_at: "2026-01-01T01:00:00Z".into(),
                valid_until: None,
            },
        )
        .unwrap();

        // A clean two-link chain ends at body-b: the first link opens on body-a
        // and the second link's fromBody re-binds to it.
        let (ok, current) =
            verify_continuity_chain(&[e1.clone(), e2.clone()], &agent.public_key(), None).unwrap();
        assert!(ok);
        assert_eq!(current.as_deref(), Some(body_b));

        // Declaring the wrong origin body breaks the first link, since the first
        // link's fromBody must match the origin when given.
        let (bad_origin, _) =
            verify_continuity_chain(&[e1.clone(), e2.clone()], &agent.public_key(), Some(body_b))
                .unwrap();
        assert!(!bad_origin);

        // A broken link (second link's fromBody does not match the first's body)
        // fails the chain.
        let broken = build_embodiment(
            &agent_seed,
            &BuildEmbodiment {
                agent_did: agent_did.into(),
                body_did: body_b.into(),
                body_hardware_root: "uROOTB".into(),
                from_body: Some("did:web:body-x.example.com".into()),
                embodied_at: "2026-01-01T01:00:00Z".into(),
                valid_until: None,
            },
        )
        .unwrap();
        let (bad_link, _) =
            verify_continuity_chain(&[e1.clone(), broken], &agent.public_key(), None).unwrap();
        assert!(!bad_link);

        // Every link must verify under the SAME agent key: a link signed by a
        // different key breaks the chain (a mind is one persistent identity).
        let e2_stranger = build_embodiment(
            &stranger_seed,
            &BuildEmbodiment {
                agent_did: agent_did.into(),
                body_did: body_b.into(),
                body_hardware_root: "uROOTB".into(),
                from_body: Some(body_a.into()),
                embodied_at: "2026-01-01T01:00:00Z".into(),
                valid_until: None,
            },
        )
        .unwrap();
        assert!(verify_embodiment(&e2_stranger, &stranger.public_key())
            .unwrap()
            .is_some());
        let (mixed_keys, _) =
            verify_continuity_chain(&[e1, e2_stranger], &agent.public_key(), None).unwrap();
        assert!(!mixed_keys);
    }

    #[test]
    fn fork_detection_flags_overlapping_bodies() {
        let agent_seed = [61u8; 32];
        let agent_did = "did:web:agent.example.com";
        let body_a = "did:web:body-a.example.com";
        let body_b = "did:web:body-b.example.com";

        let build = |body: &str, root: &str, from: &str, until: &str| {
            build_embodiment(
                &agent_seed,
                &BuildEmbodiment {
                    agent_did: agent_did.into(),
                    body_did: body.into(),
                    body_hardware_root: root.into(),
                    from_body: None,
                    embodied_at: from.into(),
                    valid_until: Some(until.into()),
                },
            )
            .unwrap()
        };

        // A clean handover: body-a's window ends exactly where body-b's begins.
        // Half-open intervals do not overlap, so this is not a fork.
        let clean_a = build(
            body_a,
            "uROOTA",
            "2026-01-01T00:00:00Z",
            "2026-01-01T01:00:00Z",
        );
        let clean_b = build(
            body_b,
            "uROOTB",
            "2026-01-01T01:00:00Z",
            "2026-01-01T02:00:00Z",
        );
        let (clean, conflict) = check_no_fork(&[clean_a, clean_b]).unwrap();
        assert!(clean);
        assert!(conflict.is_none());

        // Overlapping windows on different bodies are a fork; the conflict names
        // both bodies.
        let fork_a = build(
            body_a,
            "uROOTA",
            "2026-01-01T00:00:00Z",
            "2026-01-01T02:00:00Z",
        );
        let fork_b = build(
            body_b,
            "uROOTB",
            "2026-01-01T01:00:00Z",
            "2026-01-01T03:00:00Z",
        );
        let (forked, conflict) = check_no_fork(&[fork_a, fork_b]).unwrap();
        assert!(!forked);
        let conflict = conflict.expect("a fork names the two conflicting bodies");
        assert_eq!(conflict.body_a, body_a);
        assert_eq!(conflict.body_b, body_b);
    }

    // Custody handoff (Phase 5.16) -----------------------------------------

    fn actor_keys_from_vector(map: &Value) -> Vec<ActorKey> {
        map.as_object()
            .expect("custody_actor_keys object")
            .iter()
            .map(|(did, jwk)| ActorKey {
                did: did.clone(),
                public_key: jwk_pub(jwk),
            })
            .collect()
    }

    // Cross-language interop: Rust verifies the Python-signed custody chain under
    // the actor keys from the vector, ending on robot-b, and localizes the
    // condition change to the hop robot-a was responsible for.
    #[test]
    fn verifies_python_custody_interop_vector() {
        let vector = load_vector();
        let chain: Vec<Value> = vector["custody_chain"]
            .as_array()
            .expect("custody_chain array")
            .clone();
        let keys = actor_keys_from_vector(&vector["custody_actor_keys"]);
        let origin = vector["custody_origin_actor"].as_str().unwrap();

        let (ok, current) = verify_handoff_chain(&chain, &keys, Some(origin)).unwrap();
        assert!(ok, "the Python custody chain must verify in Rust");
        assert_eq!(
            current.as_deref(),
            Some("did:web:robot-b.example.com"),
            "the chain ends holding at robot-b"
        );

        let change = locate_condition_change(&chain).expect("the condition changed");
        assert_eq!(
            change.responsible_holder.as_deref(),
            Some("did:web:robot-a.example.com"),
            "robot-a held the task while its condition changed"
        );
        assert_eq!(change.from_condition, "intact");
        assert_eq!(change.to_condition, "damaged");
    }

    #[test]
    fn handoff_roundtrip_and_receiver_rule() {
        let robot_seed = [71u8; 32];
        let other_seed = [72u8; 32];
        let robot = Ed25519KeyPair::from_seed(&robot_seed);
        let other = Ed25519KeyPair::from_seed(&other_seed);
        let worker = "did:web:worker-jane.example.com";
        let robot_a = "did:web:robot-a.example.com";

        let cred = build_handoff(
            &robot_seed,
            &BuildHandoff {
                task_id: "tote-42".into(),
                from_actor: worker.into(),
                to_actor: robot_a.into(),
                condition: Some("intact".into()),
                handoff_at: "2026-01-01T00:00:00Z".into(),
                valid_until: None,
            },
        )
        .unwrap();

        let subject = verify_handoff(&cred, &robot.public_key())
            .unwrap()
            .expect("handoff verifies under the receiver key");
        assert_eq!(subject["fromActor"], json!(worker));
        assert_eq!(subject["toActor"], json!(robot_a));

        // The issuer must be the receiver: forge a handoff issued by a different
        // party over the same subject and re-sign it. It must be rejected even with
        // a valid proof under the signing key, because a party attests its own
        // acceptance of custody.
        let forged = {
            let mut bare = cred.clone();
            bare.as_object_mut().unwrap().remove("proof");
            bare["issuer"] = json!("did:web:impostor.example.com");
            let opts = BuildProofOptions::new(
                "did:web:impostor.example.com#key-1".to_string(),
                "2026-01-01T00:00:00Z",
            );
            data_integrity::sign(&bare, &other_seed, &opts).unwrap()
        };
        assert!(verify_handoff(&forged, &other.public_key())
            .unwrap()
            .is_none());
    }

    #[test]
    fn handoff_chain_links_and_rejects() {
        let a_seed = [73u8; 32];
        let b_seed = [74u8; 32];
        let a = Ed25519KeyPair::from_seed(&a_seed);
        let b = Ed25519KeyPair::from_seed(&b_seed);
        let worker = "did:web:worker-jane.example.com";
        let robot_a = "did:web:robot-a.example.com";
        let robot_b = "did:web:robot-b.example.com";

        let h1 = build_handoff(
            &a_seed,
            &BuildHandoff {
                task_id: "tote-42".into(),
                from_actor: worker.into(),
                to_actor: robot_a.into(),
                condition: Some("intact".into()),
                handoff_at: "2026-01-01T00:00:00Z".into(),
                valid_until: None,
            },
        )
        .unwrap();
        let h2 = build_handoff(
            &b_seed,
            &BuildHandoff {
                task_id: "tote-42".into(),
                from_actor: robot_a.into(),
                to_actor: robot_b.into(),
                condition: Some("damaged".into()),
                handoff_at: "2026-01-01T00:10:00Z".into(),
                valid_until: None,
            },
        )
        .unwrap();

        let keys = vec![
            ActorKey {
                did: robot_a.into(),
                public_key: a.public_key().to_vec(),
            },
            ActorKey {
                did: robot_b.into(),
                public_key: b.public_key().to_vec(),
            },
        ];

        // A clean two-link chain ends holding at robot-b: the first link's
        // fromActor is the origin worker and the second link re-binds to robot-a.
        let (ok, current) =
            verify_handoff_chain(&[h1.clone(), h2.clone()], &keys, Some(worker)).unwrap();
        assert!(ok);
        assert_eq!(current.as_deref(), Some(robot_b));

        // Declaring the wrong origin actor breaks the first link.
        let (bad_origin, _) =
            verify_handoff_chain(&[h1.clone(), h2.clone()], &keys, Some(robot_b)).unwrap();
        assert!(!bad_origin);

        // A broken link (second link's fromActor does not match the first's
        // toActor) fails the chain.
        let broken = build_handoff(
            &b_seed,
            &BuildHandoff {
                task_id: "tote-42".into(),
                from_actor: "did:web:robot-x.example.com".into(),
                to_actor: robot_b.into(),
                condition: Some("damaged".into()),
                handoff_at: "2026-01-01T00:10:00Z".into(),
                valid_until: None,
            },
        )
        .unwrap();
        let (bad_link, _) =
            verify_handoff_chain(&[h1.clone(), broken], &keys, Some(worker)).unwrap();
        assert!(!bad_link);

        // A missing receiver key for a link fails the chain.
        let partial = vec![ActorKey {
            did: robot_a.into(),
            public_key: a.public_key().to_vec(),
        }];
        let (no_key, _) =
            verify_handoff_chain(&[h1.clone(), h2.clone()], &partial, Some(worker)).unwrap();
        assert!(!no_key);

        // holder_at reports who held the task at a moment: robot-a right after the
        // first handoff, robot-b right after the second.
        assert_eq!(
            holder_at(&[h1.clone(), h2.clone()], "2026-01-01T00:05:00Z").as_deref(),
            Some(robot_a)
        );
        assert_eq!(
            holder_at(&[h1.clone(), h2.clone()], "2026-01-01T00:15:00Z").as_deref(),
            Some(robot_b)
        );

        // A chain whose condition never changes localizes nothing.
        let steady = build_handoff(
            &b_seed,
            &BuildHandoff {
                task_id: "tote-42".into(),
                from_actor: robot_a.into(),
                to_actor: robot_b.into(),
                condition: Some("intact".into()),
                handoff_at: "2026-01-01T00:10:00Z".into(),
                valid_until: None,
            },
        )
        .unwrap();
        assert!(locate_condition_change(&[h1, steady]).is_none());
    }

    // Robot-to-infrastructure bounded access (Phase 5.17) ------------------

    // Cross-language interop: Rust authorizes the Python-signed grant and request
    // from the vector under the operator and robot keys, offline.
    #[test]
    fn authorizes_python_access_interop_vector() {
        let vector = load_vector();
        let grant = vector["access_grant_credential"].clone();
        let request = vector["access_request_credential"].clone();
        let operator_pub = jwk_pub(&vector["access_operator_key"]);
        let robot_pub = jwk_pub(&vector["access_robot_key"]);

        let res = authorize_access(
            &grant,
            &request,
            &operator_pub,
            &robot_pub,
            Some("2026-01-01T00:05:00Z"),
        )
        .unwrap();
        assert!(
            res.ok,
            "the Python grant and request must authorize in Rust"
        );
        assert!(res.reasons.is_empty());
    }

    // Fused-sensor provenance (Phase 5.18) ---------------------------------

    // Cross-language interop: Rust reproduces the exact inputs digest and fused
    // output hash Python pinned, and verifies the Python-signed attestation.
    #[test]
    fn verifies_python_fused_interop_vector() {
        let vector = load_vector();
        let robot_pub = jwk_pub(&vector["robot_public_key_jwk"]);

        let inputs: Vec<String> = vector["fused_input_frame_hashes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            fusion_inputs_digest(&inputs).unwrap(),
            vector["expected_fusion_inputs_digest"].as_str().unwrap()
        );

        assert_eq!(
            hash_fused_output(b"world-model-0"),
            vector["expected_fused_output_hash"].as_str().unwrap()
        );

        let cred = vector["fused_perception_attestation"].clone();
        let subject = verify_fused_attestation(&cred, &robot_pub, None)
            .unwrap()
            .expect("fused attestation verifies");
        assert_eq!(subject["fusionMethod"], "occupancy-grid-v1");
        assert_eq!(
            subject["inputsDigest"].as_str().unwrap(),
            vector["expected_fusion_inputs_digest"].as_str().unwrap()
        );
    }

    // Wear and degradation attestation (Phase 5.19) ------------------------

    // Cross-language interop: Rust verifies the Python-signed wear history and
    // reproduces the physical scope narrowed for the pinned wear level.
    #[test]
    fn verifies_python_wear_interop_vector() {
        let vector = load_vector();
        let robot_pub = jwk_pub(&vector["robot_public_key_jwk"]);

        let chain: Vec<Value> = vector["wear_chain"].as_array().unwrap().clone();
        let latest = verify_wear_chain(&chain, &robot_pub)
            .unwrap()
            .expect("wear chain verifies");
        assert_eq!(latest["wearLevel"].as_f64().unwrap(), 0.3);

        let scope = vector["wear_input_scope"].clone();
        let level = vector["wear_attenuation_level"].as_f64().unwrap();
        let narrowed = attenuate_for_wear(&scope, level).unwrap();
        assert_eq!(narrowed, vector["expected_attenuated_scope"]);
        assert_eq!(narrowed["maxForceN"].as_f64().unwrap(), 60.0);
        assert_eq!(narrowed["maxSpeedMps"].as_f64().unwrap(), 1.125);
        assert_eq!(narrowed["maxSpeedNearHumansMps"].as_f64().unwrap(), 0.1875);
        assert!(attenuates(&scope, &narrowed));
    }

    // Bystander-consent evidence (Phase 5.20) ------------------------------

    // Cross-language interop: Rust reproduces the capture hash Python pinned,
    // verifies the bystander-signed token is bound to that capture, and verifies
    // the robot-signed evidence with the token and the bystander key.
    #[test]
    fn verifies_python_consent_interop_vector() {
        let vector = load_vector();
        let robot_pub = jwk_pub(&vector["robot_public_key_jwk"]);
        let bystander_pub = jwk_pub(&vector["consent_bystander_key"]);

        let capture = b"bystander-frame-0";
        let capture_hash = hash_capture(capture);
        assert_eq!(
            capture_hash,
            vector["expected_consent_capture_hash"].as_str().unwrap()
        );

        let token = vector["consent_token_credential"].clone();
        let robot_did = token["credentialSubject"]["robotDid"].as_str().unwrap();
        let tok_subject = verify_consent_token(
            &token,
            &bystander_pub,
            &capture_hash,
            robot_did,
            Some("2026-01-01T00:05:00Z"),
        )
        .unwrap()
        .expect("consent token verifies bound to the capture");
        assert_eq!(tok_subject["captureHash"].as_str().unwrap(), capture_hash);

        let evidence = vector["consent_evidence_credential"].clone();
        let bystander_did = token["issuer"].as_str().unwrap();
        let keys = [BystanderKey {
            did: bystander_did.to_string(),
            public_key: bystander_pub.clone(),
        }];
        let ev_subject = verify_consent_evidence(
            &evidence,
            &robot_pub,
            Some(capture),
            Some(&[token.clone()]),
            Some(&keys),
            Some("2026-01-01T00:05:00Z"),
        )
        .unwrap()
        .expect("consent evidence verifies with token and bystander key");
        assert_eq!(ev_subject["basis"].as_str().unwrap(), "explicit-consent");
    }
}

#[cfg(test)]
mod robot_root_identity_tests {
    use super::*;
    use crate::keys::Ed25519KeyPair;
    use std::path::PathBuf;

    const NOW: &str = "2026-07-01T00:00:00Z";
    const VALID_FROM: &str = "2026-01-01T00:00:00Z";
    const CREATED: &str = "2026-01-01T00:00:00Z";
    const VALID_SECONDS: i64 = 100 * 365 * 24 * 3600;
    // Matches the manufacturer seed recorded in the interop vector (0x04 x32).
    const MANUFACTURER_SEED: [u8; 32] = [0x04; 32];
    const FORGED_ID: &str = "urn:uuid:66666666-6666-6666-6666-666666666666";

    fn load_vector() -> Value {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../test-vectors/root-of-trust/vector.json");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read vector {}: {e}", path.display()));
        serde_json::from_str(&text).expect("vector is valid JSON")
    }

    fn robot_pub(vector: &Value) -> Vec<u8> {
        let x = vector["robotPublicKey"]["x"].as_str().unwrap();
        URL_SAFE_NO_PAD.decode(x).unwrap()
    }

    fn stray_multikey(seed: &[u8]) -> String {
        let kp = Ed25519KeyPair::from_seed_slice(seed).unwrap();
        multikey::encode_ed25519_public(&kp.public_key()).unwrap()
    }

    fn stray_did(seed: &[u8]) -> String {
        Ed25519KeyPair::from_seed_slice(seed).unwrap().did_key()
    }

    fn robot_attributes() -> Value {
        json!({ "make": "Acme Robotics", "model": "AR-7", "serial": "SN-000123" })
    }

    // The committed Python-minted robot chain must verify in Rust: recognized
    // manufacturer provenance plus hardware-rooting.
    #[test]
    fn verifies_python_robot_identity_interop_vector() {
        let v = load_vector();
        let root = v["trustedRoot"].as_str().unwrap();
        let r = verify_robot_identity_chain(
            &v["robotAuthorityIdentity"],
            &v["robotRecognizedIssuer"],
            &v["robotHardwareCredential"],
            root,
            &robot_pub(&v),
            Some(&v["rootOfTrust"]),
            NOW,
            30,
        );
        assert!(r.ok, "robot chain must verify: {:?}", r.reason);
        assert!(r.hardware_rooted);
        assert_eq!(r.robot_did.as_deref(), v["expected"]["robotDid"].as_str());
        assert_eq!(
            r.issuer_did.as_deref(),
            v["expected"]["robotIssuerDid"].as_str()
        );
        assert_eq!(r.root_did.as_deref(), Some(root));
        assert_eq!(
            v["expected"]["verifyRobotIdentityChain"].as_bool(),
            Some(true)
        );
    }

    // Adversarial: pinning a different root breaks the recognition anchor.
    #[test]
    fn wrong_pinned_root_rejected() {
        let v = load_vector();
        let other_root = stray_did(&[0x09; 32]);
        let r = verify_robot_identity_chain(
            &v["robotAuthorityIdentity"],
            &v["robotRecognizedIssuer"],
            &v["robotHardwareCredential"],
            &other_root,
            &robot_pub(&v),
            None,
            NOW,
            30,
        );
        assert!(!r.ok);
        assert_eq!(r.reason.as_deref(), Some("recognized_issuer_not_from_root"));
    }

    // Adversarial: the manufacturer vouched a key that is not the robot's real
    // key. Provenance holds but the hardware key does not match.
    #[test]
    fn manufacturer_vouched_a_different_key() {
        let v = load_vector();
        let root = v["trustedRoot"].as_str().unwrap();
        let robot_did = v["expected"]["robotDid"].as_str().unwrap();
        let forged = build_robot_identity(
            &MANUFACTURER_SEED,
            robot_did,
            &stray_multikey(&[0x09; 32]),
            &robot_attributes(),
            VALID_SECONDS,
            VALID_FROM,
            CREATED,
            None,
            FORGED_ID,
        )
        .unwrap();
        let r = verify_robot_identity_chain(
            &forged,
            &v["robotRecognizedIssuer"],
            &v["robotHardwareCredential"],
            root,
            &robot_pub(&v),
            Some(&v["rootOfTrust"]),
            NOW,
            30,
        );
        assert!(!r.ok);
        assert_eq!(r.reason.as_deref(), Some("hardware_key_mismatch"));
    }

    // Adversarial: an impostor key is presented for the hardware credential, so
    // the secure-element attestation no longer verifies.
    #[test]
    fn impostor_key_fails_hardware_root() {
        let v = load_vector();
        let root = v["trustedRoot"].as_str().unwrap();
        let impostor = Ed25519KeyPair::from_seed(&[0x09; 32]).public_key();
        let r = verify_robot_identity_chain(
            &v["robotAuthorityIdentity"],
            &v["robotRecognizedIssuer"],
            &v["robotHardwareCredential"],
            root,
            &impostor,
            Some(&v["rootOfTrust"]),
            NOW,
            30,
        );
        assert!(!r.ok);
        assert_eq!(r.reason.as_deref(), Some("hardware_root_invalid"));
    }
}
