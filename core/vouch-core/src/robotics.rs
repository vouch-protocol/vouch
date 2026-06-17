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
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|e| CoreError::Crypto(format!("rng: {e}")))?;
        let plaintext = jcs::canonicalize(payload);
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| CoreError::Crypto(format!("aes key: {e}")))?;
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .map_err(|e| CoreError::Crypto(format!("encrypt: {e}")))?;
        let mut blob = Vec::with_capacity(nonce.len() + ct.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);

        let mut body = Map::new();
        body.insert("version".into(), json!(BLACKBOX_VERSION));
        body.insert("seq".into(), json!(self.entries.len()));
        body.insert("timestamp".into(), json!(timestamp));
        body.insert("event".into(), json!(event));
        body.insert("ciphertext".into(), json!(mb64(&blob)));
        body.insert("prevHash".into(), json!(self.head));
        let h = entry_hash(&body)?;
        body.insert("entryHash".into(), json!(h.clone()));

        let entry = Value::Object(body);
        self.entries.push(entry.clone());
        self.head = h;
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
}
