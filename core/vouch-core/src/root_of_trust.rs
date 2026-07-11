//! Root of Trust for Machine Identity (Vouch Protocol).
//!
//! Byte-exact port of the Python reference `vouch/root_of_trust.py`. Lets Vouch
//! Protocol act as the trust anchor for AI agent and robot identity. A verifier
//! pins ONE Vouch root, then verifies any agent offline by walking:
//!
//! ```text
//! agent identity credential  ->  recognized-issuer credential  ->  Vouch root
//! ```
//!
//! Three credential types compose this chain, all secured with the same
//! `eddsa-jcs-2022` Data Integrity proof used elsewhere in the core:
//!
//!   1. Root of Trust credential: self-issued by the root (issuer == subject).
//!   2. Recognized-issuer credential: issued by the root, naming an issuer that may attest agent or robot identity.
//!   3. Agent identity credential: issued by a recognized issuer, binding an agent key to real attributes (issuer != subject).
//!
//! The core is deterministic and clock-free: the caller supplies `valid_from`,
//! `created`, and the current instant used for verification. That keeps the
//! proofs reproducible and interoperable with the Python and TypeScript SDKs
//! (see `test-vectors/root-of-trust/vector.json`).

use serde_json::{json, Map, Value};

use crate::credentials::{PROTOCOL_VERSION, VC_CONTEXT_V2, VC_TYPE, VOUCH_CONTEXT_V1};
use crate::data_integrity::{self, BuildProofOptions};
use crate::error::{CoreError, Result};
use crate::keys::{did_key_to_ed25519, ed25519_to_did_key, Ed25519KeyPair};
use crate::time::iso_to_epoch_seconds;

/// Credential type identifiers (the second entry in each `type` array).
pub const ROOT_OF_TRUST_TYPE: &str = "VouchRootOfTrust";
pub const RECOGNIZED_ISSUER_TYPE: &str = "RecognizedIssuerCredential";
pub const AGENT_IDENTITY_TYPE: &str = "AgentIdentityCredential";

/// Actions an issuer can be recognized to perform.
pub const ACTION_ISSUE_AGENT_IDENTITY: &str = "issueAgentIdentity";
pub const ACTION_ISSUE_ROBOT_IDENTITY: &str = "issueRobotIdentity";

/// The three trust-layer credential types. A single credential must carry exactly
/// one of these, otherwise one signed object could be replayed into a different
/// slot of the chain (type confusion).
const TRUST_TYPES: [&str; 3] = [
    ROOT_OF_TRUST_TYPE,
    RECOGNIZED_ISSUER_TYPE,
    AGENT_IDENTITY_TYPE,
];

/// Default validity windows. Roots are long lived; issuer and identity
/// credentials rotate more often. All are overridable per call.
pub const ROOT_VALID_SECONDS: i64 = 10 * 365 * 24 * 3600;
pub const ISSUER_VALID_SECONDS: i64 = 365 * 24 * 3600;
pub const IDENTITY_VALID_SECONDS: i64 = 365 * 24 * 3600;

/// The proof verification method is always `{did}#key-1` for a did:key signer.
fn verification_method_of(did: &str) -> String {
    format!("{did}#key-1")
}

/// Outcome of [`verify_identity_chain`].
///
/// `ok` is true only if every link verified and anchored to the pinned root.
/// On failure `reason` carries a structured code matching the Python reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityChainResult {
    pub ok: bool,
    pub reason: Option<String>,
    pub agent_did: Option<String>,
    pub issuer_did: Option<String>,
    pub root_did: Option<String>,
    pub attributes: Option<Value>,
}

impl IdentityChainResult {
    fn fail(reason: impl Into<String>) -> Self {
        Self {
            ok: false,
            reason: Some(reason.into()),
            agent_did: None,
            issuer_did: None,
            root_did: None,
            attributes: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Credential builders
// ---------------------------------------------------------------------------

/// Self-issue the Vouch Root of Trust credential.
///
/// Issuer and subject are both the root's own DID (derived from `root_seed`).
/// `scope` defaults to `["ai-agent", "robot"]` when None. `valid_from` and
/// `created` are ISO-8601 instants ("YYYY-MM-DDTHH:MM:SSZ"); the core does not
/// read a clock.
#[allow(clippy::too_many_arguments)]
pub fn build_root_of_trust(
    root_seed: &[u8],
    name: &str,
    scope: Option<&[&str]>,
    valid_seconds: i64,
    valid_from: &str,
    created: &str,
    credential_id: &str,
) -> Result<Value> {
    let root_did = did_of_seed(root_seed)?;
    let scope_val: Vec<Value> = match scope {
        Some(s) => s.iter().map(|x| json!(x)).collect(),
        None => vec![json!("ai-agent"), json!("robot")],
    };
    let mut subject = Map::new();
    subject.insert("id".into(), json!(root_did));
    subject.insert("vouchVersion".into(), json!(PROTOCOL_VERSION));
    subject.insert(
        "rootOfTrust".into(),
        json!({ "name": name, "scope": scope_val }),
    );

    let credential = envelope(
        credential_id,
        &[VC_TYPE, ROOT_OF_TRUST_TYPE],
        &root_did,
        Value::Object(subject),
        valid_from,
        valid_seconds,
        None,
    )?;
    sign(&credential, root_seed, &root_did, created)
}

/// Issue a recognized-issuer credential from the root.
///
/// The root attests that `issuer_did` may perform `recognized_actions`
/// (default `["issueAgentIdentity"]`). `recognizedIn` chains back to the root
/// DID so a verifier can trace the recognition to the anchor it pinned.
#[allow(clippy::too_many_arguments)]
pub fn build_recognized_issuer(
    root_seed: &[u8],
    issuer_did: &str,
    recognized_actions: Option<&[&str]>,
    valid_seconds: i64,
    valid_from: &str,
    created: &str,
    credential_status: Option<Value>,
    credential_id: &str,
) -> Result<Value> {
    if issuer_did.is_empty() {
        return Err(CoreError::Json("issuer_did is required".into()));
    }
    let root_did = did_of_seed(root_seed)?;
    let actions: Vec<Value> = match recognized_actions {
        Some(a) => a.iter().map(|x| json!(x)).collect(),
        None => vec![json!(ACTION_ISSUE_AGENT_IDENTITY)],
    };
    let mut subject = Map::new();
    subject.insert("id".into(), json!(issuer_did));
    subject.insert("recognizedActions".into(), Value::Array(actions));
    subject.insert("recognizedIn".into(), json!(root_did));

    let credential = envelope(
        credential_id,
        &[VC_TYPE, RECOGNIZED_ISSUER_TYPE],
        &root_did,
        Value::Object(subject),
        valid_from,
        valid_seconds,
        credential_status,
    )?;
    sign(&credential, root_seed, &root_did, created)
}

/// Issue an authority-issued identity credential for an agent.
///
/// Here the issuer (derived from `issuer_seed`) differs from the subject: a
/// recognized issuer binds `subject_did` to real `attributes` (owner, model,
/// capability class, and so on). `attributes` MUST be a non-empty JSON object.
#[allow(clippy::too_many_arguments)]
pub fn build_agent_identity(
    issuer_seed: &[u8],
    subject_did: &str,
    attributes: &Value,
    valid_seconds: i64,
    valid_from: &str,
    created: &str,
    credential_status: Option<Value>,
    credential_id: &str,
) -> Result<Value> {
    if subject_did.is_empty() {
        return Err(CoreError::Json("subject_did is required".into()));
    }
    match attributes.as_object() {
        Some(o) if !o.is_empty() => {}
        _ => {
            return Err(CoreError::Json(
                "attributes must be a non-empty object".into(),
            ))
        }
    }
    let issuer_did = did_of_seed(issuer_seed)?;
    let mut subject = Map::new();
    subject.insert("id".into(), json!(subject_did));
    subject.insert("identity".into(), attributes.clone());

    let credential = envelope(
        credential_id,
        &[VC_TYPE, AGENT_IDENTITY_TYPE],
        &issuer_did,
        Value::Object(subject),
        valid_from,
        valid_seconds,
        credential_status,
    )?;
    sign(&credential, issuer_seed, &issuer_did, created)
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify an agent identity against a pinned Vouch root, fully offline for
/// did:key issuers.
///
/// Walks the chain: the recognized-issuer credential must be signed by the
/// pinned root and grant `required_action`; the identity credential must be
/// signed by that recognized issuer. Everything anchors at `trusted_root`, the
/// ONE DID the verifier trusts up front. `now_iso` is the current instant used
/// for the temporal window; `clock_skew_seconds` is the allowed drift.
///
/// The reason codes returned on failure match the Python reference exactly.
#[allow(clippy::too_many_arguments)]
pub fn verify_identity_chain(
    identity_credential: &Value,
    recognized_issuer_credential: &Value,
    trusted_root: &str,
    root_credential: Option<&Value>,
    action_credential: Option<&Value>,
    required_action: &str,
    now_iso: &str,
    clock_skew_seconds: i64,
) -> IdentityChainResult {
    if trusted_root.is_empty() {
        return IdentityChainResult::fail("no_trusted_root");
    }

    // 1. The recognition must be signed by the pinned root.
    if let Err(reason) = verify_trust_credential(
        recognized_issuer_credential,
        RECOGNIZED_ISSUER_TYPE,
        now_iso,
        clock_skew_seconds,
    ) {
        return IdentityChainResult::fail(format!("recognized_issuer_{reason}"));
    }
    if issuer_of(recognized_issuer_credential).as_deref() != Some(trusted_root) {
        return IdentityChainResult::fail("recognized_issuer_not_from_root");
    }

    let rec_subject = match recognized_issuer_credential.get("credentialSubject") {
        Some(Value::Object(o)) => o,
        _ => return IdentityChainResult::fail("recognized_issuer_bad_subject"),
    };
    let recognized_did = match rec_subject.get("id").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return IdentityChainResult::fail("recognized_issuer_no_subject"),
    };
    let actions_ok = rec_subject
        .get("recognizedActions")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().any(|x| x.as_str() == Some(required_action)))
        .unwrap_or(false);
    if !actions_ok {
        return IdentityChainResult::fail("issuer_not_recognized_for_action");
    }

    // 2. The identity must be signed by the recognized issuer.
    if let Err(reason) = verify_trust_credential(
        identity_credential,
        AGENT_IDENTITY_TYPE,
        now_iso,
        clock_skew_seconds,
    ) {
        return IdentityChainResult::fail(format!("identity_{reason}"));
    }
    if issuer_of(identity_credential).as_deref() != Some(recognized_did.as_str()) {
        return IdentityChainResult::fail("identity_not_from_recognized_issuer");
    }

    let id_subject = match identity_credential.get("credentialSubject") {
        Some(Value::Object(o)) => o,
        _ => return IdentityChainResult::fail("identity_bad_subject"),
    };
    let agent_did = match id_subject.get("id").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return IdentityChainResult::fail("identity_no_subject"),
    };
    let attributes = id_subject.get("identity").cloned();

    // 3. Optional: confirm the root credential is genuinely self-issued.
    if let Some(root_cred) = root_credential {
        if let Err(reason) =
            verify_trust_credential(root_cred, ROOT_OF_TRUST_TYPE, now_iso, clock_skew_seconds)
        {
            return IdentityChainResult::fail(format!("root_{reason}"));
        }
        let root_sub = match root_cred.get("credentialSubject") {
            Some(Value::Object(o)) => o,
            _ => return IdentityChainResult::fail("root_bad_subject"),
        };
        let root_sub_id = root_sub.get("id").and_then(|v| v.as_str());
        if issuer_of(root_cred).as_deref() != Some(trusted_root)
            || root_sub_id != Some(trusted_root)
        {
            return IdentityChainResult::fail("root_not_self_issued");
        }
    }

    // 4. Optional: bind the agent's own action to this identity.
    if let Some(action_cred) = action_credential {
        let action_issuer = match issuer_of(action_cred) {
            Some(i) => i,
            None => return IdentityChainResult::fail("action_proof_invalid"),
        };
        match resolve_key(&action_issuer) {
            Some(pk) => match data_integrity::verify_proof(action_cred, &pk) {
                Ok(true) => {}
                _ => return IdentityChainResult::fail("action_proof_invalid"),
            },
            None => return IdentityChainResult::fail("action_proof_invalid"),
        }
        if !within_window(action_cred, now_iso, clock_skew_seconds) {
            return IdentityChainResult::fail("action_proof_invalid");
        }
        if action_issuer != agent_did {
            return IdentityChainResult::fail("action_not_from_agent");
        }
    }

    IdentityChainResult {
        ok: true,
        reason: None,
        agent_did: Some(agent_did),
        issuer_did: Some(recognized_did),
        root_did: Some(trusted_root.to_string()),
        attributes,
    }
}

// ---------------------------------------------------------------------------
// Module-private helpers
// ---------------------------------------------------------------------------

/// Build the unsigned VC envelope shared by all three credential types.
#[allow(clippy::too_many_arguments)]
fn envelope(
    credential_id: &str,
    types: &[&str],
    issuer: &str,
    subject: Value,
    valid_from: &str,
    valid_seconds: i64,
    credential_status: Option<Value>,
) -> Result<Value> {
    let from = iso_to_epoch_seconds(valid_from)?;
    let valid_until = epoch_to_iso(from + valid_seconds);
    let types_val: Vec<Value> = types.iter().map(|t| json!(t)).collect();

    let mut vc = Map::new();
    vc.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    vc.insert("id".into(), json!(credential_id));
    vc.insert("type".into(), Value::Array(types_val));
    vc.insert("issuer".into(), json!(issuer));
    vc.insert("validFrom".into(), json!(valid_from));
    vc.insert("validUntil".into(), json!(valid_until));
    vc.insert("credentialSubject".into(), subject);
    if let Some(status) = credential_status {
        vc.insert("credentialStatus".into(), status);
    }
    Ok(Value::Object(vc))
}

/// Attach an eddsa-jcs-2022 Data Integrity proof to `credential`.
fn sign(credential: &Value, seed: &[u8], issuer_did: &str, created: &str) -> Result<Value> {
    let opts = BuildProofOptions::new(verification_method_of(issuer_did), created);
    data_integrity::sign(credential, seed, &opts)
}

/// did:key DID for a raw 32-byte Ed25519 seed.
fn did_of_seed(seed: &[u8]) -> Result<String> {
    let kp = Ed25519KeyPair::from_seed_slice(seed)?;
    ed25519_to_did_key(&kp.public_key())
}

/// Verify a trust-layer credential (root, recognized-issuer, or identity).
///
/// Checks the type (exactly one trust type), the proof, the proof purpose, that
/// the verification method belongs to the issuer, and the validity window.
/// Returns the Python reason code on failure.
fn verify_trust_credential(
    credential: &Value,
    expected_type: &str,
    now_iso: &str,
    clock_skew_seconds: i64,
) -> std::result::Result<(), &'static str> {
    let obj = match credential.as_object() {
        Some(o) => o,
        None => return Err("not_a_credential"),
    };

    let types = match obj.get("type").and_then(|v| v.as_array()) {
        Some(t) => t,
        None => return Err("wrong_type"),
    };
    if !types.iter().any(|t| t.as_str() == Some(expected_type)) {
        return Err("wrong_type");
    }
    // Exactly one trust-layer type, so the credential cannot double as another
    // link in the chain.
    let trust_count = TRUST_TYPES
        .iter()
        .filter(|tt| types.iter().any(|t| t.as_str() == Some(**tt)))
        .count();
    if trust_count != 1 {
        return Err("ambiguous_type");
    }

    let issuer = match issuer_of(credential) {
        Some(i) if !i.is_empty() => i,
        _ => return Err("no_issuer"),
    };

    let proof = match obj.get("proof").and_then(|p| p.as_object()) {
        Some(p) => p,
        None => return Err("no_proof"),
    };
    if proof.get("proofPurpose").and_then(|v| v.as_str()) != Some("assertionMethod") {
        return Err("bad_proof_purpose");
    }
    match proof.get("verificationMethod").and_then(|v| v.as_str()) {
        Some(vm) if !vm.is_empty() && vm.split('#').next() == Some(issuer.as_str()) => {}
        _ => return Err("vm_mismatch"),
    }

    let public_key = match resolve_key(&issuer) {
        Some(k) => k,
        None => return Err("unresolved_key"),
    };
    match data_integrity::verify_proof(credential, &public_key) {
        Ok(true) => {}
        Ok(false) => return Err("proof_invalid"),
        Err(_) => return Err("proof_malformed"),
    }

    // Temporal window.
    let vf = obj.get("validFrom").and_then(|v| v.as_str());
    let vu = obj.get("validUntil").and_then(|v| v.as_str());
    let (vf, vu) = match (vf, vu) {
        (Some(a), Some(b)) => (a, b),
        _ => return Err("no_validity_window"),
    };
    let now = match iso_to_epoch_seconds(now_iso) {
        Ok(n) => n,
        Err(_) => return Err("no_validity_window"),
    };
    let valid_from = match iso_to_epoch_seconds(vf) {
        Ok(t) => t,
        Err(_) => return Err("no_validity_window"),
    };
    let valid_until = match iso_to_epoch_seconds(vu) {
        Ok(t) => t,
        Err(_) => return Err("no_validity_window"),
    };
    if now - valid_until > clock_skew_seconds {
        return Err("expired");
    }
    if valid_from - now > clock_skew_seconds {
        return Err("not_yet_valid");
    }
    Ok(())
}

/// Whether `now_iso` falls inside the credential's validity window (used for the
/// optional action credential check).
fn within_window(credential: &Value, now_iso: &str, clock_skew_seconds: i64) -> bool {
    let obj = match credential.as_object() {
        Some(o) => o,
        None => return false,
    };
    let vf = obj.get("validFrom").and_then(|v| v.as_str());
    let vu = obj.get("validUntil").and_then(|v| v.as_str());
    let (vf, vu) = match (vf, vu) {
        (Some(a), Some(b)) => (a, b),
        _ => return false,
    };
    let now = match iso_to_epoch_seconds(now_iso) {
        Ok(n) => n,
        Err(_) => return false,
    };
    let from = match iso_to_epoch_seconds(vf) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let until = match iso_to_epoch_seconds(vu) {
        Ok(t) => t,
        Err(_) => return false,
    };
    now >= from - clock_skew_seconds && now <= until + clock_skew_seconds
}

/// Resolve an issuer's Ed25519 public key. Offline for did:key issuers, which is
/// all the vector and the current core support.
fn resolve_key(did: &str) -> Option<Vec<u8>> {
    if did.starts_with("did:key:") {
        did_key_to_ed25519(did).ok()
    } else {
        None
    }
}

/// Return the issuer DID, tolerating the list form used by multi-issuer VCs.
fn issuer_of(credential: &Value) -> Option<String> {
    match credential.get("issuer") {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Array(a)) => a.first().and_then(|v| v.as_str()).map(|s| s.to_string()),
        _ => None,
    }
}

/// Format Unix epoch seconds as "YYYY-MM-DDTHH:MM:SSZ" (inverse of
/// [`iso_to_epoch_seconds`] for whole-second UTC instants).
fn epoch_to_iso(epoch: i64) -> String {
    let days = epoch.div_euclid(86400);
    let secs = epoch.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    let hh = secs / 3600;
    let mm = (secs % 3600) / 60;
    let ss = secs % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Civil date (year, month, day) from days since the Unix epoch. Howard
/// Hinnant's algorithm; the inverse of `time::days_from_civil`.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const ROOT_SEED: [u8; 32] = [0x01; 32];
    const ISSUER_SEED: [u8; 32] = [0x02; 32];
    const AGENT_SEED: [u8; 32] = [0x03; 32];

    const VALID_FROM: &str = "2026-01-01T00:00:00Z";
    const CREATED: &str = "2026-01-01T00:00:00Z";
    const VALID_SECONDS: i64 = 100 * 365 * 24 * 3600;
    const NOW: &str = "2026-07-01T00:00:00Z";

    const ROOT_ID: &str = "urn:uuid:11111111-1111-1111-1111-111111111111";
    const RECOGNITION_ID: &str = "urn:uuid:22222222-2222-2222-2222-222222222222";
    const IDENTITY_ID: &str = "urn:uuid:33333333-3333-3333-3333-333333333333";

    fn load_vector() -> Value {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../test-vectors/root-of-trust/vector.json");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read vector {}: {e}", path.display()));
        serde_json::from_str(&text).expect("vector is valid JSON")
    }

    fn agent_attributes() -> Value {
        json!({ "owner": "Acme", "model": "gpt-x", "capabilityClass": "shopping" })
    }

    fn build_all() -> (Value, Value, Value) {
        let issuer_did = did_of_seed(&ISSUER_SEED).unwrap();
        let agent_did = did_of_seed(&AGENT_SEED).unwrap();

        let root = build_root_of_trust(
            &ROOT_SEED,
            "Vouch Machine Identity Root",
            None,
            VALID_SECONDS,
            VALID_FROM,
            CREATED,
            ROOT_ID,
        )
        .unwrap();

        let recognition = build_recognized_issuer(
            &ROOT_SEED,
            &issuer_did,
            Some(&[ACTION_ISSUE_AGENT_IDENTITY]),
            VALID_SECONDS,
            VALID_FROM,
            CREATED,
            None,
            RECOGNITION_ID,
        )
        .unwrap();

        let identity = build_agent_identity(
            &ISSUER_SEED,
            &agent_did,
            &agent_attributes(),
            VALID_SECONDS,
            VALID_FROM,
            CREATED,
            None,
            IDENTITY_ID,
        )
        .unwrap();

        (root, recognition, identity)
    }

    // (a) Verify Python-signed credentials from the committed interop vector.
    #[test]
    fn verifies_python_signed_vector() {
        let vector = load_vector();
        let trusted_root = vector["trustedRoot"].as_str().unwrap();
        let result = verify_identity_chain(
            &vector["agentIdentity"],
            &vector["recognizedIssuer"],
            trusted_root,
            Some(&vector["rootOfTrust"]),
            None,
            ACTION_ISSUE_AGENT_IDENTITY,
            NOW,
            30,
        );
        assert!(result.ok, "chain must verify: {:?}", result.reason);
        assert_eq!(
            result.agent_did.as_deref(),
            vector["expected"]["agentDid"].as_str()
        );
        assert_eq!(
            result.issuer_did.as_deref(),
            vector["expected"]["issuerDid"].as_str()
        );
        assert_eq!(result.root_did.as_deref(), Some(trusted_root));
    }

    // (b) Reproduce every proofValue byte-for-byte from the same fixed inputs.
    #[test]
    fn reproduces_vector_byte_for_byte() {
        let vector = load_vector();
        let (root, recognition, identity) = build_all();

        assert_eq!(
            root["proof"]["proofValue"], vector["rootOfTrust"]["proof"]["proofValue"],
            "root of trust proofValue diverges from Python"
        );
        assert_eq!(
            recognition["proof"]["proofValue"], vector["recognizedIssuer"]["proof"]["proofValue"],
            "recognized issuer proofValue diverges from Python"
        );
        assert_eq!(
            identity["proof"]["proofValue"], vector["agentIdentity"]["proof"]["proofValue"],
            "agent identity proofValue diverges from Python"
        );

        // The derived DIDs and validity window must also match the vector.
        assert_eq!(root["issuer"], vector["trustedRoot"]);
        assert_eq!(root["validUntil"], vector["rootOfTrust"]["validUntil"]);
        assert_eq!(identity["issuer"], vector["agentIdentity"]["issuer"]);
    }

    // Round-trip: credentials we build verify through our own chain walker.
    #[test]
    fn self_built_chain_verifies() {
        let (root, recognition, identity) = build_all();
        let root_did = did_of_seed(&ROOT_SEED).unwrap();
        let agent_did = did_of_seed(&AGENT_SEED).unwrap();
        let issuer_did = did_of_seed(&ISSUER_SEED).unwrap();

        let result = verify_identity_chain(
            &identity,
            &recognition,
            &root_did,
            Some(&root),
            None,
            ACTION_ISSUE_AGENT_IDENTITY,
            NOW,
            30,
        );
        assert!(result.ok, "self-built chain must verify: {:?}", result.reason);
        assert_eq!(result.agent_did.as_deref(), Some(agent_did.as_str()));
        assert_eq!(result.issuer_did.as_deref(), Some(issuer_did.as_str()));
        assert_eq!(result.attributes, Some(agent_attributes()));
    }

    // (c) Adversarial: a tampered identity proof must break the chain.
    #[test]
    fn tampered_identity_proof_is_rejected() {
        let vector = load_vector();
        let mut identity = vector["agentIdentity"].clone();
        let original = identity["proof"]["proofValue"].as_str().unwrap().to_string();
        // Flip one base58 character so the value still decodes but the signature
        // no longer matches.
        let mut chars: Vec<char> = original.chars().collect();
        let idx = chars.len() - 1;
        chars[idx] = if chars[idx] == 'A' { 'B' } else { 'A' };
        identity["proof"]["proofValue"] = json!(chars.into_iter().collect::<String>());

        let result = verify_identity_chain(
            &identity,
            &vector["recognizedIssuer"],
            vector["trustedRoot"].as_str().unwrap(),
            Some(&vector["rootOfTrust"]),
            None,
            ACTION_ISSUE_AGENT_IDENTITY,
            NOW,
            30,
        );
        assert!(!result.ok, "tampered proof must be rejected");
        assert_eq!(
            result.reason.as_deref(),
            Some("identity_proof_invalid"),
            "unexpected reason for tampered proof"
        );
    }

    // A recognition that does not grant the required action is rejected.
    #[test]
    fn wrong_action_is_rejected() {
        let (root, _recognition, identity) = build_all();
        let root_did = did_of_seed(&ROOT_SEED).unwrap();
        let issuer_did = did_of_seed(&ISSUER_SEED).unwrap();
        let recognition = build_recognized_issuer(
            &ROOT_SEED,
            &issuer_did,
            Some(&[ACTION_ISSUE_ROBOT_IDENTITY]),
            VALID_SECONDS,
            VALID_FROM,
            CREATED,
            None,
            RECOGNITION_ID,
        )
        .unwrap();
        let result = verify_identity_chain(
            &identity,
            &recognition,
            &root_did,
            Some(&root),
            None,
            ACTION_ISSUE_AGENT_IDENTITY,
            NOW,
            30,
        );
        assert!(!result.ok);
        assert_eq!(
            result.reason.as_deref(),
            Some("issuer_not_recognized_for_action")
        );
    }

    // A credential carrying two trust types is ambiguous and rejected.
    #[test]
    fn ambiguous_type_is_rejected() {
        let (_root, recognition, mut identity) = build_all();
        identity["type"] = json!([
            VC_TYPE,
            AGENT_IDENTITY_TYPE,
            RECOGNIZED_ISSUER_TYPE
        ]);
        let root_did = did_of_seed(&ROOT_SEED).unwrap();
        let result = verify_identity_chain(
            &identity,
            &recognition,
            &root_did,
            None,
            None,
            ACTION_ISSUE_AGENT_IDENTITY,
            NOW,
            30,
        );
        assert!(!result.ok);
        assert_eq!(result.reason.as_deref(), Some("identity_ambiguous_type"));
    }

    #[test]
    fn epoch_iso_roundtrip() {
        assert_eq!(epoch_to_iso(0), "1970-01-01T00:00:00Z");
        let from = iso_to_epoch_seconds(VALID_FROM).unwrap();
        assert_eq!(epoch_to_iso(from + VALID_SECONDS), "2125-12-08T00:00:00Z");
    }
}
