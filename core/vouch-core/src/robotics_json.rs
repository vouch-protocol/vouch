//! JSON facades for the robotics primitives.
//!
//! The robotics core ([`crate::robotics`]) works in typed Rust. These facades
//! present every capability as JSON-in / JSON-out with keys passed as bytes and
//! binary fields carried as multibase strings, so the UniFFI, WASM, and C-ABI
//! wrappers expose robotics to Swift, Kotlin/JVM, .NET, C/C++, and the browser
//! with one shared implementation instead of re-deriving the plumbing per layer.
//!
//! Convention: a verifier that returns "no subject/session" yields the JSON
//! literal `null`; callers test for it.

use serde_json::{json, Value};
use std::collections::HashSet;

use crate::error::{CoreError, Result};
use crate::robotics as r;

fn parse(s: &str) -> Result<Value> {
    serde_json::from_str(s).map_err(|e| CoreError::Json(format!("json: {e}")))
}
fn gs(v: &Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}
fn gos(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(String::from)
}
fn gof(v: &Value, k: &str) -> Option<f64> {
    v.get(k).and_then(|x| x.as_f64())
}
fn gstrs(v: &Value, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|e| e.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}
fn gostrs(v: &Value, k: &str) -> Option<Vec<String>> {
    v.get(k).and_then(|x| x.as_array()).map(|a| {
        a.iter()
            .filter_map(|e| e.as_str().map(String::from))
            .collect()
    })
}
fn gwindows(v: &Value, k: &str) -> Option<Vec<r::ShiftWindow>> {
    v.get(k).and_then(|x| x.as_array()).map(|a| {
        a.iter()
            .map(|w| r::ShiftWindow {
                start: gs(w, "start"),
                end: gs(w, "end"),
            })
            .collect()
    })
}
fn opt_obj(s: Option<&str>) -> Result<Option<Value>> {
    match s {
        Some(t) if !t.is_empty() && t != "null" => Ok(Some(parse(t)?)),
        _ => Ok(None),
    }
}
fn subj(opt: Option<Value>) -> String {
    opt.unwrap_or(Value::Null).to_string()
}

// ---- identity -------------------------------------------------------------

pub fn mint_robot_identity(robot_seed: &[u8], params_json: &str) -> Result<String> {
    let p = parse(params_json)?;
    let params = r::MintRobotIdentity {
        robot_did: gs(&p, "robotDid"),
        make: gs(&p, "make"),
        model: gs(&p, "model"),
        serial: gs(&p, "serial"),
        owner: gos(&p, "owner"),
        root_kind: gs(&p, "rootKind"),
        root_public_multibase: gs(&p, "rootPublicMultibase"),
        attestation: r::unmb64(&gs(&p, "attestation"))?,
        lifecycle: p.get("lifecycle").filter(|v| !v.is_null()).cloned(),
        valid_from: gs(&p, "validFrom"),
        valid_until: gos(&p, "validUntil"),
    };
    Ok(r::mint_robot_identity(robot_seed, &params)?.to_string())
}

pub fn verify_robot_identity(credential_json: &str, robot_pub: &[u8]) -> Result<String> {
    Ok(subj(r::verify_robot_identity(
        &parse(credential_json)?,
        robot_pub,
    )?))
}

// ---- provenance -----------------------------------------------------------

pub fn config_hash(config_json: &str) -> Result<String> {
    Ok(r::config_hash(&parse(config_json)?))
}

pub fn build_provenance_attestation(signer_seed: &[u8], params_json: &str) -> Result<String> {
    let p = parse(params_json)?;
    let params = r::BuildProvenance {
        issuer_did: gs(&p, "issuerDid"),
        robot_did: gs(&p, "robotDid"),
        model_name: gs(&p, "modelName"),
        weights_hash: gs(&p, "weightsHash"),
        safety_policy: gs(&p, "safetyPolicy"),
        config: p.get("config").filter(|v| !v.is_null()).cloned(),
        version: gos(&p, "version"),
        supersedes: gos(&p, "supersedes"),
        valid_from: gs(&p, "validFrom"),
        valid_until: gos(&p, "validUntil"),
    };
    Ok(r::build_provenance_attestation(signer_seed, &params)?.to_string())
}

pub fn verify_provenance_attestation(
    attestation_json: &str,
    public_key: &[u8],
    config_json: Option<&str>,
) -> Result<String> {
    let config = opt_obj(config_json)?;
    Ok(subj(r::verify_provenance_attestation(
        &parse(attestation_json)?,
        public_key,
        config.as_ref(),
    )?))
}

// ---- capability -----------------------------------------------------------

pub fn build_physical_scope_credential(signer_seed: &[u8], params_json: &str) -> Result<String> {
    let p = parse(params_json)?;
    let params = r::BuildPhysicalScope {
        issuer_did: gs(&p, "issuerDid"),
        subject_did: gs(&p, "subjectDid"),
        max_force_n: gof(&p, "maxForceN"),
        max_speed_mps: gof(&p, "maxSpeedMps"),
        max_speed_near_humans_mps: gof(&p, "maxSpeedNearHumansMps"),
        allowed_zones: gostrs(&p, "allowedZones"),
        shift_windows: gwindows(&p, "shiftWindows"),
        valid_from: gs(&p, "validFrom"),
        valid_until: gos(&p, "validUntil"),
    };
    Ok(r::build_physical_scope_credential(signer_seed, &params)?.to_string())
}

pub fn check_physical_action(scope_json: &str, action_json: &str) -> Result<String> {
    let a = parse(action_json)?;
    let action = r::PhysicalAction {
        force_n: gof(&a, "forceN"),
        speed_mps: gof(&a, "speedMps"),
        near_humans: a
            .get("nearHumans")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        zone: gos(&a, "zone"),
        time_hm: gos(&a, "timeHm"),
    };
    let res = r::check_physical_action(&parse(scope_json)?, &action);
    Ok(json!({"ok": res.ok, "reasons": res.reasons}).to_string())
}

pub fn attenuates(parent_json: &str, child_json: &str) -> Result<bool> {
    Ok(r::attenuates(&parse(parent_json)?, &parse(child_json)?))
}

// ---- handshake ------------------------------------------------------------

fn policy(policy_json: Option<&str>) -> Result<Option<r::TrustPolicy>> {
    match opt_obj(policy_json)? {
        Some(v) => Ok(Some(r::TrustPolicy::new(
            gstrs(&v, "trustedDomains"),
            v.get("acceptUnknown")
                .and_then(|x| x.as_bool())
                .unwrap_or(false),
        ))),
        None => Ok(None),
    }
}

fn session_to_json(s: &r::BoundedSession) -> Value {
    json!({
        "sessionId": s.session_id,
        "initiator": s.initiator,
        "responder": s.responder,
        "scope": s.scope,
        "nonce": s.nonce,
        "validUntil": s.valid_until,
    })
}

fn session_from_json(v: &Value) -> r::BoundedSession {
    r::BoundedSession {
        session_id: gs(v, "sessionId"),
        initiator: gs(v, "initiator"),
        responder: gs(v, "responder"),
        scope: gstrs(v, "scope"),
        nonce: gs(v, "nonce"),
        valid_until: gos(v, "validUntil"),
    }
}

pub fn build_hello(signer_seed: &[u8], params_json: &str) -> Result<String> {
    let p = parse(params_json)?;
    let params = r::BuildHello {
        from_did: gs(&p, "fromDid"),
        proposed_scope: gstrs(&p, "proposedScope"),
        nonce: gs(&p, "nonce"),
        peer_did: gos(&p, "peerDid"),
        issued_at: gs(&p, "issuedAt"),
    };
    Ok(r::build_hello(signer_seed, &params)?.to_string())
}

pub fn build_accept(
    signer_seed: &[u8],
    hello_json: &str,
    hello_public_key: &[u8],
    policy_json: &str,
    params_json: &str,
) -> Result<String> {
    let pol = policy(Some(policy_json))?.unwrap_or_default();
    let p = parse(params_json)?;
    let params = r::BuildAccept {
        from_did: gs(&p, "fromDid"),
        offered_scope: gstrs(&p, "offeredScope"),
        session_id: gs(&p, "sessionId"),
        valid_until: gs(&p, "validUntil"),
        created: gs(&p, "created"),
    };
    Ok(r::build_accept(
        signer_seed,
        &parse(hello_json)?,
        hello_public_key,
        &pol,
        &params,
    )?
    .to_string())
}

pub fn verify_accept(
    accept_json: &str,
    accept_public_key: &[u8],
    expected_nonce: &str,
    policy_json: Option<&str>,
) -> Result<String> {
    let pol = policy(policy_json)?;
    let session = r::verify_accept(
        &parse(accept_json)?,
        accept_public_key,
        expected_nonce,
        pol.as_ref(),
    )?;
    Ok(session
        .map(|s| session_to_json(&s))
        .unwrap_or(Value::Null)
        .to_string())
}

pub fn build_confirm(
    signer_seed: &[u8],
    from_did: &str,
    session_json: &str,
    created: &str,
) -> Result<String> {
    let session = session_from_json(&parse(session_json)?);
    Ok(r::build_confirm(signer_seed, from_did, &session, created)?.to_string())
}

pub fn verify_confirm(
    confirm_json: &str,
    confirm_public_key: &[u8],
    session_id: &str,
    expected_nonce: &str,
) -> Result<bool> {
    r::verify_confirm(
        &parse(confirm_json)?,
        confirm_public_key,
        session_id,
        expected_nonce,
    )
}

// ---- black box and kill switch -------------------------------------------

pub fn genesis_prev_hash() -> String {
    r::genesis_prev_hash()
}

pub fn blackbox_append_entry(
    key: &[u8],
    seq: u64,
    event: &str,
    payload_json: &str,
    timestamp: &str,
    prev_hash: &str,
) -> Result<String> {
    Ok(
        r::blackbox_append_entry(key, seq, event, &parse(payload_json)?, timestamp, prev_hash)?
            .to_string(),
    )
}

pub fn blackbox_open_entry(entry_json: &str, key: &[u8]) -> Result<String> {
    Ok(r::open_entry(&parse(entry_json)?, key)?.to_string())
}

pub fn verify_blackbox_chain(
    entries_json: &str,
    genesis_prev_hash: Option<&str>,
) -> Result<String> {
    let entries = parse(entries_json)?;
    let arr = entries
        .as_array()
        .ok_or_else(|| CoreError::Json("entries must be a JSON array".into()))?;
    let res = r::verify_blackbox_chain(arr, genesis_prev_hash);
    Ok(json!({"ok": res.ok, "reason": res.reason}).to_string())
}

pub fn build_killswitch_credential(authority_seed: &[u8], params_json: &str) -> Result<String> {
    let p = parse(params_json)?;
    let params = r::BuildKillswitch {
        issuer_did: gs(&p, "issuerDid"),
        target: gs(&p, "target"),
        reason: gs(&p, "reason"),
        command: gos(&p, "command"),
        scope: gostrs(&p, "scope"),
        valid_from: gs(&p, "validFrom"),
        valid_until: gos(&p, "validUntil"),
    };
    Ok(r::build_killswitch_credential(authority_seed, &params)?.to_string())
}

pub fn verify_killswitch_credential(
    credential_json: &str,
    public_key: &[u8],
    trusted_authorities_json: Option<&str>,
) -> Result<String> {
    let trusted: Option<HashSet<String>> = opt_obj(trusted_authorities_json)?.map(|v| {
        v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|e| e.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    });
    Ok(subj(r::verify_killswitch_credential(
        &parse(credential_json)?,
        public_key,
        trusted.as_ref(),
    )?))
}

// ---- passport -------------------------------------------------------------

pub fn build_passport(signer_seed: &[u8], params_json: &str) -> Result<String> {
    let p = parse(params_json)?;
    let params = r::BuildPassport {
        issuer_did: gs(&p, "issuerDid"),
        robot_did: gs(&p, "robotDid"),
        make: gs(&p, "make"),
        model: gs(&p, "model"),
        owner: gs(&p, "owner"),
        authorized_actions: gstrs(&p, "authorizedActions"),
        certification: gos(&p, "certification"),
        status: gos(&p, "status"),
        valid_from: gs(&p, "validFrom"),
        valid_until: gos(&p, "validUntil"),
    };
    Ok(r::build_passport(signer_seed, &params)?.to_string())
}

pub fn encode_passport(passport_json: &str) -> Result<String> {
    Ok(r::encode_passport(&parse(passport_json)?))
}

pub fn decode_passport(uri: &str) -> Result<String> {
    Ok(r::decode_passport(uri)?.to_string())
}

pub fn verify_passport(passport_json: &str, public_key: &[u8], now_iso: &str) -> Result<String> {
    Ok(subj(r::verify_passport(
        &parse(passport_json)?,
        public_key,
        now_iso,
    )?))
}

pub fn verify_passport_uri(uri: &str, public_key: &[u8], now_iso: &str) -> Result<String> {
    Ok(subj(r::verify_passport_uri(uri, public_key, now_iso)?))
}

// ---- liveness -------------------------------------------------------------

fn gi(v: &Value, k: &str) -> i64 {
    v.get(k).and_then(|x| x.as_i64()).unwrap_or(0)
}

/// Build a motionDigest from a JSON array of samples against an optional scope.
/// `params_json` is `{"scope": {...}|null, "samples": [{forceN, speedMps,
/// nearHumans, zone, timeHm}, ...]}`.
pub fn motion_digest(params_json: &str) -> Result<String> {
    let p = parse(params_json)?;
    let scope = p.get("scope").filter(|v| !v.is_null()).cloned();
    let mut collector = r::MotionCollector::new(scope);
    if let Some(samples) = p.get("samples").and_then(|v| v.as_array()) {
        for s in samples {
            collector.record(&r::MotionSample {
                force_n: gof(s, "forceN"),
                speed_mps: gof(s, "speedMps"),
                near_humans: s
                    .get("nearHumans")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                zone: gos(s, "zone"),
                time_hm: gos(s, "timeHm"),
            })?;
        }
    }
    Ok(collector.digest().to_string())
}

pub fn validate_motion_digest(digest_json: &str) -> Result<bool> {
    Ok(r::validate_motion_digest(&parse(digest_json)?).is_ok())
}

pub fn build_robot_heartbeat(robot_seed: &[u8], params_json: &str) -> Result<String> {
    let p = parse(params_json)?;
    let params = r::BuildRobotHeartbeat {
        robot_did: gs(&p, "robotDid"),
        session_id: gs(&p, "sessionId"),
        interval_index: gi(&p, "intervalIndex"),
        interval_seconds: gi(&p, "intervalSeconds"),
        motion_digest: p.get("motionDigest").cloned().unwrap_or(Value::Null),
        valid_from: gs(&p, "validFrom"),
    };
    Ok(r::build_robot_heartbeat(robot_seed, &params)?.to_string())
}

pub fn verify_robot_heartbeat(credential_json: &str, robot_public_key: &[u8]) -> Result<String> {
    Ok(subj(r::verify_robot_heartbeat(
        &parse(credential_json)?,
        robot_public_key,
    )?))
}

pub fn is_live(
    credential_json: &str,
    now_iso: &str,
    interval_seconds: Option<i64>,
    grace_intervals: i64,
) -> Result<bool> {
    r::is_live(
        &parse(credential_json)?,
        now_iso,
        interval_seconds,
        grace_intervals,
    )
}

// ---- revocation -----------------------------------------------------------

pub fn build_status_list_entry(
    status_list_credential: &str,
    status_list_index: i64,
    status_purpose: &str,
    entry_id: Option<&str>,
) -> Result<String> {
    Ok(r::build_status_list_entry(
        status_list_credential,
        status_list_index,
        status_purpose,
        entry_id,
    )?
    .to_string())
}

pub fn attach_credential_status(
    credential_json: &str,
    signer_seed: &[u8],
    params_json: &str,
) -> Result<String> {
    let p = parse(params_json)?;
    let params = r::AttachCredentialStatus {
        status_list_credential: gs(&p, "statusListCredential"),
        status_list_index: gi(&p, "statusListIndex"),
        status_purpose: gos(&p, "statusPurpose")
            .unwrap_or_else(|| r::STATUS_PURPOSE_REVOCATION.to_string()),
        entry_id: gos(&p, "entryId"),
        created: gs(&p, "created"),
    };
    Ok(r::attach_credential_status(&parse(credential_json)?, signer_seed, &params)?.to_string())
}

pub fn check_credential_status(
    credential_json: &str,
    status_list_credential_json: &str,
    status_purpose: &str,
) -> Result<bool> {
    r::check_credential_status(
        &parse(credential_json)?,
        &parse(status_list_credential_json)?,
        status_purpose,
    )
}

// ---- safety record --------------------------------------------------------

/// Append one event to a ledger and return `{entry, head}`. The chain is
/// stateless across calls: pass the previous head as `prevHash` (or the genesis).
/// `params_json` is `{eventType, severity, details?, actor?, timestamp,
/// prevHash, seq}`.
pub fn safety_append_entry(params_json: &str) -> Result<String> {
    let p = parse(params_json)?;
    let prev = gs(&p, "prevHash");
    let mut log = r::SafetyEventLog::new(Some(&prev));
    let entry = log.append(
        &gs(&p, "eventType"),
        &gs(&p, "severity"),
        p.get("details").filter(|v| !v.is_null()),
        p.get("actor").and_then(|v| v.as_str()),
        &gs(&p, "timestamp"),
    )?;
    Ok(json!({"entry": entry, "head": log.head()}).to_string())
}

pub fn verify_safety_log(entries_json: &str, genesis_prev_hash: Option<&str>) -> Result<String> {
    let entries = parse(entries_json)?;
    let arr = entries
        .as_array()
        .ok_or_else(|| CoreError::Json("entries must be a JSON array".into()))?;
    let res = r::verify_safety_log(arr, genesis_prev_hash);
    Ok(json!({"ok": res.ok, "reason": res.reason}).to_string())
}

pub fn summarize_entries(entries_json: &str, head: Option<&str>) -> Result<String> {
    let entries = parse(entries_json)?;
    let arr = entries
        .as_array()
        .ok_or_else(|| CoreError::Json("entries must be a JSON array".into()))?;
    Ok(r::summarize_entries(arr, head).to_string())
}

pub fn build_safety_record(signer_seed: &[u8], params_json: &str) -> Result<String> {
    let p = parse(params_json)?;
    let params = r::BuildSafetyRecord {
        issuer_did: gs(&p, "issuerDid"),
        robot_did: gs(&p, "robotDid"),
        summary: p.get("summary").cloned().unwrap_or(Value::Null),
        period_start: gos(&p, "periodStart"),
        period_end: gos(&p, "periodEnd"),
        valid_from: gs(&p, "validFrom"),
        valid_until: gos(&p, "validUntil"),
    };
    Ok(r::build_safety_record(signer_seed, &params)?.to_string())
}

pub fn verify_safety_record(credential_json: &str, public_key: &[u8]) -> Result<String> {
    Ok(subj(r::verify_safety_record(
        &parse(credential_json)?,
        public_key,
    )?))
}

// ---- perception provenance ------------------------------------------------

/// Multibase SHA-256 of a raw sensor frame.
pub fn hash_frame(frame: &[u8]) -> String {
    r::hash_frame(frame)
}

/// Append one frame-provenance record to a log and return `{entry, head}`. The
/// chain is stateless across calls: pass the previous head as `prevHash` (or the
/// genesis). `params_json` is `{sensorId, modality, frameHash|frame_mb,
/// timestamp, prevHash}` where `frame_mb` is a multibase-encoded raw frame.
pub fn perception_record_entry(params_json: &str) -> Result<String> {
    let p = parse(params_json)?;
    let prev = gs(&p, "prevHash");
    let mut log = r::PerceptionLog::new(Some(&prev));
    let frame = match gos(&p, "frameMb") {
        Some(mb) => Some(r::unmb64(&mb)?),
        None => None,
    };
    let entry = log.record(
        &gs(&p, "sensorId"),
        &gs(&p, "modality"),
        frame.as_deref(),
        p.get("frameHash").and_then(|v| v.as_str()),
        &gs(&p, "timestamp"),
    )?;
    Ok(json!({"entry": entry, "head": log.head()}).to_string())
}

pub fn verify_perception_log(
    entries_json: &str,
    genesis_prev_hash: Option<&str>,
) -> Result<String> {
    let entries = parse(entries_json)?;
    let arr = entries
        .as_array()
        .ok_or_else(|| CoreError::Json("entries must be a JSON array".into()))?;
    let res = r::verify_perception_log(arr, genesis_prev_hash);
    Ok(json!({"ok": res.ok, "reason": res.reason}).to_string())
}

pub fn build_perception_attestation(robot_seed: &[u8], params_json: &str) -> Result<String> {
    let p = parse(params_json)?;
    let params = r::BuildPerception {
        robot_did: gs(&p, "robotDid"),
        sensor_id: gs(&p, "sensorId"),
        modality: gs(&p, "modality"),
        frame_hash: gs(&p, "frameHash"),
        captured_at: gos(&p, "capturedAt"),
        log_head: gos(&p, "logHead"),
        valid_from: gs(&p, "validFrom"),
        valid_until: gos(&p, "validUntil"),
    };
    Ok(r::build_perception_attestation(robot_seed, &params)?.to_string())
}

/// Verify a perception attestation. When `frame_mb` is a non-empty multibase
/// string, the raw frame is decoded and its hash compared to the attested value.
pub fn verify_perception_attestation(
    credential_json: &str,
    public_key: &[u8],
    frame_mb: Option<&str>,
) -> Result<String> {
    let frame = match frame_mb {
        Some(mb) if !mb.is_empty() => Some(r::unmb64(mb)?),
        _ => None,
    };
    Ok(subj(r::verify_perception_attestation(
        &parse(credential_json)?,
        public_key,
        frame.as_deref(),
    )?))
}

// ---- delegation lease -----------------------------------------------------

pub fn build_delegation_lease(signer_seed: &[u8], params_json: &str) -> Result<String> {
    let p = parse(params_json)?;
    let params = r::BuildDelegationLease {
        issuer_did: gs(&p, "issuerDid"),
        robot_did: gs(&p, "robotDid"),
        lease_id: gs(&p, "leaseId"),
        scope: p.get("scope").cloned().unwrap_or(Value::Null),
        parent_lease_id: gos(&p, "parentLeaseId"),
        valid_from: gs(&p, "validFrom"),
        valid_until: gs(&p, "validUntil"),
    };
    Ok(r::build_delegation_lease(signer_seed, &params)?.to_string())
}

pub fn verify_delegation_lease(
    credential_json: &str,
    public_key: &[u8],
    now_iso: Option<&str>,
    parent_scope_json: Option<&str>,
) -> Result<String> {
    let now = match now_iso {
        Some(n) if !n.is_empty() && n != "null" => Some(n),
        _ => None,
    };
    let parent = opt_obj(parent_scope_json)?;
    Ok(subj(r::verify_delegation_lease(
        &parse(credential_json)?,
        public_key,
        now,
        parent.as_ref(),
    )?))
}

/// Decide whether a verified lease subject permits a proposed action.
/// `params_json` is `{subject, action, credential?, now?}` where `action` is the
/// same shape as [`check_physical_action`]'s action object.
pub fn lease_permits(params_json: &str) -> Result<bool> {
    let p = parse(params_json)?;
    let subject = p.get("subject").cloned().unwrap_or(Value::Null);
    let a = p.get("action").cloned().unwrap_or(Value::Null);
    let action = r::PhysicalAction {
        force_n: gof(&a, "forceN"),
        speed_mps: gof(&a, "speedMps"),
        near_humans: a
            .get("nearHumans")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        zone: gos(&a, "zone"),
        time_hm: gos(&a, "timeHm"),
    };
    let credential = p.get("credential").filter(|v| !v.is_null()).cloned();
    let now = gos(&p, "now");
    Ok(r::lease_permits(
        &subject,
        &action,
        credential.as_ref(),
        now.as_deref(),
    ))
}

// ---- physical quorum ------------------------------------------------------

pub fn build_action_approval(approver_seed: &[u8], params_json: &str) -> Result<String> {
    let p = parse(params_json)?;
    let params = r::BuildActionApproval {
        approver_did: gs(&p, "approverDid"),
        action_id: gs(&p, "actionId"),
        robot_did: gs(&p, "robotDid"),
        decision: gos(&p, "decision").unwrap_or_else(|| r::APPROVE.to_string()),
        valid_from: gs(&p, "validFrom"),
        valid_until: gos(&p, "validUntil"),
    };
    Ok(r::build_action_approval(approver_seed, &params)?.to_string())
}

/// Verify a quorum authorization. `params_json` is `{approvals: [...], actionId,
/// robotDid, approverKeys: {did: keyB64url, ...}, threshold, approverSet?: [...],
/// now?}`. Each `approverKeys` value is the approver's Ed25519 public key as a
/// base64url-no-pad string (the same encoding as a JWK `x`). Returns
/// `{authorized, approvers: [...]}`.
pub fn verify_action_authorization(params_json: &str) -> Result<String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let p = parse(params_json)?;
    let approvals: Vec<Value> = p
        .get("approvals")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let action_id = gs(&p, "actionId");
    let robot_did = gs(&p, "robotDid");
    let threshold = p.get("threshold").and_then(|v| v.as_i64()).unwrap_or(0);

    let mut keys: Vec<r::ApproverKey> = Vec::new();
    if let Some(obj) = p.get("approverKeys").and_then(|v| v.as_object()) {
        for (did, key) in obj {
            let b64 = key
                .as_str()
                .ok_or_else(|| CoreError::Json("approverKeys values must be base64url".into()))?;
            let public_key = URL_SAFE_NO_PAD
                .decode(b64)
                .map_err(|e| CoreError::Json(format!("bad base64url: {e}")))?;
            keys.push(r::ApproverKey {
                did: did.clone(),
                public_key,
            });
        }
    }

    let approver_set: Option<HashSet<String>> = p
        .get("approverSet")
        .filter(|v| !v.is_null())
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|e| e.as_str().map(String::from))
                .collect()
        });
    let now = gos(&p, "now");

    let (authorized, approvers) = r::verify_action_authorization(
        &approvals,
        &action_id,
        &robot_did,
        &keys,
        threshold,
        approver_set.as_ref(),
        now.as_deref(),
    )?;
    Ok(json!({"authorized": authorized, "approvers": approvers}).to_string())
}

// ---- robot lifecycle ------------------------------------------------------

fn owner_keys(v: &Value) -> Result<Vec<r::OwnerKey>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let mut keys: Vec<r::OwnerKey> = Vec::new();
    if let Some(obj) = v.as_object() {
        for (did, key) in obj {
            let b64 = key
                .as_str()
                .ok_or_else(|| CoreError::Json("publicKeys values must be base64url".into()))?;
            let public_key = URL_SAFE_NO_PAD
                .decode(b64)
                .map_err(|e| CoreError::Json(format!("bad base64url: {e}")))?;
            keys.push(r::OwnerKey {
                did: did.clone(),
                public_key,
            });
        }
    }
    Ok(keys)
}

fn key_entries(v: &Value) -> Result<Vec<r::KeyEntry>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let mut keys: Vec<r::KeyEntry> = Vec::new();
    if let Some(obj) = v.as_object() {
        for (multibase, key) in obj {
            let b64 = key
                .as_str()
                .ok_or_else(|| CoreError::Json("publicKeys values must be base64url".into()))?;
            let public_key = URL_SAFE_NO_PAD
                .decode(b64)
                .map_err(|e| CoreError::Json(format!("bad base64url: {e}")))?;
            keys.push(r::KeyEntry {
                multibase: multibase.clone(),
                public_key,
            });
        }
    }
    Ok(keys)
}

pub fn build_ownership_transfer(current_owner_seed: &[u8], params_json: &str) -> Result<String> {
    let p = parse(params_json)?;
    let params = r::BuildOwnershipTransfer {
        issuer_did: gs(&p, "issuerDid"),
        robot_did: gs(&p, "robotDid"),
        to_owner: gs(&p, "toOwner"),
        from_owner: gos(&p, "fromOwner"),
        prev_transfer_id: gos(&p, "prevTransferId"),
        valid_from: gs(&p, "validFrom"),
    };
    Ok(r::build_ownership_transfer(current_owner_seed, &params)?.to_string())
}

pub fn verify_ownership_transfer(credential_json: &str, public_key: &[u8]) -> Result<String> {
    Ok(subj(r::verify_ownership_transfer(
        &parse(credential_json)?,
        public_key,
    )?))
}

/// Verify a chain of custody. `params_json` is `{transfers: [...], publicKeys:
/// {did: keyB64url, ...}, originOwner?}` where each `publicKeys` value is the
/// owner's Ed25519 public key as a base64url-no-pad string. Returns `{ok,
/// currentOwner}`.
pub fn verify_custody_chain(params_json: &str) -> Result<String> {
    let p = parse(params_json)?;
    let transfers: Vec<Value> = p
        .get("transfers")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let keys = owner_keys(p.get("publicKeys").unwrap_or(&Value::Null))?;
    let origin = gos(&p, "originOwner");
    let (ok, current) = r::verify_custody_chain(&transfers, &keys, origin.as_deref())?;
    Ok(json!({"ok": ok, "currentOwner": current}).to_string())
}

pub fn build_key_rotation(old_key_seed: &[u8], params_json: &str) -> Result<String> {
    let p = parse(params_json)?;
    let params = r::BuildKeyRotation {
        robot_did: gs(&p, "robotDid"),
        new_key_multibase: gs(&p, "newKey"),
        reason: gos(&p, "reason"),
        valid_from: gs(&p, "validFrom"),
    };
    Ok(r::build_key_rotation(old_key_seed, &params)?.to_string())
}

pub fn verify_key_rotation(credential_json: &str, old_public_key: &[u8]) -> Result<String> {
    Ok(subj(r::verify_key_rotation(
        &parse(credential_json)?,
        old_public_key,
    )?))
}

/// Verify a key history. `params_json` is `{rotations: [...], originKey,
/// publicKeys: {keyMultibase: keyB64url, ...}}` where each `publicKeys` value is
/// the Ed25519 public key as a base64url-no-pad string keyed by its multibase.
/// Returns `{ok, currentKey}`.
pub fn verify_key_history(params_json: &str) -> Result<String> {
    let p = parse(params_json)?;
    let rotations: Vec<Value> = p
        .get("rotations")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let origin_key = gs(&p, "originKey");
    let keys = key_entries(p.get("publicKeys").unwrap_or(&Value::Null))?;
    let (ok, current) = r::verify_key_history(&rotations, &origin_key, &keys)?;
    Ok(json!({"ok": ok, "currentKey": current}).to_string())
}

pub fn build_decommission(signer_seed: &[u8], params_json: &str) -> Result<String> {
    let p = parse(params_json)?;
    let params = r::BuildDecommission {
        issuer_did: gs(&p, "issuerDid"),
        robot_did: gs(&p, "robotDid"),
        reason: gs(&p, "reason"),
        final_disposition: gos(&p, "finalDisposition"),
        valid_from: gs(&p, "validFrom"),
        valid_until: gos(&p, "validUntil"),
    };
    Ok(r::build_decommission(signer_seed, &params)?.to_string())
}

pub fn verify_decommission(
    credential_json: &str,
    public_key: &[u8],
    trusted_authorities_json: Option<&str>,
) -> Result<String> {
    let trusted: Option<HashSet<String>> = opt_obj(trusted_authorities_json)?.map(|v| {
        v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|e| e.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    });
    Ok(subj(r::verify_decommission(
        &parse(credential_json)?,
        public_key,
        trusted.as_ref(),
    )?))
}

// ---- regulatory conformance -----------------------------------------------

/// Check a credential set against a named profile and return the report.
/// `credentials_json` is a JSON array of credentials.
pub fn check_conformance(credentials_json: &str, profile_id: &str) -> Result<String> {
    let credentials = parse(credentials_json)?;
    let arr = credentials
        .as_array()
        .ok_or_else(|| CoreError::Json("credentials must be a JSON array".into()))?;
    Ok(r::check_conformance(arr, profile_id)?.to_string())
}

/// Multibase SHA-256 of the JCS-canonical report.
pub fn report_digest(report_json: &str) -> Result<String> {
    Ok(r::report_digest(&parse(report_json)?))
}

/// Build a signed `RobotConformanceAttestation`. `params_json` is `{issuerDid,
/// robotDid, report, validFrom, validUntil?}` where `report` comes from
/// [`check_conformance`].
pub fn build_conformance_attestation(signer_seed: &[u8], params_json: &str) -> Result<String> {
    let p = parse(params_json)?;
    let params = r::BuildConformanceAttestation {
        issuer_did: gs(&p, "issuerDid"),
        robot_did: gs(&p, "robotDid"),
        report: p.get("report").cloned().unwrap_or(Value::Null),
        valid_from: gs(&p, "validFrom"),
        valid_until: gos(&p, "validUntil"),
    };
    Ok(r::build_conformance_attestation(signer_seed, &params)?.to_string())
}

pub fn verify_conformance_attestation(credential_json: &str, public_key: &[u8]) -> Result<String> {
    Ok(subj(r::verify_conformance_attestation(
        &parse(credential_json)?,
        public_key,
    )?))
}
