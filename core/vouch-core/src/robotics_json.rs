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
