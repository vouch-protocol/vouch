//! Delegation links and time-bound chain validation.
//!
//! A delegation link carries an issuer, subject, intent, and an optional
//! validity window (Specification 9.2). Time-bound validation enforces that each
//! link's window is within its parent's (time attenuation, 9.3 step 6) and that
//! the current instant is within the narrowest link's window. The full v1.7
//! capability-attenuation rule across the other dimensions lives with the SDKs;
//! this core provides the link structure plus the deterministic temporal checks.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use crate::attenuation;
use crate::data_integrity;
use crate::error::{CoreError, Result};
use crate::multikey;
use crate::time::iso_to_epoch_seconds;

/// Inputs for one delegation link.
#[derive(Debug, Clone)]
pub struct DelegationLinkInput {
    pub issuer: String,
    pub subject: String,
    pub intent: Value,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub parent_proof_value: Option<String>,
}

/// Build a delegation link object (field order matches the SDK).
pub fn build_delegation_link(input: &DelegationLinkInput) -> Value {
    let mut link = Map::new();
    link.insert("issuer".into(), json!(input.issuer));
    link.insert("subject".into(), json!(input.subject));
    link.insert("intent".into(), input.intent.clone());
    if let Some(vf) = &input.valid_from {
        link.insert("validFrom".into(), json!(vf));
    }
    if let Some(vu) = &input.valid_until {
        link.insert("validUntil".into(), json!(vu));
    }
    if let Some(pp) = &input.parent_proof_value {
        link.insert("parentProofValue".into(), json!(pp));
    }
    Value::Object(link)
}

fn link_window(link: &Value) -> Result<(Option<i64>, Option<i64>)> {
    let obj = link
        .as_object()
        .ok_or_else(|| CoreError::Json("delegation link must be an object".into()))?;
    let vf = match obj.get("validFrom").and_then(|v| v.as_str()) {
        Some(s) => Some(iso_to_epoch_seconds(s)?),
        None => None,
    };
    let vu = match obj.get("validUntil").and_then(|v| v.as_str()) {
        Some(s) => Some(iso_to_epoch_seconds(s)?),
        None => None,
    };
    Ok((vf, vu))
}

/// Validate the time-bound rule over a chain ordered root -> leaf: every link's
/// window is within its parent's, and `now_iso` falls within the last link's
/// window (allowing clock skew). Returns Ok(true) if the chain is time-valid.
pub fn verify_chain_time_bound(
    chain: &[Value],
    now_iso: &str,
    clock_skew_seconds: i64,
) -> Result<bool> {
    let now = iso_to_epoch_seconds(now_iso)?;
    let mut parent: Option<(Option<i64>, Option<i64>)> = None;

    for link in chain {
        let (vf, vu) = link_window(link)?;
        if let Some((pf, pu)) = parent {
            if let (Some(f), Some(pf)) = (vf, pf) {
                if f < pf {
                    return Ok(false); // child starts before parent
                }
            }
            if let (Some(u), Some(pu)) = (vu, pu) {
                if u > pu {
                    return Ok(false); // child ends after parent
                }
            }
        }
        parent = Some((vf, vu));
    }

    if let Some((vf, vu)) = parent {
        if let Some(f) = vf {
            if now < f - clock_skew_seconds {
                return Ok(false);
            }
        }
        if let Some(u) = vu {
            if now > u + clock_skew_seconds {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// Delegation chain verification (Specification 9.3)
// ---------------------------------------------------------------------------
//
// A faithful port of `vouch.verifier.verify_delegation_chain` (Python is the
// reference). Every step and reason code matches it exactly; the shared vectors
// in `test-vectors/delegation-chain/vector.json` are the contract.

/// Map a signed Vouch credential onto the six-dimension link shape that
/// `attenuation::non_expansion` compares: action / target / resource from
/// `credentialSubject.intent`, time from `validFrom` / `validUntil`, rate and
/// policy from `intent.rate` / `intent.policy`, subject from `intent.delegatee`.
pub fn capability_view(credential: &Value, include_time: bool) -> Value {
    let intent = credential
        .get("credentialSubject")
        .and_then(|s| s.get("intent"))
        .and_then(|i| i.as_object())
        .cloned()
        .unwrap_or_default();
    let mut view = Map::new();
    view.insert(
        "issuer".into(),
        issuer_did(credential)
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    view.insert(
        "subject".into(),
        intent.get("delegatee").cloned().unwrap_or(Value::Null),
    );
    let mut dims = Map::new();
    for k in ["action", "target", "resource", "amount"] {
        if let Some(v) = intent.get(k) {
            dims.insert(k.into(), v.clone());
        }
    }
    view.insert("intent".into(), Value::Object(dims));
    if include_time {
        for k in ["validFrom", "validUntil"] {
            if let Some(v) = credential.get(k) {
                view.insert(k.into(), v.clone());
            }
        }
    }
    for k in ["rate", "policy"] {
        if let Some(v) = intent.get(k) {
            view.insert(k.into(), v.clone());
        }
    }
    Value::Object(view)
}

fn issuer_did(credential: &Value) -> Option<String> {
    match credential.get("issuer") {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Array(a)) => a.first().and_then(|v| v.as_str()).map(String::from),
        Some(Value::Object(o)) => o.get("id").and_then(|v| v.as_str()).map(String::from),
        _ => None,
    }
}

fn resolve_chain_key(did: &str, root_keys: &BTreeMap<String, Vec<u8>>) -> Option<Vec<u8>> {
    if let Some(k) = root_keys.get(did) {
        return Some(k.clone());
    }
    let mk = did.strip_prefix("did:key:")?;
    let decoded = multikey::decode(mk).ok()?;
    if decoded.algorithm == "Ed25519" {
        Some(decoded.raw_key)
    } else {
        None
    }
}

/// The proof value a link binds to its parent: the eddsa-jcs-2022 member of a
/// proof set, else the first proof value, else a single proof's value.
fn parent_proof_binding_value(grant: &Value) -> String {
    match grant.get("proof") {
        Some(Value::Array(items)) => {
            for p in items {
                if p.get("cryptosuite").and_then(|v| v.as_str())
                    == Some(data_integrity::CRYPTOSUITE_ID)
                {
                    return p
                        .get("proofValue")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                }
            }
            for p in items {
                if let Some(v) = p.get("proofValue").and_then(|v| v.as_str()) {
                    if !v.is_empty() {
                        return v.to_string();
                    }
                }
            }
            String::new()
        }
        Some(Value::Object(p)) => p
            .get("proofValue")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        _ => String::new(),
    }
}

fn verify_grant_proof(grant: &Value, issuer: &str, key: &[u8]) -> bool {
    let proofs: Vec<&Value> = match grant.get("proof") {
        Some(Value::Array(items)) => items.iter().collect(),
        Some(p) => vec![p],
        None => return false,
    };
    let body: Map<String, Value> = match grant.as_object() {
        Some(o) => o
            .iter()
            .filter(|(k, _)| k.as_str() != "proof")
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        None => return false,
    };
    for proof in proofs {
        let Some(p) = proof.as_object() else { continue };
        match p.get("cryptosuite") {
            None => {}
            Some(Value::String(s)) if s == data_integrity::CRYPTOSUITE_ID => {}
            _ => continue,
        }
        if p.get("proofPurpose").and_then(|v| v.as_str()) != Some("assertionMethod") {
            continue;
        }
        let Some(vm) = p.get("verificationMethod").and_then(|v| v.as_str()) else {
            continue;
        };
        if vm.split('#').next() != Some(issuer) {
            continue;
        }
        let mut candidate = body.clone();
        candidate.insert("proof".into(), proof.clone());
        if let Ok(true) = data_integrity::verify_proof(&Value::Object(candidate), key) {
            return true;
        }
    }
    false
}

fn first_64(s: &str) -> String {
    s.chars().take(64).collect()
}

/// Verify a credential's embedded `delegationChain`. Returns `None` when the
/// chain is valid (or absent), otherwise the reason code.
///
/// `root_keys` supplies keys for non-`did:key` grant issuers (and marks them as
/// trusted roots); `root_dids`, when given, is the set of trusted root DIDs the
/// chain must start from. `did:key` issuers always resolve offline.
pub fn verify_delegation_chain(
    credential: &Value,
    now_iso: &str,
    clock_skew_seconds: i64,
    root_keys: &BTreeMap<String, Vec<u8>>,
    root_dids: Option<&[String]>,
) -> Option<String> {
    let malformed = || Some("malformed_delegation".to_string());
    if !credential.is_object() {
        return malformed();
    }
    let chain = match credential
        .get("credentialSubject")
        .and_then(|s| s.get("delegationChain"))
    {
        None | Some(Value::Null) => return None,
        Some(Value::Array(a)) if a.is_empty() => return None,
        Some(Value::Array(a)) => a,
        Some(_) => return malformed(),
    };
    let Ok(now) = iso_to_epoch_seconds(now_iso) else {
        return malformed();
    };

    let mut grants: Vec<&Value> = Vec::with_capacity(chain.len());
    for link in chain {
        let (Some(link_issuer), Some(link_subject)) = (
            link.get("issuer").and_then(|v| v.as_str()),
            link.get("subject").and_then(|v| v.as_str()),
        ) else {
            return malformed();
        };
        let Some(grant) = link.get("parentCredential").filter(|g| g.is_object()) else {
            return Some("delegation_link_unsigned".into());
        };
        if !matches!(
            grant.get("proof"),
            Some(Value::Object(_)) | Some(Value::Array(_))
        ) {
            return Some("delegation_link_unsigned".into());
        }
        let grant_issuer = issuer_did(grant);
        if grant_issuer.as_deref() != Some(link_issuer) {
            return Some("delegation_link_issuer_mismatch".into());
        }
        let Some(key) = resolve_chain_key(link_issuer, root_keys) else {
            return Some("delegation_issuer_key_unresolved".into());
        };
        if !verify_grant_proof(grant, link_issuer, &key) {
            return Some("delegation_signature_invalid".into());
        }
        if let Some(bound) = link.get("parentProofValue") {
            if bound.as_str() != Some(first_64(&parent_proof_binding_value(grant)).as_str()) {
                return Some("delegation_link_tampered".into());
            }
        }
        let delegatee = grant
            .get("credentialSubject")
            .and_then(|s| s.get("intent"))
            .and_then(|i| i.get("delegatee"))
            .and_then(|d| d.as_str())
            .filter(|d| !d.is_empty());
        let Some(delegatee) = delegatee else {
            return Some("delegation_no_delegatee".into());
        };
        if delegatee != link_subject {
            return Some("delegation_subject_mismatch".into());
        }
        let window = (
            grant
                .get("validFrom")
                .and_then(|v| v.as_str())
                .map(iso_to_epoch_seconds),
            grant
                .get("validUntil")
                .and_then(|v| v.as_str())
                .map(iso_to_epoch_seconds),
        );
        let (Some(Ok(from)), Some(Ok(until))) = window else {
            return malformed();
        };
        if now - until > clock_skew_seconds {
            return Some("delegation_expired".into());
        }
        if from - now > clock_skew_seconds {
            return Some("delegation_not_yet_valid".into());
        }
        grants.push(grant);
    }

    for i in 1..chain.len() {
        if chain[i - 1].get("subject") != chain[i].get("issuer") {
            return Some("delegation_subject_issuer_mismatch".into());
        }
    }
    let last_subject = chain[chain.len() - 1]
        .get("subject")
        .and_then(|v| v.as_str());
    if last_subject.map(String::from) != issuer_did(credential) {
        return Some("delegation_subject_issuer_mismatch".into());
    }

    if let Some(dids) = root_dids {
        let root = chain[0]
            .get("issuer")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !dids.iter().any(|d| d == root) {
            return Some("untrusted_principal".into());
        }
    }

    let mut views: Vec<Value> = grants.iter().map(|g| capability_view(g, true)).collect();
    views.push(capability_view(credential, true));
    if let Err(dim) = attenuation::first_broader_step(&views) {
        return Some(format!("scope_exceeds_parent:{}", dim.as_str()));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(vf: &str, vu: &str) -> Value {
        build_delegation_link(&DelegationLinkInput {
            issuer: "did:web:a".into(),
            subject: "did:web:b".into(),
            intent: json!({"action":"read","target":"t","resource":"https://x/y"}),
            valid_from: Some(vf.into()),
            valid_until: Some(vu.into()),
            parent_proof_value: None,
        })
    }

    #[test]
    fn nested_windows_pass() {
        let chain = vec![
            link("2026-04-26T09:00:00Z", "2026-04-26T12:00:00Z"),
            link("2026-04-26T10:00:00Z", "2026-04-26T11:00:00Z"),
        ];
        assert!(verify_chain_time_bound(&chain, "2026-04-26T10:30:00Z", 30).unwrap());
    }

    #[test]
    fn child_wider_than_parent_fails() {
        let chain = vec![
            link("2026-04-26T10:00:00Z", "2026-04-26T11:00:00Z"),
            link("2026-04-26T09:00:00Z", "2026-04-26T12:00:00Z"), // wider
        ];
        assert!(!verify_chain_time_bound(&chain, "2026-04-26T10:30:00Z", 30).unwrap());
    }

    #[test]
    fn now_outside_leaf_window_fails() {
        let chain = vec![link("2026-04-26T10:00:00Z", "2026-04-26T11:00:00Z")];
        assert!(!verify_chain_time_bound(&chain, "2026-04-26T12:00:00Z", 30).unwrap());
    }
}
