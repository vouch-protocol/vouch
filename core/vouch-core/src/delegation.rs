//! Delegation links and time-bound chain validation.
//!
//! A delegation link carries an issuer, subject, intent, and an optional
//! validity window (Specification 9.2). Time-bound validation enforces that each
//! link's window is within its parent's (time attenuation, 9.3 step 6) and that
//! the current instant is within the narrowest link's window. The full v1.7
//! capability-attenuation rule across the other dimensions lives with the SDKs;
//! this core provides the link structure plus the deterministic temporal checks.

use serde_json::{json, Map, Value};

use crate::error::{CoreError, Result};
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
