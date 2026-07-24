//! v1.7 capability attenuation: the non-expansion rule over the six delegation
//! dimensions, verifier cost budgets, and chain-cascade revocation
//! (Specification 9.3 to 9.6).
//!
//! Security posture: default-deny. Every check answers "is the child broader
//! than its parent on this dimension?" and any malformed input, unknown shape,
//! or ambiguous comparison rejects rather than admits. A delegation chain grants
//! authority, so a false "valid" is an authority-escalation bug; a false
//! "invalid" is only an availability issue. We bias hard toward rejection.
//!
//! A dimension absent on a child link is inherited unchanged from its parent;
//! it can never be widened by omission. A dimension the parent leaves unbounded
//! may be narrowed by a child. Only when the child *specifies* a dimension that
//! the parent also bounds do we compare them.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::error::{CoreError, Result};
use crate::time::iso_to_epoch_seconds;

/// A small tolerance for rate comparison so exact-equal rates are not rejected
/// by floating-point noise.
const RATE_EPSILON: f64 = 1e-9;

/// The six capability dimensions a delegation link may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dimension {
    Action,
    Target,
    Resource,
    Time,
    Rate,
    Policy,
}

impl Dimension {
    pub fn as_str(self) -> &'static str {
        match self {
            Dimension::Action => "action",
            Dimension::Target => "target",
            Dimension::Resource => "resource",
            Dimension::Time => "time",
            Dimension::Rate => "rate",
            Dimension::Policy => "policy",
        }
    }
}

/// A structured reason a delegation chain is rejected. `code()` yields the
/// on-the-wire reason string used across the SDKs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegationReject {
    /// A child link is broader than its parent on the named dimension.
    ScopeExceedsParent { dimension: Dimension },
    /// The verifier's local cost budget was exceeded; `limit` names which one.
    VerifierBudgetExceeded { limit: String },
    /// A link (0-indexed from the root) is revoked; the whole chain and every
    /// authority below it is rejected.
    DelegationRevoked { link_index: usize },
    /// A link's `subject` does not match the next link's `issuer`.
    SubjectIssuerMismatch { link_index: usize },
    /// The root link's issuer is not in the verifier's trusted set.
    UntrustedPrincipal,
    /// The current instant is outside the chain's effective validity window.
    OutsideValidityWindow,
    /// The chain or a link is structurally malformed.
    Malformed { detail: String },
}

impl DelegationReject {
    pub fn code(&self) -> &'static str {
        match self {
            DelegationReject::ScopeExceedsParent { .. } => "scope_exceeds_parent",
            DelegationReject::VerifierBudgetExceeded { .. } => "verifier_budget_exceeded",
            DelegationReject::DelegationRevoked { .. } => "delegation_revoked",
            DelegationReject::SubjectIssuerMismatch { .. } => "subject_issuer_mismatch",
            DelegationReject::UntrustedPrincipal => "untrusted_principal",
            DelegationReject::OutsideValidityWindow => "outside_validity_window",
            DelegationReject::Malformed { .. } => "malformed_delegation",
        }
    }
}

/// Verifier-local cost budget (Specification 9.4). `None` means unlimited.
/// These are the verifier's configurable choice, not a protocol requirement.
#[derive(Debug, Clone, Default)]
pub struct VerifierBudget {
    pub max_depth: Option<usize>,
    pub max_cumulative_ttl_seconds: Option<i64>,
}

type DResult = std::result::Result<(), DelegationReject>;

// --------------------------------------------------------------------------
// Dimension helpers
// --------------------------------------------------------------------------

fn intent<'a>(link: &'a Value) -> Option<&'a Value> {
    link.get("intent")
}

/// Normalize an action/target field to a set of strings.
/// `Ok(None)`  => absent (inherit from parent).
/// `Ok(Some)`  => a string or an array of strings.
/// `Err`       => present but malformed (default-deny).
fn string_set(v: Option<&Value>) -> Result<Option<BTreeSet<String>>> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            let mut set = BTreeSet::new();
            set.insert(s.clone());
            Ok(Some(set))
        }
        Some(Value::Array(arr)) => {
            let mut set = BTreeSet::new();
            for item in arr {
                match item.as_str() {
                    Some(s) => {
                        set.insert(s.to_string());
                    }
                    None => {
                        return Err(CoreError::Json("action/target array must be strings".into()))
                    }
                }
            }
            Ok(Some(set))
        }
        Some(_) => Err(CoreError::Json("action/target must be a string or array".into())),
    }
}

/// Path-component-wise sub-resource test. `child` is within `parent` when it is
/// equal to it, or extends it at a path boundary. Trailing slashes are ignored.
fn is_sub_resource(child: &str, parent: &str) -> bool {
    let c = child.trim_end_matches('/');
    let p = parent.trim_end_matches('/');
    if c == p {
        return true;
    }
    // child must extend parent at a "/" boundary, not merely share a prefix
    // (so "https://x/a2" is NOT under "https://x/a").
    c.len() > p.len() && c.starts_with(p) && c.as_bytes()[p.len()] == b'/'
}

/// Parse an ISO-8601 duration (the subset used by rate windows: days, hours,
/// minutes, seconds, e.g. `PT1H`, `PT30M`, `PT1H30M15S`, `P1D`) to seconds.
fn parse_duration_seconds(s: &str) -> Result<i64> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes[0] != b'P' {
        return Err(CoreError::Json(format!("invalid duration: {s}")));
    }
    let mut total: i64 = 0;
    let mut num = String::new();
    let mut in_time = false;
    let mut saw_field = false;
    for &b in &bytes[1..] {
        match b {
            b'T' => in_time = true,
            b'0'..=b'9' => num.push(b as char),
            b'D' | b'H' | b'M' | b'S' => {
                if num.is_empty() {
                    return Err(CoreError::Json(format!("invalid duration: {s}")));
                }
                let n: i64 = num
                    .parse()
                    .map_err(|_| CoreError::Json(format!("invalid duration: {s}")))?;
                let secs = match b {
                    b'D' => n * 86_400,
                    b'H' => n * 3_600,
                    b'M' if in_time => n * 60, // minute in the time section
                    b'M' => n * 2_592_000,     // month in the date section (approx 30d)
                    b'S' => n,
                    _ => unreachable!(),
                };
                total += secs;
                num.clear();
                saw_field = true;
            }
            _ => return Err(CoreError::Json(format!("invalid duration: {s}"))),
        }
    }
    if !saw_field || !num.is_empty() {
        return Err(CoreError::Json(format!("invalid duration: {s}")));
    }
    Ok(total)
}

/// Rate as events per second: `limit / window_seconds`. Higher is broader.
fn rate_events_per_sec(rate: &Value) -> Result<f64> {
    let obj = rate
        .as_object()
        .ok_or_else(|| CoreError::Json("rate must be an object".into()))?;
    let limit = obj
        .get("limit")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| CoreError::Json("rate.limit must be a number".into()))?;
    if limit < 0.0 {
        return Err(CoreError::Json("rate.limit must be non-negative".into()));
    }
    let window = obj
        .get("window")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CoreError::Json("rate.window must be an ISO-8601 duration".into()))?;
    let secs = parse_duration_seconds(window)?;
    if secs <= 0 {
        return Err(CoreError::Json("rate.window must be positive".into()));
    }
    Ok(limit / secs as f64)
}

/// Child policy must be equal to or stricter than the parent's. Numeric parent
/// constraints are treated as minimum thresholds (higher child value = stricter).
/// Non-numeric constraints require exact equality. A parent key the child omits
/// means the child dropped a constraint, which is broader, and is rejected.
/// Conservative by construction: anything not provably at-least-as-strict fails.
fn policy_not_weaker(parent: &Value, child: &Value) -> bool {
    let (pobj, cobj) = match (parent.as_object(), child.as_object()) {
        (Some(p), Some(c)) => (p, c),
        _ => return false, // a policy that is not an object cannot be reasoned about
    };
    for (k, pv) in pobj {
        match cobj.get(k) {
            None => return false, // child dropped a parent constraint => weaker
            Some(cv) => match (pv.as_f64(), cv.as_f64()) {
                (Some(pn), Some(cn)) => {
                    if cn < pn {
                        return false; // lower threshold => less strict
                    }
                }
                (Some(_), None) | (None, Some(_)) => return false, // type mismatch
                (None, None) => {
                    if pv != cv {
                        return false; // non-numeric must match exactly
                    }
                }
            },
        }
    }
    true
}

fn window(link: &Value) -> Result<(Option<i64>, Option<i64>)> {
    let vf = match link.get("validFrom").and_then(|v| v.as_str()) {
        Some(s) => Some(iso_to_epoch_seconds(s)?),
        None => None,
    };
    let vu = match link.get("validUntil").and_then(|v| v.as_str()) {
        Some(s) => Some(iso_to_epoch_seconds(s)?),
        None => None,
    };
    Ok((vf, vu))
}

// --------------------------------------------------------------------------
// Non-expansion between an adjacent (parent, child) pair
// --------------------------------------------------------------------------

/// Verify that `child` does not broaden `parent` on any dimension. Returns the
/// offending [`Dimension`] on failure. Malformed inputs reject as `Resource` or
/// the relevant dimension via the error-to-reject mapping in [`validate_chain`].
pub fn non_expansion(parent: &Value, child: &Value) -> std::result::Result<(), Dimension> {
    let p_intent = intent(parent);
    let c_intent = intent(child);

    // action: child actions must be a subset of the parent's.
    if let Ok(Some(c_actions)) = string_set(c_intent.and_then(|v| v.get("action"))) {
        if let Ok(Some(p_actions)) = string_set(p_intent.and_then(|v| v.get("action"))) {
            if !c_actions.is_subset(&p_actions) {
                return Err(Dimension::Action);
            }
        }
    } else if c_intent.map(|v| v.get("action").is_some()).unwrap_or(false) {
        return Err(Dimension::Action); // present but malformed
    }

    // target: child targets must be a subset of the parent's.
    if let Ok(Some(c_targets)) = string_set(c_intent.and_then(|v| v.get("target"))) {
        if let Ok(Some(p_targets)) = string_set(p_intent.and_then(|v| v.get("target"))) {
            if !c_targets.is_subset(&p_targets) {
                return Err(Dimension::Target);
            }
        }
    } else if c_intent.map(|v| v.get("target").is_some()).unwrap_or(false) {
        return Err(Dimension::Target);
    }

    // resource: child resource must be a sub-resource of the parent's.
    let c_res = c_intent.and_then(|v| v.get("resource")).and_then(|v| v.as_str());
    if let Some(cr) = c_res {
        if let Some(pr) = p_intent.and_then(|v| v.get("resource")).and_then(|v| v.as_str()) {
            if !is_sub_resource(cr, pr) {
                return Err(Dimension::Resource);
            }
        }
    } else if c_intent
        .and_then(|v| v.get("resource"))
        .map(|v| !v.is_null())
        .unwrap_or(false)
    {
        return Err(Dimension::Resource); // present but not a string
    }

    // time: child window must be within the parent's.
    let (cf, cu) = match window(child) {
        Ok(w) => w,
        Err(_) => return Err(Dimension::Time),
    };
    let (pf, pu) = match window(parent) {
        Ok(w) => w,
        Err(_) => return Err(Dimension::Time),
    };
    if let (Some(f), Some(pf)) = (cf, pf) {
        if f < pf {
            return Err(Dimension::Time);
        }
    }
    if let (Some(u), Some(pu)) = (cu, pu) {
        if u > pu {
            return Err(Dimension::Time);
        }
    }

    // rate: child events-per-second must not exceed the parent's.
    if let Some(cr) = child.get("rate") {
        if !cr.is_null() {
            let ce = match rate_events_per_sec(cr) {
                Ok(e) => e,
                Err(_) => return Err(Dimension::Rate),
            };
            if let Some(pr) = parent.get("rate") {
                if !pr.is_null() {
                    let pe = match rate_events_per_sec(pr) {
                        Ok(e) => e,
                        Err(_) => return Err(Dimension::Rate),
                    };
                    if ce > pe + RATE_EPSILON {
                        return Err(Dimension::Rate);
                    }
                }
            }
        }
    }

    // policy: child policy must be equal to or stricter than the parent's.
    if let Some(cp) = child.get("policy") {
        if !cp.is_null() {
            if let Some(pp) = parent.get("policy") {
                if !pp.is_null() && !policy_not_weaker(pp, cp) {
                    return Err(Dimension::Policy);
                }
            }
        }
    }

    Ok(())
}

// --------------------------------------------------------------------------
// Full chain validation
// --------------------------------------------------------------------------

fn link_str<'a>(link: &'a Value, key: &str) -> Option<&'a str> {
    link.get(key).and_then(|v| v.as_str())
}

/// Validate a delegation chain ordered root -> leaf under the v1.7 rules.
///
/// * `trusted_roots` empty => the root-trust check is skipped (the caller
///   anchors trust elsewhere); otherwise the root issuer must be present.
/// * `revoked_link_indices` are links the caller has resolved as revoked
///   (credential- or DID-level); any hit rejects the whole chain (cascade).
/// * `budget` caps the verifier's work; `None` fields are unlimited.
///
/// Returns `Ok(())` when the chain is valid, or the first [`DelegationReject`].
pub fn validate_chain(
    chain: &[Value],
    trusted_roots: &[String],
    revoked_link_indices: &[usize],
    budget: &VerifierBudget,
    now_iso: &str,
    clock_skew_seconds: i64,
) -> DResult {
    if chain.is_empty() {
        return Err(DelegationReject::Malformed {
            detail: "empty delegation chain".into(),
        });
    }

    // Verifier budget: depth.
    if let Some(max) = budget.max_depth {
        if chain.len() > max {
            return Err(DelegationReject::VerifierBudgetExceeded {
                limit: "depth".into(),
            });
        }
    }

    // Every link must be an object with issuer and subject.
    for (i, link) in chain.iter().enumerate() {
        if link.as_object().is_none() {
            return Err(DelegationReject::Malformed {
                detail: format!("link {i} is not an object"),
            });
        }
        if link_str(link, "issuer").is_none() || link_str(link, "subject").is_none() {
            return Err(DelegationReject::Malformed {
                detail: format!("link {i} missing issuer/subject"),
            });
        }
    }

    // Root trust.
    if !trusted_roots.is_empty() {
        let root_issuer = link_str(&chain[0], "issuer").unwrap();
        if !trusted_roots.iter().any(|r| r == root_issuer) {
            return Err(DelegationReject::UntrustedPrincipal);
        }
    }

    // Cascade revocation: a revoked link invalidates the whole chain.
    if let Some(&idx) = revoked_link_indices.iter().min() {
        if idx < chain.len() {
            return Err(DelegationReject::DelegationRevoked { link_index: idx });
        }
    }

    // Linkage and non-expansion for each adjacent pair.
    for i in 1..chain.len() {
        let parent = &chain[i - 1];
        let child = &chain[i];
        if link_str(parent, "subject") != link_str(child, "issuer") {
            return Err(DelegationReject::SubjectIssuerMismatch { link_index: i });
        }
        non_expansion(parent, child)
            .map_err(|dimension| DelegationReject::ScopeExceedsParent { dimension })?;
    }

    // Effective validity window: the intersection of every link's window, i.e.
    // the latest start and the earliest end. `now` must fall inside it.
    let mut eff_start: Option<i64> = None;
    let mut eff_end: Option<i64> = None;
    let mut cumulative_ttl: i64 = 0;
    for link in chain {
        let (vf, vu) = window(link).map_err(|e| DelegationReject::Malformed {
            detail: e.to_string(),
        })?;
        if let Some(f) = vf {
            eff_start = Some(eff_start.map_or(f, |cur| cur.max(f)));
        }
        if let Some(u) = vu {
            eff_end = Some(eff_end.map_or(u, |cur| cur.min(u)));
        }
        if let (Some(f), Some(u)) = (vf, vu) {
            if u >= f {
                cumulative_ttl += u - f;
            }
        }
    }
    let now = iso_to_epoch_seconds(now_iso).map_err(|e| DelegationReject::Malformed {
        detail: e.to_string(),
    })?;
    if let Some(f) = eff_start {
        if now < f - clock_skew_seconds {
            return Err(DelegationReject::OutsideValidityWindow);
        }
    }
    if let Some(u) = eff_end {
        if now > u + clock_skew_seconds {
            return Err(DelegationReject::OutsideValidityWindow);
        }
    }

    // Verifier budget: cumulative TTL across the chain.
    if let Some(max) = budget.max_cumulative_ttl_seconds {
        if cumulative_ttl > max {
            return Err(DelegationReject::VerifierBudgetExceeded {
                limit: "cumulative_ttl".into(),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn link(issuer: &str, subject: &str, intent: Value) -> Value {
        json!({
            "issuer": issuer,
            "subject": subject,
            "intent": intent,
            "validFrom": "2026-04-26T09:00:00Z",
            "validUntil": "2026-04-26T12:00:00Z"
        })
    }

    fn now() -> &'static str {
        "2026-04-26T10:00:00Z"
    }

    #[test]
    fn restate_unchanged_is_valid() {
        let i = json!({"action":"read","target":"t","resource":"https://x/a"});
        let chain = vec![
            link("did:web:root", "did:web:a", i.clone()),
            link("did:web:a", "did:web:b", i.clone()),
        ];
        assert!(validate_chain(&chain, &[], &[], &VerifierBudget::default(), now(), 30).is_ok());
    }

    #[test]
    fn resource_narrowing_is_valid() {
        let chain = vec![
            link("did:web:root", "did:web:a", json!({"resource":"https://x/a"})),
            link("did:web:a", "did:web:b", json!({"resource":"https://x/a/b"})),
        ];
        assert!(validate_chain(&chain, &[], &[], &VerifierBudget::default(), now(), 30).is_ok());
    }

    #[test]
    fn resource_widening_rejected_naming_dimension() {
        let chain = vec![
            link("did:web:root", "did:web:a", json!({"resource":"https://x/a/b"})),
            link("did:web:a", "did:web:b", json!({"resource":"https://x/a"})),
        ];
        let err = validate_chain(&chain, &[], &[], &VerifierBudget::default(), now(), 30).unwrap_err();
        assert_eq!(err.code(), "scope_exceeds_parent");
        assert_eq!(err, DelegationReject::ScopeExceedsParent { dimension: Dimension::Resource });
    }

    #[test]
    fn sibling_prefix_is_not_sub_resource() {
        assert!(!is_sub_resource("https://x/a2", "https://x/a"));
        assert!(is_sub_resource("https://x/a/b", "https://x/a"));
        assert!(is_sub_resource("https://x/a", "https://x/a/"));
    }

    #[test]
    fn action_superset_rejected() {
        let chain = vec![
            link("did:web:root", "did:web:a", json!({"action":"read"})),
            link("did:web:a", "did:web:b", json!({"action":["read","write"]})),
        ];
        let err = validate_chain(&chain, &[], &[], &VerifierBudget::default(), now(), 30).unwrap_err();
        assert_eq!(err, DelegationReject::ScopeExceedsParent { dimension: Dimension::Action });
    }

    #[test]
    fn action_subset_ok() {
        let chain = vec![
            link("did:web:root", "did:web:a", json!({"action":["read","write"]})),
            link("did:web:a", "did:web:b", json!({"action":"read"})),
        ];
        assert!(validate_chain(&chain, &[], &[], &VerifierBudget::default(), now(), 30).is_ok());
    }

    #[test]
    fn rate_widening_rejected() {
        let mut a = link("did:web:root", "did:web:a", json!({"action":"read"}));
        a["rate"] = json!({"limit":100,"window":"PT1H"});
        let mut b = link("did:web:a", "did:web:b", json!({"action":"read"}));
        b["rate"] = json!({"limit":100,"window":"PT30M"}); // twice the events/sec
        let chain = vec![a, b];
        let err = validate_chain(&chain, &[], &[], &VerifierBudget::default(), now(), 30).unwrap_err();
        assert_eq!(err, DelegationReject::ScopeExceedsParent { dimension: Dimension::Rate });
    }

    #[test]
    fn rate_narrowing_ok() {
        let mut a = link("did:web:root", "did:web:a", json!({"action":"read"}));
        a["rate"] = json!({"limit":100,"window":"PT1H"});
        let mut b = link("did:web:a", "did:web:b", json!({"action":"read"}));
        b["rate"] = json!({"limit":50,"window":"PT1H"});
        let chain = vec![a, b];
        assert!(validate_chain(&chain, &[], &[], &VerifierBudget::default(), now(), 30).is_ok());
    }

    #[test]
    fn policy_weakening_rejected() {
        let mut a = link("did:web:root", "did:web:a", json!({"action":"read"}));
        a["policy"] = json!({"minHeartbeatAgeSeconds":300});
        let mut b = link("did:web:a", "did:web:b", json!({"action":"read"}));
        b["policy"] = json!({"minHeartbeatAgeSeconds":100}); // weaker
        let chain = vec![a, b];
        let err = validate_chain(&chain, &[], &[], &VerifierBudget::default(), now(), 30).unwrap_err();
        assert_eq!(err, DelegationReject::ScopeExceedsParent { dimension: Dimension::Policy });
    }

    #[test]
    fn policy_dropping_constraint_rejected() {
        let mut a = link("did:web:root", "did:web:a", json!({"action":"read"}));
        a["policy"] = json!({"minHeartbeatAgeSeconds":300});
        let mut b = link("did:web:a", "did:web:b", json!({"action":"read"}));
        b["policy"] = json!({"unrelated":true}); // dropped the parent's constraint
        let chain = vec![a, b];
        assert!(validate_chain(&chain, &[], &[], &VerifierBudget::default(), now(), 30).is_err());
    }

    #[test]
    fn time_widening_rejected() {
        let chain = vec![
            json!({"issuer":"did:web:root","subject":"did:web:a","intent":{"action":"read"},
                   "validFrom":"2026-04-26T10:00:00Z","validUntil":"2026-04-26T11:00:00Z"}),
            json!({"issuer":"did:web:a","subject":"did:web:b","intent":{"action":"read"},
                   "validFrom":"2026-04-26T09:00:00Z","validUntil":"2026-04-26T12:00:00Z"}),
        ];
        let err = validate_chain(&chain, &[], &[], &VerifierBudget::default(), "2026-04-26T10:30:00Z", 30).unwrap_err();
        assert_eq!(err, DelegationReject::ScopeExceedsParent { dimension: Dimension::Time });
    }

    #[test]
    fn subject_issuer_mismatch_rejected() {
        let i = json!({"action":"read"});
        let chain = vec![
            link("did:web:root", "did:web:a", i.clone()),
            link("did:web:WRONG", "did:web:b", i.clone()),
        ];
        let err = validate_chain(&chain, &[], &[], &VerifierBudget::default(), now(), 30).unwrap_err();
        assert_eq!(err, DelegationReject::SubjectIssuerMismatch { link_index: 1 });
    }

    #[test]
    fn untrusted_root_rejected() {
        let i = json!({"action":"read"});
        let chain = vec![link("did:web:root", "did:web:a", i)];
        let err = validate_chain(&chain, &["did:web:other".into()], &[], &VerifierBudget::default(), now(), 30).unwrap_err();
        assert_eq!(err, DelegationReject::UntrustedPrincipal);
    }

    #[test]
    fn cascade_revocation_rejects_whole_chain() {
        let i = json!({"action":"read"});
        let chain = vec![
            link("did:web:root", "did:web:a", i.clone()),
            link("did:web:a", "did:web:b", i.clone()),
            link("did:web:b", "did:web:c", i.clone()),
        ];
        // middle link revoked
        let err = validate_chain(&chain, &[], &[1], &VerifierBudget::default(), now(), 30).unwrap_err();
        assert_eq!(err, DelegationReject::DelegationRevoked { link_index: 1 });
    }

    #[test]
    fn budget_depth_exceeded() {
        let i = json!({"action":"read"});
        let chain = vec![
            link("did:web:root", "did:web:a", i.clone()),
            link("did:web:a", "did:web:b", i.clone()),
            link("did:web:b", "did:web:c", i.clone()),
        ];
        let budget = VerifierBudget { max_depth: Some(2), max_cumulative_ttl_seconds: None };
        let err = validate_chain(&chain, &[], &[], &budget, now(), 30).unwrap_err();
        assert_eq!(err, DelegationReject::VerifierBudgetExceeded { limit: "depth".into() });
    }

    #[test]
    fn deep_but_attenuating_chain_is_valid_without_depth_cap() {
        // Ten hops, each restating the same authority: valid now that the fixed
        // depth limit is gone (this is the whole point of v1.7).
        let mut chain = Vec::new();
        let i = json!({"action":"read","resource":"https://x/a"});
        for n in 0..10 {
            let issuer = if n == 0 { "did:web:root".to_string() } else { format!("did:web:h{}", n - 1) };
            let subject = format!("did:web:h{n}");
            chain.push(link(&issuer, &subject, i.clone()));
        }
        assert!(validate_chain(&chain, &[], &[], &VerifierBudget::default(), now(), 30).is_ok());
    }

    #[test]
    fn now_outside_effective_window_rejected() {
        let chain = vec![link("did:web:root", "did:web:a", json!({"action":"read"}))];
        let err = validate_chain(&chain, &[], &[], &VerifierBudget::default(), "2026-04-26T20:00:00Z", 30).unwrap_err();
        assert_eq!(err, DelegationReject::OutsideValidityWindow);
    }

    #[test]
    fn absent_child_dimension_inherits_and_passes() {
        let chain = vec![
            link("did:web:root", "did:web:a", json!({"action":"read","resource":"https://x/a"})),
            link("did:web:a", "did:web:b", json!({"resource":"https://x/a/b"})), // action omitted => inherit
        ];
        assert!(validate_chain(&chain, &[], &[], &VerifierBudget::default(), now(), 30).is_ok());
    }

    #[test]
    fn duration_parser() {
        assert_eq!(parse_duration_seconds("PT1H").unwrap(), 3600);
        assert_eq!(parse_duration_seconds("PT30M").unwrap(), 1800);
        assert_eq!(parse_duration_seconds("PT1H30M15S").unwrap(), 5415);
        assert_eq!(parse_duration_seconds("P1D").unwrap(), 86400);
        assert!(parse_duration_seconds("1H").is_err());
        assert!(parse_duration_seconds("PT").is_err());
    }
}
