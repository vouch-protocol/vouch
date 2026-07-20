//! Disconnected-edge / DTN trust primitives (PAD-106 to PAD-124), one byte-exact
//! implementation in the core so the disconnected-edge surface verifies across every
//! language wrapper, mirroring the Python `vouch.robotics` disconnected-edge modules.
//!
//! This file is being ported module-by-module from the Python reference. Batch 1:
//! bounded-staleness revocation (PAD-106), presenter freshness + graded decay
//! (PAD-107, 119), channel-geometry proof of presence (PAD-108), and
//! ephemeris-scoped authority (PAD-109). Later batches add localization, the
//! revocation accumulator, quorum/swarm trust, edge trust, perception consensus,
//! and DTN bundle custody.
//!
//! As elsewhere in the core, timestamps and nonces are caller-supplied so the output
//! is deterministic and reproducible across SDKs.

use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::sync::OnceLock;

use sha2::{Digest, Sha256};

use crate::data_integrity::{self, BuildProofOptions};
use crate::error::{CoreError, Result};
use crate::robotics::{attenuates, check_physical_action, has_type, mb64, unmb64, PhysicalAction};
use crate::time::iso_to_epoch_seconds;

pub const VC_CONTEXT_V2: &str = "https://www.w3.org/ns/credentials/v2";
pub const VOUCH_CONTEXT_V1: &str = "https://vouch-protocol.com/contexts/v1";

pub const FRESHNESS_TOKEN_TYPE: &str = "FreshnessToken";
pub const PRESENCE_ATTESTATION_TYPE: &str = "ChannelGeometryPresenceAttestation";
pub const GEOSCOPED_GRANT_TYPE: &str = "EphemerisScopedGrantCredential";

// Consequence tiers (PAD-106).
pub const CONSEQUENCE_ROUTINE: &str = "routine";
pub const CONSEQUENCE_SENSITIVE: &str = "sensitive";
pub const CONSEQUENCE_CRITICAL: &str = "critical";

/// Speed of light in vacuum (m/s), for the Doppler helper.
pub const SPEED_OF_LIGHT_MPS: f64 = 299_792_458.0;

fn vm(did: &str) -> String {
    format!("{did}#key-1")
}

fn tier_or_critical(tier: &str) -> &str {
    match tier {
        CONSEQUENCE_ROUTINE | CONSEQUENCE_SENSITIVE | CONSEQUENCE_CRITICAL => tier,
        _ => CONSEQUENCE_CRITICAL,
    }
}

// ===========================================================================
// PAD-106: bounded-staleness revocation freshness gate
// ===========================================================================

/// Default maximum acceptable snapshot age (seconds) per consequence tier:
/// routine 30 days, sensitive 24 hours, critical 1 hour.
pub fn default_staleness_budget_seconds(tier: &str) -> i64 {
    match tier_or_critical(tier) {
        CONSEQUENCE_ROUTINE => 30 * 24 * 60 * 60,
        CONSEQUENCE_SENSITIVE => 24 * 60 * 60,
        _ => 60 * 60,
    }
}

/// Outcome of a bounded-staleness evaluation (PAD-106).
#[derive(Debug, Clone)]
pub struct FreshnessVerdict {
    pub allow: bool,
    pub tier: String,
    pub reason: String,
    pub staleness_seconds: Option<i64>,
    pub budget_seconds: i64,
}

/// The snapshot's freshness anchor (`validFrom` epoch seconds), or `None` if the
/// snapshot is unusable: malformed timestamps or expired past its own `validUntil`.
fn snapshot_as_of(snapshot: &Value, now_epoch: i64) -> Option<i64> {
    let vf = snapshot.get("validFrom")?.as_str()?;
    let valid_from = iso_to_epoch_seconds(vf).ok()?;
    if let Some(vu) = snapshot.get("validUntil").and_then(|v| v.as_str()) {
        match iso_to_epoch_seconds(vu) {
            Ok(vu_e) if now_epoch <= vu_e => {}
            _ => return None, // expired or malformed -> unusable
        }
    }
    Some(valid_from)
}

/// Decide whether a locally-held revocation `snapshot` is fresh enough to authorize
/// an action of consequence `tier`, at `now_iso`. Fails closed on every ambiguity.
/// Does NOT verify the snapshot proof or the revocation bit — the caller does both
/// first. `budget_override` optionally supplies a per-tier budget (seconds).
pub fn evaluate_freshness(
    tier: &str,
    snapshot: Option<&Value>,
    now_iso: &str,
    budget_override: Option<i64>,
) -> Result<FreshnessVerdict> {
    let tier = tier_or_critical(tier).to_string();
    let budget = budget_override.unwrap_or_else(|| default_staleness_budget_seconds(&tier));
    let now_epoch = iso_to_epoch_seconds(now_iso)
        .map_err(|e| CoreError::Json(format!("bad now timestamp: {e}")))?;

    let as_of = snapshot.and_then(|s| snapshot_as_of(s, now_epoch));
    match as_of {
        None => {
            if tier == CONSEQUENCE_ROUTINE {
                Ok(FreshnessVerdict {
                    allow: true,
                    tier,
                    reason: "no usable revocation snapshot; routine tier tolerates it".into(),
                    staleness_seconds: None,
                    budget_seconds: budget,
                })
            } else {
                Ok(FreshnessVerdict {
                    allow: false,
                    reason: format!("no usable revocation snapshot; {tier} tier fails closed"),
                    tier,
                    staleness_seconds: None,
                    budget_seconds: budget,
                })
            }
        }
        Some(af) => {
            let staleness = now_epoch - af;
            let allow = staleness <= budget;
            let reason = if allow {
                format!("snapshot age {staleness}s within {tier} budget {budget}s")
            } else {
                format!("snapshot age {staleness}s exceeds {tier} budget {budget}s; fails closed")
            };
            Ok(FreshnessVerdict {
                allow,
                tier,
                reason,
                staleness_seconds: Some(staleness),
                budget_seconds: budget,
            })
        }
    }
}

// ===========================================================================
// PAD-107: presenter freshness token  /  PAD-119: graded trust decay
// ===========================================================================

/// Default acceptable epoch gap per consequence tier (PAD-107).
pub fn default_max_epoch_gap(tier: &str) -> i64 {
    match tier_or_critical(tier) {
        CONSEQUENCE_ROUTINE => 100,
        CONSEQUENCE_SENSITIVE => 10,
        _ => 1,
    }
}

/// A relay issues `subject_did` a token proving recent contact at `epoch` (PAD-107).
pub fn build_freshness_token(
    relay_seed: &[u8],
    relay_did: &str,
    subject_did: &str,
    epoch: i64,
    nonce: &str,
    created: &str,
) -> Result<Value> {
    if epoch < 0 {
        return Err(CoreError::Json("epoch must be non-negative".into()));
    }
    let mut subject = Map::new();
    subject.insert("id".into(), json!(subject_did));
    subject.insert("epoch".into(), json!(epoch));
    subject.insert("nonce".into(), json!(nonce));

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert("type".into(), json!(["VerifiableCredential", FRESHNESS_TOKEN_TYPE]));
    cred.insert("issuer".into(), json!(relay_did));
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(vm(relay_did), created);
    data_integrity::sign(&Value::Object(cred), relay_seed, &opts)
}

/// Verify a FreshnessToken: proof, consequence-scaled epoch gap, optional subject and
/// rollback (`seen_epoch`) checks. Returns the subject on success.
#[allow(clippy::too_many_arguments)]
pub fn verify_freshness_token(
    token: &Value,
    relay_public_key: &[u8],
    verifier_epoch: i64,
    tier: &str,
    max_epoch_gap_override: Option<i64>,
    expected_subject: Option<&str>,
    seen_epoch: Option<i64>,
) -> Result<Option<Value>> {
    if !has_type(token.get("type"), FRESHNESS_TOKEN_TYPE) {
        return Ok(None);
    }
    if !data_integrity::verify_proof(token, relay_public_key)? {
        return Ok(None);
    }
    let subject = match token.get("credentialSubject") {
        Some(Value::Object(_)) => token.get("credentialSubject").cloned().unwrap(),
        _ => return Ok(None),
    };
    if let Some(want) = expected_subject {
        if subject.get("id").and_then(|v| v.as_str()) != Some(want) {
            return Ok(None);
        }
    }
    let token_epoch = match subject.get("epoch").and_then(|v| v.as_i64()) {
        Some(e) => e,
        None => return Ok(None),
    };
    if let Some(seen) = seen_epoch {
        if token_epoch < seen {
            return Ok(None); // rollback
        }
    }
    let budget = max_epoch_gap_override.unwrap_or_else(|| default_max_epoch_gap(tier));
    let gap = verifier_epoch - token_epoch;
    if gap < 0 || gap > budget {
        return Ok(None);
    }
    Ok(Some(subject))
}

/// Continuously-decaying trust weight in [0, 1] (PAD-119). `form`: "exponential"
/// (half-life) or "linear" (zero at 2*half_life).
pub fn decay_weight(elapsed_epochs: i64, half_life_epochs: f64, form: &str) -> Result<f64> {
    if elapsed_epochs < 0 {
        return Err(CoreError::Json("elapsed_epochs must be non-negative".into()));
    }
    if half_life_epochs <= 0.0 {
        return Err(CoreError::Json("half_life_epochs must be positive".into()));
    }
    let e = elapsed_epochs as f64;
    match form {
        "exponential" => Ok(0.5_f64.powf(e / half_life_epochs)),
        "linear" => Ok((1.0 - e / (2.0 * half_life_epochs)).max(0.0)),
        _ => Err(CoreError::Json(format!("unknown decay form: {form}"))),
    }
}

/// Default minimum remaining trust weight required per consequence tier (PAD-119).
pub fn default_weight_threshold(tier: &str) -> f64 {
    match tier_or_critical(tier) {
        CONSEQUENCE_ROUTINE => 0.1,
        CONSEQUENCE_SENSITIVE => 0.5,
        _ => 0.9,
    }
}

/// Admit an action only if the decayed weight meets the consequence-scaled threshold.
pub fn decay_permits(
    elapsed_epochs: i64,
    half_life_epochs: f64,
    tier: &str,
    form: &str,
    threshold_override: Option<f64>,
) -> Result<bool> {
    let w = decay_weight(elapsed_epochs, half_life_epochs, form)?;
    let need = threshold_override.unwrap_or_else(|| default_weight_threshold(tier));
    Ok(w >= need)
}

// ===========================================================================
// PAD-108: channel-geometry proof of presence
// ===========================================================================

fn vec3(v: &Value) -> Option<[f64; 3]> {
    let arr = v.as_array()?;
    if arr.len() != 3 {
        return None;
    }
    Some([arr[0].as_f64()?, arr[1].as_f64()?, arr[2].as_f64()?])
}

pub fn expected_range_m(a: [f64; 3], b: [f64; 3]) -> f64 {
    ((a[0] - b[0]).powi(2) + (a[1] - b[1]).powi(2) + (a[2] - b[2]).powi(2)).sqrt()
}

/// Radial velocity of the peer along the line of sight from the verifier (positive
/// when receding). Zero range returns 0.
pub fn radial_velocity_mps(verifier: [f64; 3], peer: [f64; 3], peer_vel: [f64; 3]) -> f64 {
    let los = [peer[0] - verifier[0], peer[1] - verifier[1], peer[2] - verifier[2]];
    let dist = (los[0].powi(2) + los[1].powi(2) + los[2].powi(2)).sqrt();
    if dist == 0.0 {
        return 0.0;
    }
    (los[0] * peer_vel[0] + los[1] * peer_vel[1] + los[2] * peer_vel[2]) / dist
}

/// Predicted Doppler shift (Hz); negative when receding.
pub fn expected_doppler_hz(
    verifier: [f64; 3],
    peer: [f64; 3],
    peer_vel: [f64; 3],
    carrier_hz: f64,
    propagation_mps: f64,
) -> f64 {
    let vr = radial_velocity_mps(verifier, peer, peer_vel);
    -(vr / propagation_mps) * carrier_hz
}

/// Whether a measured range agrees with the claimed position within tolerance.
pub fn check_presence(
    verifier_position: [f64; 3],
    claimed_peer_position: [f64; 3],
    measured_range_m: f64,
    tolerance_m: f64,
) -> bool {
    let predicted = expected_range_m(verifier_position, claimed_peer_position);
    (measured_range_m - predicted).abs() <= tolerance_m
}

/// Build a signed presence attestation binding a nonce, the peer's claimed position
/// (and optional velocity), and the verifier's measured range and tolerance (PAD-108).
#[allow(clippy::too_many_arguments)]
pub fn build_presence_attestation(
    signer_seed: &[u8],
    issuer_did: &str,
    peer_did: &str,
    nonce: &str,
    claimed_position: [f64; 3],
    measured_range_m: f64,
    tolerance_m: f64,
    claimed_velocity: Option<[f64; 3]>,
    created: &str,
) -> Result<Value> {
    let mut geometry = Map::new();
    geometry.insert("claimedPosition".into(), json!(claimed_position.to_vec()));
    geometry.insert("measuredRangeM".into(), json!(measured_range_m));
    geometry.insert("toleranceM".into(), json!(tolerance_m));
    if let Some(v) = claimed_velocity {
        geometry.insert("claimedVelocity".into(), json!(v.to_vec()));
    }

    let mut subject = Map::new();
    subject.insert("id".into(), json!(peer_did));
    subject.insert("nonce".into(), json!(nonce));
    subject.insert("geometry".into(), Value::Object(geometry));

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert("type".into(), json!(["VerifiableCredential", PRESENCE_ATTESTATION_TYPE]));
    cred.insert("issuer".into(), json!(issuer_did));
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(vm(issuer_did), created);
    data_integrity::sign(&Value::Object(cred), signer_seed, &opts)
}

/// Verify a presence attestation: proof, optional nonce echo, and that the measured
/// range agrees with the claimed position relative to `verifier_position` (PAD-108).
pub fn verify_presence_attestation(
    attestation: &Value,
    public_key: &[u8],
    verifier_position: [f64; 3],
    expected_nonce: Option<&str>,
) -> Result<Option<Value>> {
    if !has_type(attestation.get("type"), PRESENCE_ATTESTATION_TYPE) {
        return Ok(None);
    }
    if !data_integrity::verify_proof(attestation, public_key)? {
        return Ok(None);
    }
    let subject = match attestation.get("credentialSubject") {
        Some(Value::Object(_)) => attestation.get("credentialSubject").cloned().unwrap(),
        _ => return Ok(None),
    };
    if let Some(want) = expected_nonce {
        if subject.get("nonce").and_then(|v| v.as_str()) != Some(want) {
            return Ok(None);
        }
    }
    let geometry = match subject.get("geometry") {
        Some(g) => g,
        None => return Ok(None),
    };
    let claimed = match geometry.get("claimedPosition").and_then(vec3) {
        Some(c) => c,
        None => return Ok(None),
    };
    let measured = match geometry.get("measuredRangeM").and_then(|v| v.as_f64()) {
        Some(m) => m,
        None => return Ok(None),
    };
    let tolerance = match geometry.get("toleranceM").and_then(|v| v.as_f64()) {
        Some(t) => t,
        None => return Ok(None),
    };
    if !check_presence(verifier_position, claimed, measured, tolerance) {
        return Ok(None);
    }
    Ok(Some(subject))
}

// ===========================================================================
// PAD-109: ephemeris-scoped delegation authority
// ===========================================================================

/// True if `position` lies inside the region predicate (sphere / box / altitudeBand).
pub fn region_contains(region: &Value, position: [f64; 3]) -> Result<bool> {
    let kind = region.get("type").and_then(|v| v.as_str());
    match kind {
        Some("sphere") => {
            let center = region
                .get("centerM")
                .and_then(vec3)
                .ok_or_else(|| CoreError::Json("region.centerM must be a 3-vector".into()))?;
            let radius = region
                .get("radiusM")
                .and_then(|v| v.as_f64())
                .ok_or_else(|| CoreError::Json("region.radiusM required".into()))?;
            if radius < 0.0 {
                return Err(CoreError::Json("region.radiusM must be non-negative".into()));
            }
            Ok(expected_range_m(position, center) <= radius)
        }
        Some("box") => {
            let lo = region
                .get("minM")
                .and_then(vec3)
                .ok_or_else(|| CoreError::Json("region.minM must be a 3-vector".into()))?;
            let hi = region
                .get("maxM")
                .and_then(vec3)
                .ok_or_else(|| CoreError::Json("region.maxM must be a 3-vector".into()))?;
            Ok((0..3).all(|i| lo[i] <= position[i] && position[i] <= hi[i]))
        }
        Some("altitudeBand") => {
            let lo = region
                .get("minM")
                .and_then(|v| v.as_f64())
                .ok_or_else(|| CoreError::Json("region.minM required".into()))?;
            let hi = region
                .get("maxM")
                .and_then(|v| v.as_f64())
                .ok_or_else(|| CoreError::Json("region.maxM required".into()))?;
            Ok(lo <= position[2] && position[2] <= hi)
        }
        other => Err(CoreError::Json(format!("unknown region type: {other:?}"))),
    }
}

/// True if `child` is fully contained in `parent` (a valid shrink-only sub-region).
/// A type mismatch is not a valid attenuation and returns false.
pub fn region_attenuates(parent: &Value, child: &Value) -> Result<bool> {
    let pk = parent.get("type").and_then(|v| v.as_str());
    let ck = child.get("type").and_then(|v| v.as_str());
    if pk != ck {
        return Ok(false);
    }
    match pk {
        Some("sphere") => {
            let pc = parent.get("centerM").and_then(vec3);
            let cc = child.get("centerM").and_then(vec3);
            let pr = parent.get("radiusM").and_then(|v| v.as_f64());
            let cr = child.get("radiusM").and_then(|v| v.as_f64());
            match (pc, cc, pr, cr) {
                (Some(pc), Some(cc), Some(pr), Some(cr)) => {
                    if pr < 0.0 || cr < 0.0 {
                        return Err(CoreError::Json("radii must be non-negative".into()));
                    }
                    Ok(expected_range_m(cc, pc) + cr <= pr)
                }
                _ => Ok(false),
            }
        }
        Some("box") => {
            let (plo, phi, clo, chi) = (
                parent.get("minM").and_then(vec3),
                parent.get("maxM").and_then(vec3),
                child.get("minM").and_then(vec3),
                child.get("maxM").and_then(vec3),
            );
            match (plo, phi, clo, chi) {
                (Some(plo), Some(phi), Some(clo), Some(chi)) => {
                    Ok((0..3).all(|i| plo[i] <= clo[i] && chi[i] <= phi[i]))
                }
                _ => Ok(false),
            }
        }
        Some("altitudeBand") => {
            let (plo, phi, clo, chi) = (
                parent.get("minM").and_then(|v| v.as_f64()),
                parent.get("maxM").and_then(|v| v.as_f64()),
                child.get("minM").and_then(|v| v.as_f64()),
                child.get("maxM").and_then(|v| v.as_f64()),
            );
            match (plo, phi, clo, chi) {
                (Some(plo), Some(phi), Some(clo), Some(chi)) => Ok(plo <= clo && chi <= phi),
                _ => Ok(false),
            }
        }
        other => Err(CoreError::Json(format!("unknown region type: {other:?}"))),
    }
}

/// Build a signed EphemerisScopedGrantCredential valid only while the holder's
/// navigation state satisfies `region` (PAD-109).
#[allow(clippy::too_many_arguments)]
pub fn build_geoscoped_grant(
    signer_seed: &[u8],
    issuer_did: &str,
    holder_did: &str,
    grant_id: &str,
    region: &Value,
    physical_scope: Option<&Value>,
    parent_grant_id: Option<&str>,
    created: &str,
) -> Result<Value> {
    if grant_id.is_empty() {
        return Err(CoreError::Json("grant_id is required".into()));
    }
    // Validate the region shape.
    region_contains(region, [0.0, 0.0, 0.0])?;

    let mut subject = Map::new();
    subject.insert("id".into(), json!(holder_did));
    subject.insert("grantId".into(), json!(grant_id));
    subject.insert("region".into(), region.clone());
    if let Some(ps) = physical_scope {
        subject.insert("physicalScope".into(), ps.clone());
    }
    if let Some(p) = parent_grant_id {
        subject.insert("parentGrantId".into(), json!(p));
    }

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert("type".into(), json!(["VerifiableCredential", GEOSCOPED_GRANT_TYPE]));
    cred.insert("issuer".into(), json!(issuer_did));
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(vm(issuer_did), created);
    data_integrity::sign(&Value::Object(cred), signer_seed, &opts)
}

/// Verify a geoscoped grant: proof and (when `parent_region` is given) that this
/// grant's region attenuates the parent. Does not evaluate holder position.
pub fn verify_geoscoped_grant(
    credential: &Value,
    public_key: &[u8],
    parent_region: Option<&Value>,
) -> Result<Option<Value>> {
    if !has_type(credential.get("type"), GEOSCOPED_GRANT_TYPE) {
        return Ok(None);
    }
    if !data_integrity::verify_proof(credential, public_key)? {
        return Ok(None);
    }
    let subject = match credential.get("credentialSubject") {
        Some(Value::Object(_)) => credential.get("credentialSubject").cloned().unwrap(),
        _ => return Ok(None),
    };
    let region = match subject.get("region") {
        Some(r) => r,
        None => return Ok(None),
    };
    if let Some(parent) = parent_region {
        if !region_attenuates(parent, region)? {
            return Ok(None);
        }
    }
    Ok(Some(subject))
}

/// Whether a verified geoscoped grant permits action at `position`.
pub fn geoscope_permits(subject: &Value, position: [f64; 3]) -> bool {
    match subject.get("region") {
        Some(region) => region_contains(region, position).unwrap_or(false),
        None => false,
    }
}

// ===========================================================================
// PAD-114: two-body orbital propagation + kinematic plausibility
// ===========================================================================

pub const MU_EARTH: f64 = 3.986_004_418e14;
pub const RANGE_OBSERVATION_TYPE: &str = "RangeObservationCredential";
pub const PROOF_OF_LOCATION_TYPE: &str = "ProofOfLocationCredential";
pub const BEAM_PRESENCE_TYPE: &str = "BeamPresenceAttestation";
pub const CONDITIONAL_REVOCATION_TYPE: &str = "ConditionalRevocationCredential";

fn stumpff_c(z: f64) -> f64 {
    if z > 1e-12 {
        let sz = z.sqrt();
        (1.0 - sz.cos()) / z
    } else if z < -1e-12 {
        let sz = (-z).sqrt();
        (sz.cosh() - 1.0) / (-z)
    } else {
        0.5
    }
}

fn stumpff_s(z: f64) -> f64 {
    if z > 1e-12 {
        let sz = z.sqrt();
        (sz - sz.sin()) / sz.powi(3)
    } else if z < -1e-12 {
        let sz = (-z).sqrt();
        (sz.sinh() - sz) / sz.powi(3)
    } else {
        1.0 / 6.0
    }
}

fn dot(a: [f64; 3], b: [f64; 3]) -> f64 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}
fn norm(a: [f64; 3]) -> f64 {
    dot(a, a).sqrt()
}

/// Propagate a state vector forward by `dt` seconds under two-body gravity `mu`,
/// using the universal-variable formulation. Returns (position, velocity).
pub fn propagate_two_body(
    r0: [f64; 3],
    v0: [f64; 3],
    dt: f64,
    mu: f64,
) -> Result<([f64; 3], [f64; 3])> {
    if mu <= 0.0 {
        return Err(CoreError::Json("mu must be positive".into()));
    }
    if dt == 0.0 {
        return Ok((r0, v0));
    }
    let r0mag = norm(r0);
    let v0mag = norm(v0);
    if r0mag == 0.0 {
        return Err(CoreError::Json("degenerate state: |r0| = 0".into()));
    }
    let sqrt_mu = mu.sqrt();
    let vr0 = dot(r0, v0) / r0mag;
    let alpha = 2.0 / r0mag - v0mag * v0mag / mu;
    let mut chi = sqrt_mu * alpha.abs() * dt;

    let mut converged = false;
    for _ in 0..100 {
        let z = alpha * chi * chi;
        let c = stumpff_c(z);
        let s = stumpff_s(z);
        let f = (r0mag * vr0 / sqrt_mu) * chi * chi * c
            + (1.0 - alpha * r0mag) * chi.powi(3) * s
            + r0mag * chi
            - sqrt_mu * dt;
        let df = (r0mag * vr0 / sqrt_mu) * chi * (1.0 - alpha * chi * chi * s)
            + (1.0 - alpha * r0mag) * chi * chi * c
            + r0mag;
        if df == 0.0 {
            return Err(CoreError::Json("two-body propagation stalled".into()));
        }
        let dchi = f / df;
        chi -= dchi;
        if dchi.abs() < 1e-8 {
            converged = true;
            break;
        }
    }
    if !converged {
        return Err(CoreError::Json("two-body propagation did not converge".into()));
    }

    let z = alpha * chi * chi;
    let c = stumpff_c(z);
    let s = stumpff_s(z);
    let fl = 1.0 - (chi * chi / r0mag) * c;
    let gl = dt - (chi.powi(3) / sqrt_mu) * s;
    let r = [
        fl * r0[0] + gl * v0[0],
        fl * r0[1] + gl * v0[1],
        fl * r0[2] + gl * v0[2],
    ];
    let rmag = norm(r);
    if rmag == 0.0 {
        return Err(CoreError::Json("degenerate propagated state".into()));
    }
    let fdot = (sqrt_mu / (rmag * r0mag)) * (alpha * chi.powi(3) * s - chi);
    let gdot = 1.0 - (chi * chi / rmag) * c;
    let v = [
        fdot * r0[0] + gdot * v0[0],
        fdot * r0[1] + gdot * v0[1],
        fdot * r0[2] + gdot * v0[2],
    ];
    Ok((r, v))
}

/// True if `claimed` is reachable from the prior orbital state within `elapsed`:
/// propagate the coast, then allow a `max_delta_v * elapsed` ball plus tolerance.
pub fn reachable_two_body(
    prior_position: [f64; 3],
    prior_velocity: [f64; 3],
    claimed_position: [f64; 3],
    elapsed_seconds: f64,
    mu: f64,
    max_delta_v_mps: f64,
    tolerance_m: f64,
) -> Result<bool> {
    if elapsed_seconds < 0.0 {
        return Err(CoreError::Json("elapsed_seconds must be non-negative".into()));
    }
    let (r_pred, _) = propagate_two_body(prior_position, prior_velocity, elapsed_seconds, mu)?;
    let d = expected_range_m(claimed_position, r_pred);
    Ok(d <= max_delta_v_mps * elapsed_seconds + tolerance_m)
}

/// Kinematic reachability dispatching on the `envelope` JSON:
/// surface `{"maxSpeedMps": v}`; orbital ball `{"maxDeltaVMps": dv}` with velocity;
/// two-body `{"model": "two-body", "maxDeltaVMps": dv, "muM3S2": mu?}` with velocity.
pub fn kinematically_reachable(
    prior_position: [f64; 3],
    claimed_position: [f64; 3],
    elapsed_seconds: f64,
    envelope: &Value,
    prior_velocity: Option<[f64; 3]>,
    tolerance_m: f64,
) -> Result<bool> {
    if elapsed_seconds < 0.0 {
        return Err(CoreError::Json("elapsed_seconds must be non-negative".into()));
    }
    if envelope.get("model").and_then(|v| v.as_str()) == Some("two-body") {
        let v0 = prior_velocity
            .ok_or_else(|| CoreError::Json("two-body model requires prior_velocity".into()))?;
        let mu = envelope.get("muM3S2").and_then(|v| v.as_f64()).unwrap_or(MU_EARTH);
        let dv = envelope.get("maxDeltaVMps").and_then(|v| v.as_f64()).unwrap_or(0.0);
        return reachable_two_body(prior_position, v0, claimed_position, elapsed_seconds, mu, dv, tolerance_m);
    }
    let d = expected_range_m(prior_position, claimed_position);
    let reach = if let Some(dv) = envelope.get("maxDeltaVMps").and_then(|v| v.as_f64()) {
        let v0 = prior_velocity.map(norm).unwrap_or(0.0);
        (v0 + dv) * elapsed_seconds
    } else {
        envelope.get("maxSpeedMps").and_then(|v| v.as_f64()).unwrap_or(0.0) * elapsed_seconds
    };
    Ok(d <= reach + tolerance_m)
}

// ===========================================================================
// PAD-113: distributed proof of location
// ===========================================================================

#[allow(clippy::too_many_arguments)]
pub fn build_range_observation(
    observer_seed: &[u8],
    observer_did: &str,
    target_did: &str,
    observer_position: [f64; 3],
    measured_range_m: f64,
    nonce: &str,
    epoch: i64,
    created: &str,
) -> Result<Value> {
    let mut subject = Map::new();
    subject.insert("id".into(), json!(target_did));
    subject.insert("observer".into(), json!(observer_did));
    subject.insert("observerPosition".into(), json!(observer_position.to_vec()));
    subject.insert("measuredRangeM".into(), json!(measured_range_m));
    subject.insert("nonce".into(), json!(nonce));
    subject.insert("epoch".into(), json!(epoch));

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert("type".into(), json!(["VerifiableCredential", RANGE_OBSERVATION_TYPE]));
    cred.insert("issuer".into(), json!(observer_did));
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(vm(observer_did), created);
    data_integrity::sign(&Value::Object(cred), observer_seed, &opts)
}

pub fn verify_range_observation(observation: &Value, observer_public_key: &[u8]) -> Result<Option<Value>> {
    if !has_type(observation.get("type"), RANGE_OBSERVATION_TYPE) {
        return Ok(None);
    }
    if !data_integrity::verify_proof(observation, observer_public_key)? {
        return Ok(None);
    }
    Ok(observation.get("credentialSubject").cloned())
}

/// Count how many observation subjects are consistent with `claimed_position`.
pub fn count_consistent(subjects: &[Value], claimed_position: [f64; 3], tolerance_m: f64) -> usize {
    let mut n = 0;
    for s in subjects {
        let obs_pos = s.get("observerPosition").and_then(vec3);
        let measured = s.get("measuredRangeM").and_then(|v| v.as_f64());
        if let (Some(p), Some(m)) = (obs_pos, measured) {
            if (m - expected_range_m(p, claimed_position)).abs() <= tolerance_m {
                n += 1;
            }
        }
    }
    n
}

/// True if at least `threshold` observations are consistent with the claimed position.
pub fn location_confirmed(subjects: &[Value], claimed_position: [f64; 3], tolerance_m: f64, threshold: usize) -> bool {
    threshold > 0 && count_consistent(subjects, claimed_position, tolerance_m) >= threshold
}

pub fn build_proof_of_location(
    combiner_seed: &[u8],
    combiner_did: &str,
    target_did: &str,
    position: [f64; 3],
    observer_dids: &[String],
    epoch: i64,
    created: &str,
) -> Result<Value> {
    let mut subject = Map::new();
    subject.insert("id".into(), json!(target_did));
    subject.insert("position".into(), json!(position.to_vec()));
    subject.insert("observers".into(), json!(observer_dids));
    subject.insert("epoch".into(), json!(epoch));

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert("type".into(), json!(["VerifiableCredential", PROOF_OF_LOCATION_TYPE]));
    cred.insert("issuer".into(), json!(combiner_did));
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(vm(combiner_did), created);
    data_integrity::sign(&Value::Object(cred), combiner_seed, &opts)
}

// ===========================================================================
// PAD-121: narrow-beam optical alignment presence
// ===========================================================================

/// True if `peer_direction` lies within half the beamwidth of the `pointing` axis.
pub fn within_beam(pointing: [f64; 3], peer_direction: [f64; 3], beamwidth_rad: f64) -> bool {
    if beamwidth_rad < 0.0 {
        return false;
    }
    let na = norm(pointing);
    let nb = norm(peer_direction);
    if na == 0.0 || nb == 0.0 {
        return false;
    }
    let cos = (dot(pointing, peer_direction) / (na * nb)).clamp(-1.0, 1.0);
    cos.acos() <= beamwidth_rad / 2.0
}

pub fn build_beam_presence(
    signer_seed: &[u8],
    issuer_did: &str,
    peer_did: &str,
    nonce: &str,
    pointing: [f64; 3],
    beamwidth_rad: f64,
    created: &str,
) -> Result<Value> {
    let mut subject = Map::new();
    subject.insert("id".into(), json!(peer_did));
    subject.insert("nonce".into(), json!(nonce));
    subject.insert("pointing".into(), json!(pointing.to_vec()));
    subject.insert("beamwidthRad".into(), json!(beamwidth_rad));

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert("type".into(), json!(["VerifiableCredential", BEAM_PRESENCE_TYPE]));
    cred.insert("issuer".into(), json!(issuer_did));
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(vm(issuer_did), created);
    data_integrity::sign(&Value::Object(cred), signer_seed, &opts)
}

pub fn verify_beam_presence(
    attestation: &Value,
    public_key: &[u8],
    peer_direction: [f64; 3],
    expected_nonce: Option<&str>,
) -> Result<Option<Value>> {
    if !has_type(attestation.get("type"), BEAM_PRESENCE_TYPE) {
        return Ok(None);
    }
    if !data_integrity::verify_proof(attestation, public_key)? {
        return Ok(None);
    }
    let subject = match attestation.get("credentialSubject") {
        Some(Value::Object(_)) => attestation.get("credentialSubject").cloned().unwrap(),
        _ => return Ok(None),
    };
    if let Some(want) = expected_nonce {
        if subject.get("nonce").and_then(|v| v.as_str()) != Some(want) {
            return Ok(None);
        }
    }
    let pointing = match subject.get("pointing").and_then(vec3) {
        Some(p) => p,
        None => return Ok(None),
    };
    let beamwidth = match subject.get("beamwidthRad").and_then(|v| v.as_f64()) {
        Some(b) => b,
        None => return Ok(None),
    };
    if !within_beam(pointing, peer_direction, beamwidth) {
        return Ok(None);
    }
    Ok(Some(subject))
}

// ===========================================================================
// PAD-112: conditional dead-man revocation
// ===========================================================================

pub fn build_conditional_revocation(
    authority_seed: &[u8],
    authority_did: &str,
    target_credential_id: &str,
    subject_did: &str,
    deadline_epoch: i64,
    created: &str,
) -> Result<Value> {
    if target_credential_id.is_empty() {
        return Err(CoreError::Json("target_credential_id is required".into()));
    }
    if deadline_epoch < 0 {
        return Err(CoreError::Json("deadline_epoch must be non-negative".into()));
    }
    let mut subject = Map::new();
    subject.insert("id".into(), json!(subject_did));
    subject.insert("targetCredentialId".into(), json!(target_credential_id));
    subject.insert("deadlineEpoch".into(), json!(deadline_epoch));
    subject.insert("renewalPredicate".into(), json!("renewal_epoch_gte_deadline"));

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert("type".into(), json!(["VerifiableCredential", CONDITIONAL_REVOCATION_TYPE]));
    cred.insert("issuer".into(), json!(authority_did));
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(vm(authority_did), created);
    data_integrity::sign(&Value::Object(cred), authority_seed, &opts)
}

pub fn verify_conditional_revocation(credential: &Value, authority_public_key: &[u8]) -> Result<Option<Value>> {
    if !has_type(credential.get("type"), CONDITIONAL_REVOCATION_TYPE) {
        return Ok(None);
    }
    if !data_integrity::verify_proof(credential, authority_public_key)? {
        return Ok(None);
    }
    Ok(credential.get("credentialSubject").cloned())
}

/// True if the dead-man revocation has fired: deadline passed and no renewal at or
/// beyond the deadline was observed.
pub fn conditional_revocation_active(
    subject: &Value,
    current_epoch: i64,
    last_renewal_epoch: Option<i64>,
) -> Result<bool> {
    let deadline = subject
        .get("deadlineEpoch")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| CoreError::Json("subject missing integer deadlineEpoch".into()))?;
    if current_epoch <= deadline {
        return Ok(false);
    }
    let renewed = matches!(last_renewal_epoch, Some(r) if r >= deadline);
    Ok(!renewed)
}

// ===========================================================================
// PAD-120: dynamic revocation accumulator (sparse Merkle tree)
// ===========================================================================

pub const SMT_DEPTH: usize = 256;
pub const REVOCATION_ACCUMULATOR_TYPE: &str = "RevocationAccumulatorRoot";

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn empty_leaf() -> [u8; 32] {
    [0u8; 32]
}

fn revoked_leaf() -> [u8; 32] {
    sha256(&[b"vouch:smt:revoked-leaf:v1"])
}

/// Precomputed default (all-empty) subtree hash at each level, defaults[256]=empty.
fn defaults() -> &'static [[u8; 32]; SMT_DEPTH + 1] {
    static DEFAULTS: OnceLock<[[u8; 32]; SMT_DEPTH + 1]> = OnceLock::new();
    DEFAULTS.get_or_init(|| {
        let mut d = [[0u8; 32]; SMT_DEPTH + 1];
        d[SMT_DEPTH] = empty_leaf();
        for i in (0..SMT_DEPTH).rev() {
            d[i] = sha256(&[&d[i + 1], &d[i + 1]]);
        }
        d
    })
}

fn smt_key(credential_id: &str) -> [u8; 32] {
    sha256(&[credential_id.as_bytes()])
}

fn smt_bit(key: &[u8; 32], level: usize) -> u8 {
    (key[level >> 3] >> (7 - (level & 7))) & 1
}

fn smt_node(level: usize, keys: &[[u8; 32]]) -> [u8; 32] {
    if keys.is_empty() {
        return defaults()[level];
    }
    if level == SMT_DEPTH {
        return revoked_leaf();
    }
    let (left, right): (Vec<_>, Vec<_>) = keys.iter().partition(|k| smt_bit(k, level) == 0);
    sha256(&[&smt_node(level + 1, &left), &smt_node(level + 1, &right)])
}

/// A dynamic revocation accumulator over the revoked set (PAD-120).
#[derive(Debug, Default, Clone)]
pub struct SparseMerkleTree {
    revoked: HashSet<[u8; 32]>,
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn revoke(&mut self, credential_id: &str) {
        self.revoked.insert(smt_key(credential_id));
    }
    pub fn unrevoke(&mut self, credential_id: &str) {
        self.revoked.remove(&smt_key(credential_id));
    }
    pub fn is_revoked(&self, credential_id: &str) -> bool {
        self.revoked.contains(&smt_key(credential_id))
    }
    pub fn root(&self) -> [u8; 32] {
        let keys: Vec<[u8; 32]> = self.revoked.iter().copied().collect();
        smt_node(0, &keys)
    }
    pub fn root_multibase(&self) -> String {
        mb64(&self.root())
    }
    /// Compressed non-membership proof: only non-default siblings, indexed by a bitmap.
    pub fn non_revocation_proof(&self, credential_id: &str) -> Value {
        let key = smt_key(credential_id);
        let mut keys: Vec<[u8; 32]> = self.revoked.iter().copied().collect();
        let mut bitmap = [0u8; SMT_DEPTH / 8];
        let mut siblings: Vec<String> = Vec::new();
        for level in 0..SMT_DEPTH {
            let (left, right): (Vec<_>, Vec<_>) = keys.iter().partition(|k| smt_bit(k, level) == 0);
            let (sib, next) = if smt_bit(&key, level) == 0 {
                (smt_node(level + 1, &right), left)
            } else {
                (smt_node(level + 1, &left), right)
            };
            keys = next;
            if sib != defaults()[level + 1] {
                bitmap[level >> 3] |= 1 << (7 - (level & 7));
                siblings.push(mb64(&sib));
            }
        }
        json!({"bitmap": mb64(&bitmap), "siblings": siblings})
    }
}

/// Verify a non-membership proof against `root` (assuming an empty leaf: not revoked).
pub fn verify_non_revocation_proof(credential_id: &str, proof: &Value, root: &[u8; 32]) -> bool {
    let key = smt_key(credential_id);
    let bitmap = match proof.get("bitmap").and_then(|v| v.as_str()).and_then(|s| unmb64(s).ok()) {
        Some(b) if b.len() == SMT_DEPTH / 8 => b,
        _ => return false,
    };
    let sib_list: Vec<[u8; 32]> = match proof.get("siblings").and_then(|v| v.as_array()) {
        Some(arr) => {
            let mut out = Vec::new();
            for s in arr {
                match s.as_str().and_then(|x| unmb64(x).ok()) {
                    Some(b) if b.len() == 32 => {
                        let mut a = [0u8; 32];
                        a.copy_from_slice(&b);
                        out.push(a);
                    }
                    _ => return false,
                }
            }
            out
        }
        None => return false,
    };
    // Map siblings to levels (ascending), defaults where bitmap bit unset.
    let mut sib_by_level = [[0u8; 32]; SMT_DEPTH];
    let mut idx = 0usize;
    for (level, slot) in sib_by_level.iter_mut().enumerate() {
        if (bitmap[level >> 3] >> (7 - (level & 7))) & 1 == 1 {
            if idx >= sib_list.len() {
                return false;
            }
            *slot = sib_list[idx];
            idx += 1;
        } else {
            *slot = defaults()[level + 1];
        }
    }
    if idx != sib_list.len() {
        return false;
    }
    let mut current = empty_leaf();
    for level in (0..SMT_DEPTH).rev() {
        let sibling = sib_by_level[level];
        current = if smt_bit(&key, level) == 0 {
            sha256(&[&current, &sibling])
        } else {
            sha256(&[&sibling, &current])
        };
    }
    &current == root
}

/// Sign the current accumulator root at `epoch` for distribution (PAD-120).
pub fn build_revocation_accumulator_root(
    authority_seed: &[u8],
    authority_did: &str,
    tree: &SparseMerkleTree,
    epoch: i64,
    created: &str,
) -> Result<Value> {
    if epoch < 0 {
        return Err(CoreError::Json("epoch must be non-negative".into()));
    }
    let mut subject = Map::new();
    subject.insert("id".into(), json!(authority_did));
    subject.insert("epoch".into(), json!(epoch));
    subject.insert("revocationRoot".into(), json!(tree.root_multibase()));

    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert("type".into(), json!(["VerifiableCredential", REVOCATION_ACCUMULATOR_TYPE]));
    cred.insert("issuer".into(), json!(authority_did));
    cred.insert("credentialSubject".into(), Value::Object(subject));

    let opts = BuildProofOptions::new(vm(authority_did), created);
    data_integrity::sign(&Value::Object(cred), authority_seed, &opts)
}

/// Verify offline that `credential_id` is not revoked as of the authority's signed root.
pub fn verify_non_revocation(
    credential_id: &str,
    proof: &Value,
    signed_root_credential: &Value,
    authority_public_key: &[u8],
) -> Result<bool> {
    if !has_type(signed_root_credential.get("type"), REVOCATION_ACCUMULATOR_TYPE) {
        return Ok(false);
    }
    if !data_integrity::verify_proof(signed_root_credential, authority_public_key)? {
        return Ok(false);
    }
    let root_mb = signed_root_credential
        .get("credentialSubject")
        .and_then(|s| s.get("revocationRoot"))
        .and_then(|v| v.as_str());
    let root_vec = match root_mb.and_then(|s| unmb64(s).ok()) {
        Some(b) if b.len() == 32 => b,
        _ => return Ok(false),
    };
    let mut root = [0u8; 32];
    root.copy_from_slice(&root_vec);
    Ok(verify_non_revocation_proof(credential_id, proof, &root))
}

// ===========================================================================
// PAD-110/111/116: swarm quarantine, quorum-of-orbits, key continuity
// ===========================================================================

pub const DISTRESS_TYPE: &str = "DistressAttestation";
pub const TRUST_STATE_UPDATE_TYPE: &str = "TrustStateUpdate";
pub const KEY_CONTINUITY_PREDELEGATION_TYPE: &str = "KeyContinuityPredelegation";
pub const CONTINUITY_APPROVAL_TYPE: &str = "ContinuityApproval";

#[allow(clippy::too_many_arguments)]
pub fn build_distress_attestation(
    observer_seed: &[u8],
    observer_did: &str,
    target_did: &str,
    reason: &str,
    evidence_ref: &str,
    epoch: i64,
    created: &str,
) -> Result<Value> {
    if target_did.is_empty() || reason.is_empty() || evidence_ref.is_empty() {
        return Err(CoreError::Json("target_did, reason, evidence_ref required".into()));
    }
    let mut subject = Map::new();
    subject.insert("id".into(), json!(target_did));
    subject.insert("observer".into(), json!(observer_did));
    subject.insert("reason".into(), json!(reason));
    subject.insert("evidenceRef".into(), json!(evidence_ref));
    subject.insert("epoch".into(), json!(epoch));
    sign_subject(observer_seed, observer_did, DISTRESS_TYPE, subject, created)
}

pub fn verify_distress_attestation(attestation: &Value, observer_public_key: &[u8]) -> Result<Option<Value>> {
    verify_typed(attestation, observer_public_key, DISTRESS_TYPE)
}

/// True if at least `threshold` distinct attested members signed distress against
/// `target_did`, optionally within an inclusive epoch `window`.
pub fn is_quarantined(
    distress_subjects: &[Value],
    target_did: &str,
    threshold: usize,
    member_dids: &HashSet<String>,
    window: Option<(i64, i64)>,
) -> bool {
    if threshold == 0 {
        return false;
    }
    let mut signers: HashSet<&str> = HashSet::new();
    for s in distress_subjects {
        if s.get("id").and_then(|v| v.as_str()) != Some(target_did) {
            continue;
        }
        let observer = match s.get("observer").and_then(|v| v.as_str()) {
            Some(o) if member_dids.contains(o) => o,
            _ => continue,
        };
        if let Some((lo, hi)) = window {
            match s.get("epoch").and_then(|v| v.as_i64()) {
                Some(e) if lo <= e && e <= hi => {}
                _ => continue,
            }
        }
        signers.insert(observer);
    }
    signers.len() >= threshold
}

pub fn build_trust_state_update(
    anchor_seed: &[u8],
    anchor_did: &str,
    scope: &str,
    change: &Value,
    epoch: i64,
    failure_domain: &str,
    created: &str,
) -> Result<Value> {
    if scope.is_empty() || failure_domain.is_empty() {
        return Err(CoreError::Json("scope and failure_domain required".into()));
    }
    let mut subject = Map::new();
    subject.insert("id".into(), json!(anchor_did));
    subject.insert("scope".into(), json!(scope));
    subject.insert("change".into(), change.clone());
    subject.insert("epoch".into(), json!(epoch));
    subject.insert("failureDomain".into(), json!(failure_domain));
    sign_subject(anchor_seed, anchor_did, TRUST_STATE_UPDATE_TYPE, subject, created)
}

pub fn verify_trust_state_update(update: &Value, anchor_public_key: &[u8]) -> Result<Option<Value>> {
    verify_typed(update, anchor_public_key, TRUST_STATE_UPDATE_TYPE)
}

/// Accept a change only when at least `threshold` corroborations agree on the same
/// (scope, change, epoch) from DISTINCT failure domains, with no epoch rollback.
pub fn accept_trust_state_update(corroborating_subjects: &[Value], current_epoch: i64, threshold: usize) -> bool {
    if threshold == 0 || corroborating_subjects.is_empty() {
        return false;
    }
    let reference = &corroborating_subjects[0];
    let scope = reference.get("scope");
    let change = reference.get("change");
    let epoch = match reference.get("epoch").and_then(|v| v.as_i64()) {
        Some(e) if e >= current_epoch => e,
        _ => return false,
    };
    let mut domains: HashSet<&str> = HashSet::new();
    for s in corroborating_subjects {
        if s.get("scope") != scope || s.get("change") != change || s.get("epoch").and_then(|v| v.as_i64()) != Some(epoch) {
            continue;
        }
        if let Some(fd) = s.get("failureDomain").and_then(|v| v.as_str()) {
            domains.insert(fd);
        }
    }
    domains.len() >= threshold
}

pub fn build_key_continuity_predelegation(
    authority_seed: &[u8],
    authority_did: &str,
    mission_credential_id: &str,
    member_dids: &[String],
    threshold: usize,
    created: &str,
) -> Result<Value> {
    let mut members: Vec<String> = member_dids.iter().cloned().collect::<HashSet<_>>().into_iter().collect();
    members.sort();
    if threshold == 0 || threshold > members.len() {
        return Err(CoreError::Json("threshold must be in 1..=len(members)".into()));
    }
    let mut subject = Map::new();
    subject.insert("id".into(), json!(mission_credential_id));
    subject.insert("members".into(), json!(members));
    subject.insert("threshold".into(), json!(threshold));
    subject.insert("bound".into(), json!("preserve_or_narrow"));
    sign_subject(authority_seed, authority_did, KEY_CONTINUITY_PREDELEGATION_TYPE, subject, created)
}

pub fn build_continuity_approval(
    member_seed: &[u8],
    member_did: &str,
    reissuance_id: &str,
    supersedes: &str,
    epoch: i64,
    created: &str,
) -> Result<Value> {
    let mut subject = Map::new();
    subject.insert("id".into(), json!(reissuance_id));
    subject.insert("member".into(), json!(member_did));
    subject.insert("supersedes".into(), json!(supersedes));
    subject.insert("epoch".into(), json!(epoch));
    sign_subject(member_seed, member_did, CONTINUITY_APPROVAL_TYPE, subject, created)
}

/// Confirm an offline re-issuance: pre-delegation authorized the group and at least
/// `threshold` distinct authorized members approved THIS re-issuance.
pub fn verify_key_continuity(
    predelegation_subject: &Value,
    reissuance_id: &str,
    supersedes: &str,
    approval_subjects: &[Value],
) -> bool {
    let members: HashSet<&str> = predelegation_subject
        .get("members")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let threshold = match predelegation_subject.get("threshold").and_then(|v| v.as_u64()) {
        Some(t) if t > 0 => t as usize,
        _ => return false,
    };
    let mut approvers: HashSet<&str> = HashSet::new();
    for s in approval_subjects {
        if s.get("id").and_then(|v| v.as_str()) != Some(reissuance_id)
            || s.get("supersedes").and_then(|v| v.as_str()) != Some(supersedes)
        {
            continue;
        }
        if let Some(m) = s.get("member").and_then(|v| v.as_str()) {
            if members.contains(m) {
                approvers.insert(m);
            }
        }
    }
    approvers.len() >= threshold
}

// ===========================================================================
// PAD-115/117/118: time-quality, autonomy envelope, integrity risk
// ===========================================================================

pub const TIME_QUALITY_TYPE: &str = "TimeQualityAttestation";
pub const AUTONOMY_SCHEDULE_TYPE: &str = "AutonomyDecaySchedule";
pub const INTEGRITY_RISK_TYPE: &str = "IntegrityRiskAttestation";
pub const INTEGRITY_FULL: &str = "full";
pub const INTEGRITY_NARROWED: &str = "narrowed";
pub const INTEGRITY_SUSPECT: &str = "suspect";

pub fn default_time_uncertainty_budget(tier: &str) -> f64 {
    match tier_or_critical(tier) {
        CONSEQUENCE_ROUTINE => 3600.0,
        CONSEQUENCE_SENSITIVE => 60.0,
        _ => 1.0,
    }
}

pub fn build_time_quality_attestation(
    signer_seed: &[u8],
    signer_did: &str,
    source_class: &str,
    since_discipline_s: f64,
    uncertainty_s: f64,
    created: &str,
) -> Result<Value> {
    if uncertainty_s < 0.0 || since_discipline_s < 0.0 {
        return Err(CoreError::Json("uncertainty_s and since_discipline_s must be non-negative".into()));
    }
    let mut subject = Map::new();
    subject.insert("id".into(), json!(signer_did));
    subject.insert("sourceClass".into(), json!(source_class));
    subject.insert("sinceDisciplineS".into(), json!(since_discipline_s));
    subject.insert("uncertaintyS".into(), json!(uncertainty_s));
    sign_subject(signer_seed, signer_did, TIME_QUALITY_TYPE, subject, created)
}

pub fn verify_time_quality_attestation(attestation: &Value, public_key: &[u8]) -> Result<Option<Value>> {
    verify_typed(attestation, public_key, TIME_QUALITY_TYPE)
}

pub fn time_quality_permits(subject: &Value, tier: &str, budget_override: Option<f64>) -> bool {
    let unc = match subject.get("uncertaintyS").and_then(|v| v.as_f64()) {
        Some(u) => u,
        None => return false,
    };
    let budget = budget_override.unwrap_or_else(|| default_time_uncertainty_budget(tier));
    unc <= budget
}

/// Build a signed decay schedule; `steps` is a JSON array of
/// {"maxStalenessEpochs": int, "physicalScope": {...}}, strictly ascending and
/// each scope attenuating the previous. Validated on build.
pub fn build_autonomy_schedule(
    authority_seed: &[u8],
    authority_did: &str,
    subject_did: &str,
    steps: &Value,
    created: &str,
) -> Result<Value> {
    let arr = steps
        .as_array()
        .ok_or_else(|| CoreError::Json("steps must be an array".into()))?;
    if arr.is_empty() {
        return Err(CoreError::Json("steps must be non-empty".into()));
    }
    let mut prev_thresh: i64 = -1;
    let mut prev_scope: Option<&Value> = None;
    for st in arr {
        let thresh = st
            .get("maxStalenessEpochs")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| CoreError::Json("maxStalenessEpochs must be an integer".into()))?;
        if thresh <= prev_thresh {
            return Err(CoreError::Json("maxStalenessEpochs must be strictly ascending".into()));
        }
        let scope = st
            .get("physicalScope")
            .ok_or_else(|| CoreError::Json("each step needs a physicalScope".into()))?;
        if let Some(prev) = prev_scope {
            if !attenuates(prev, scope) {
                return Err(CoreError::Json("each step's scope must attenuate the previous".into()));
            }
        }
        prev_thresh = thresh;
        prev_scope = Some(scope);
    }
    let mut subject = Map::new();
    subject.insert("id".into(), json!(subject_did));
    subject.insert("steps".into(), steps.clone());
    sign_subject(authority_seed, authority_did, AUTONOMY_SCHEDULE_TYPE, subject, created)
}

pub fn verify_autonomy_schedule(schedule: &Value, authority_public_key: &[u8]) -> Result<Option<Value>> {
    verify_typed(schedule, authority_public_key, AUTONOMY_SCHEDULE_TYPE)
}

/// Select the physical scope for the current staleness: the first step whose
/// threshold >= staleness; beyond the last, the tightest step's scope.
pub fn select_envelope(schedule_subject: &Value, staleness_epochs: i64) -> Option<Value> {
    let steps = schedule_subject.get("steps")?.as_array()?;
    for st in steps {
        if let Some(t) = st.get("maxStalenessEpochs").and_then(|v| v.as_i64()) {
            if staleness_epochs <= t {
                return st.get("physicalScope").cloned();
            }
        }
    }
    steps.last().and_then(|st| st.get("physicalScope").cloned())
}

pub fn autonomy_permits(schedule_subject: &Value, staleness_epochs: i64, action: &PhysicalAction) -> bool {
    match select_envelope(schedule_subject, staleness_epochs) {
        Some(scope) => check_physical_action(&scope, action).ok,
        None => false,
    }
}

pub fn build_integrity_risk_attestation(
    signer_seed: &[u8],
    signer_did: &str,
    cumulative_risk: f64,
    metrics: Option<&Value>,
    prev_hash: Option<&str>,
    created: &str,
) -> Result<Value> {
    if cumulative_risk < 0.0 {
        return Err(CoreError::Json("cumulative_risk must be non-negative".into()));
    }
    let mut subject = Map::new();
    subject.insert("id".into(), json!(signer_did));
    subject.insert("cumulativeRisk".into(), json!(cumulative_risk));
    if let Some(m) = metrics {
        subject.insert("metrics".into(), m.clone());
    }
    if let Some(p) = prev_hash {
        subject.insert("prevHash".into(), json!(p));
    }
    sign_subject(signer_seed, signer_did, INTEGRITY_RISK_TYPE, subject, created)
}

pub fn verify_integrity_risk_attestation(attestation: &Value, public_key: &[u8]) -> Result<Option<Value>> {
    verify_typed(attestation, public_key, INTEGRITY_RISK_TYPE)
}

/// Deterministic risk-to-authority mapping (defaults: narrow 0.3, suspect 0.7).
pub fn integrity_authority_level(cumulative_risk: f64, narrow_threshold: f64, suspect_threshold: f64) -> &'static str {
    if cumulative_risk >= suspect_threshold {
        INTEGRITY_SUSPECT
    } else if cumulative_risk >= narrow_threshold {
        INTEGRITY_NARROWED
    } else {
        INTEGRITY_FULL
    }
}

// ===========================================================================
// PAD-122/123: perception consensus + mutual-attestation mesh
// ===========================================================================

pub const PERCEPTION_CLAIM_TYPE: &str = "SharedPerceptionClaim";
pub const INTERACTION_ATTESTATION_TYPE: &str = "InteractionAttestation";

pub fn build_perception_claim(
    signer_seed: &[u8],
    signer_did: &str,
    scene_nonce: &str,
    feature: &str,
    value: &Value,
    epoch: i64,
    created: &str,
) -> Result<Value> {
    if scene_nonce.is_empty() || feature.is_empty() {
        return Err(CoreError::Json("scene_nonce and feature required".into()));
    }
    let mut subject = Map::new();
    subject.insert("id".into(), json!(signer_did));
    subject.insert("sceneNonce".into(), json!(scene_nonce));
    subject.insert("feature".into(), json!(feature));
    subject.insert("value".into(), value.clone());
    subject.insert("epoch".into(), json!(epoch));
    sign_subject(signer_seed, signer_did, PERCEPTION_CLAIM_TYPE, subject, created)
}

pub fn verify_perception_claim(claim: &Value, public_key: &[u8]) -> Result<Option<Value>> {
    verify_typed(claim, public_key, PERCEPTION_CLAIM_TYPE)
}

fn value_distance(a: &Value, b: &Value) -> Option<f64> {
    if let (Some(x), Some(y)) = (a.as_f64(), b.as_f64()) {
        return Some((x - y).abs());
    }
    if let (Some(x), Some(y)) = (a.as_array(), b.as_array()) {
        if x.len() == y.len() {
            let mut sum = 0.0;
            for i in 0..x.len() {
                let (xi, yi) = (x[i].as_f64()?, y[i].as_f64()?);
                sum += (xi - yi).powi(2);
            }
            return Some(sum.sqrt());
        }
    }
    None
}

/// Cross-check perception claims of one shared feature. Returns (corroborated,
/// flagged) DIDs (each sorted). A node is corroborated when at least `threshold`
/// OTHER nodes agree within `tolerance`.
pub fn cross_check_perception(claim_subjects: &[Value], tolerance: f64, threshold: usize) -> (Vec<String>, Vec<String>) {
    let entries: Vec<(&str, &Value)> = claim_subjects
        .iter()
        .filter_map(|s| Some((s.get("id")?.as_str()?, s.get("value")?)))
        .collect();
    let mut corroborated = Vec::new();
    let mut flagged = Vec::new();
    for (did, val) in &entries {
        let mut agree = 0usize;
        for (other, oval) in &entries {
            if other == did {
                continue;
            }
            if let Some(d) = value_distance(val, oval) {
                if d <= tolerance {
                    agree += 1;
                }
            }
        }
        if agree >= threshold {
            corroborated.push(did.to_string());
        } else {
            flagged.push(did.to_string());
        }
    }
    corroborated.sort();
    flagged.sort();
    (corroborated, flagged)
}

pub fn build_interaction_attestation(
    signer_seed: &[u8],
    signer_did: &str,
    peer_did: &str,
    outcome: &str,
    epoch: i64,
    created: &str,
) -> Result<Value> {
    if peer_did.is_empty() {
        return Err(CoreError::Json("peer_did required".into()));
    }
    let mut subject = Map::new();
    subject.insert("id".into(), json!(peer_did));
    subject.insert("attestor".into(), json!(signer_did));
    subject.insert("outcome".into(), json!(outcome));
    subject.insert("epoch".into(), json!(epoch));
    sign_subject(signer_seed, signer_did, INTERACTION_ATTESTATION_TYPE, subject, created)
}

pub fn verify_interaction_attestation(attestation: &Value, attestor_public_key: &[u8]) -> Result<Option<Value>> {
    verify_typed(attestation, attestor_public_key, INTERACTION_ATTESTATION_TYPE)
}

/// Decay-weighted sum of the freshest positive interaction attestation per distinct
/// neighbor for `node_did`.
pub fn node_standing(
    attestation_subjects: &[Value],
    node_did: &str,
    current_epoch: i64,
    half_life_epochs: f64,
    positive_outcomes: &[&str],
) -> f64 {
    let mut freshest: std::collections::HashMap<&str, i64> = std::collections::HashMap::new();
    for s in attestation_subjects {
        if s.get("id").and_then(|v| v.as_str()) != Some(node_did) {
            continue;
        }
        let outcome = s.get("outcome").and_then(|v| v.as_str()).unwrap_or("");
        if !positive_outcomes.contains(&outcome) {
            continue;
        }
        let attestor = match s.get("attestor").and_then(|v| v.as_str()) {
            Some(a) => a,
            None => continue,
        };
        let e = match s.get("epoch").and_then(|v| v.as_i64()) {
            Some(e) if e <= current_epoch => e,
            _ => continue,
        };
        freshest.entry(attestor).and_modify(|cur| { if e > *cur { *cur = e; } }).or_insert(e);
    }
    let mut total = 0.0;
    for e in freshest.values() {
        if let Ok(w) = decay_weight(current_epoch - e, half_life_epochs, "exponential") {
            total += w;
        }
    }
    total
}

// ===========================================================================
// PAD-124: DTN Bundle Protocol custody binding
// ===========================================================================

pub const BUNDLE_CREDENTIAL_TYPE: &str = "BundleTrustCredential";
pub const CUSTODY_TRANSFER_TYPE: &str = "BundleCustodyTransfer";

pub fn bind_credential_to_bundle(
    originator_seed: &[u8],
    originator_did: &str,
    bundle_id: &str,
    payload_hash: &str,
    intent: &Value,
    created: &str,
) -> Result<Value> {
    if bundle_id.is_empty() || payload_hash.is_empty() {
        return Err(CoreError::Json("bundle_id and payload_hash required".into()));
    }
    let mut subject = Map::new();
    subject.insert("id".into(), json!(bundle_id));
    subject.insert("originator".into(), json!(originator_did));
    subject.insert("payloadHash".into(), json!(payload_hash));
    subject.insert("intent".into(), intent.clone());
    sign_subject(originator_seed, originator_did, BUNDLE_CREDENTIAL_TYPE, subject, created)
}

pub fn verify_bundle_trust(bundle_credential: &Value, originator_public_key: &[u8], payload_hash: &str) -> Result<Option<Value>> {
    match verify_typed(bundle_credential, originator_public_key, BUNDLE_CREDENTIAL_TYPE)? {
        Some(subject) => {
            if subject.get("payloadHash").and_then(|v| v.as_str()) != Some(payload_hash) {
                return Ok(None);
            }
            Ok(Some(subject))
        }
        None => Ok(None),
    }
}

pub fn build_custody_transfer(
    relay_seed: &[u8],
    relay_did: &str,
    bundle_id: &str,
    previous_custodian: Option<&str>,
    epoch: i64,
    created: &str,
) -> Result<Value> {
    let mut subject = Map::new();
    subject.insert("id".into(), json!(bundle_id));
    subject.insert("custodian".into(), json!(relay_did));
    subject.insert("previousCustodian".into(), match previous_custodian {
        Some(p) => json!(p),
        None => Value::Null,
    });
    subject.insert("epoch".into(), json!(epoch));
    sign_subject(relay_seed, relay_did, CUSTODY_TRANSFER_TYPE, subject, created)
}

pub fn verify_custody_transfer(transfer: &Value, custodian_public_key: &[u8]) -> Result<Option<Value>> {
    verify_typed(transfer, custodian_public_key, CUSTODY_TRANSFER_TYPE)
}

/// Confirm custody transfers form an unbroken chain for `bundle_id`.
pub fn custody_chain_ok(transfer_subjects: &[Value], bundle_id: &str, originator: &str) -> bool {
    let chain: Vec<&Value> = transfer_subjects
        .iter()
        .filter(|s| s.get("id").and_then(|v| v.as_str()) == Some(bundle_id))
        .collect();
    if chain.is_empty() {
        return false;
    }
    let mut expected_prev = originator.to_string();
    for s in chain {
        let prev = s.get("previousCustodian").and_then(|v| v.as_str());
        if prev != Some(expected_prev.as_str()) {
            return false;
        }
        match s.get("custodian").and_then(|v| v.as_str()) {
            Some(c) => expected_prev = c.to_string(),
            None => return false,
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Shared helpers for the build/verify pattern above.
// ---------------------------------------------------------------------------

fn sign_subject(seed: &[u8], issuer_did: &str, cred_type: &str, subject: Map<String, Value>, created: &str) -> Result<Value> {
    let mut cred = Map::new();
    cred.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    cred.insert("type".into(), json!(["VerifiableCredential", cred_type]));
    cred.insert("issuer".into(), json!(issuer_did));
    cred.insert("credentialSubject".into(), Value::Object(subject));
    let opts = BuildProofOptions::new(vm(issuer_did), created);
    data_integrity::sign(&Value::Object(cred), seed, &opts)
}

fn verify_typed(credential: &Value, public_key: &[u8], cred_type: &str) -> Result<Option<Value>> {
    if !has_type(credential.get("type"), cred_type) {
        return Ok(None);
    }
    if !data_integrity::verify_proof(credential, public_key)? {
        return Ok(None);
    }
    Ok(credential.get("credentialSubject").cloned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Ed25519KeyPair;

    fn identity(seed: &[u8]) -> (Vec<u8>, String) {
        let kp = Ed25519KeyPair::from_seed_slice(seed).unwrap();
        let pk = kp.public_key().to_vec();
        let did = crate::keys::ed25519_to_did_key(&pk).unwrap();
        (pk, did)
    }

    #[test]
    fn freshness_gate_tiers_and_fail_closed() {
        let now = "2026-07-19T12:00:00Z";
        let snap = json!({"type": ["BitstringStatusListCredential"], "validFrom": "2026-07-19T11:40:00Z"});
        assert!(evaluate_freshness(CONSEQUENCE_CRITICAL, Some(&snap), now, None).unwrap().allow);
        // 5 days old
        let stale = json!({"type": ["BitstringStatusListCredential"], "validFrom": "2026-07-14T12:00:00Z"});
        assert!(evaluate_freshness(CONSEQUENCE_ROUTINE, Some(&stale), now, None).unwrap().allow);
        assert!(!evaluate_freshness(CONSEQUENCE_CRITICAL, Some(&stale), now, None).unwrap().allow);
        // absent snapshot
        assert!(evaluate_freshness(CONSEQUENCE_ROUTINE, None, now, None).unwrap().allow);
        assert!(!evaluate_freshness(CONSEQUENCE_SENSITIVE, None, now, None).unwrap().allow);
        // unknown tier -> critical
        assert!(!evaluate_freshness("wild", Some(&stale), now, None).unwrap().allow);
    }

    #[test]
    fn freshness_token_roundtrip_and_gap() {
        let (pk, did) = identity(&[7u8; 32]);
        let tok = build_freshness_token(&[7u8; 32], &did, "did:web:node", 100, "n", "2026-07-19T12:00:00Z").unwrap();
        assert!(verify_freshness_token(&tok, &pk, 100, CONSEQUENCE_CRITICAL, None, None, None).unwrap().is_some());
        // 4 behind: fails critical (gap 1), passes routine (gap 100)
        assert!(verify_freshness_token(&tok, &pk, 104, CONSEQUENCE_CRITICAL, None, None, None).unwrap().is_none());
        assert!(verify_freshness_token(&tok, &pk, 104, CONSEQUENCE_ROUTINE, None, None, None).unwrap().is_some());
        // rollback
        assert!(verify_freshness_token(&tok, &pk, 100, CONSEQUENCE_CRITICAL, None, None, Some(200)).unwrap().is_none());
    }

    #[test]
    fn decay_curve() {
        assert!((decay_weight(0, 10.0, "exponential").unwrap() - 1.0).abs() < 1e-9);
        assert!((decay_weight(10, 10.0, "exponential").unwrap() - 0.5).abs() < 1e-9);
        assert!(!decay_permits(10, 10.0, CONSEQUENCE_CRITICAL, "exponential", None).unwrap());
        assert!(decay_permits(10, 10.0, CONSEQUENCE_ROUTINE, "exponential", None).unwrap());
    }

    #[test]
    fn presence_roundtrip_and_replay_rejection() {
        let (pk, did) = identity(&[9u8; 32]);
        let att = build_presence_attestation(
            &[9u8; 32], &did, "did:web:peer", "n1", [100.0, 0.0, 0.0], 100.4, 1.0, None, "2026-07-19T12:00:00Z",
        )
        .unwrap();
        assert!(verify_presence_attestation(&att, &pk, [0.0, 0.0, 0.0], Some("n1")).unwrap().is_some());
        // imposter: measured range inconsistent with the claimed position
        let spoof = build_presence_attestation(
            &[9u8; 32], &did, "did:web:peer", "n", [100.0, 0.0, 0.0], 480.0, 1.0, None, "2026-07-19T12:00:00Z",
        )
        .unwrap();
        assert!(verify_presence_attestation(&spoof, &pk, [0.0, 0.0, 0.0], None).unwrap().is_none());
    }

    #[test]
    fn geoscope_regions_and_grant() {
        let (pk, did) = identity(&[11u8; 32]);
        let region = json!({"type": "sphere", "centerM": [0.0, 0.0, 0.0], "radiusM": 50.0});
        let grant = build_geoscoped_grant(&[11u8; 32], &did, "did:web:rover", "g1", &region, None, None, "2026-07-19T12:00:00Z").unwrap();
        let sub = verify_geoscoped_grant(&grant, &pk, None).unwrap().unwrap();
        assert!(geoscope_permits(&sub, [10.0, 10.0, 0.0]));
        assert!(!geoscope_permits(&sub, [40.0, 40.0, 0.0]));
        // attenuation
        let parent = json!({"type": "sphere", "centerM": [0.0, 0.0, 0.0], "radiusM": 100.0});
        let inside = json!({"type": "sphere", "centerM": [10.0, 0.0, 0.0], "radiusM": 20.0});
        let outside = json!({"type": "sphere", "centerM": [90.0, 0.0, 0.0], "radiusM": 20.0});
        assert!(region_attenuates(&parent, &inside).unwrap());
        assert!(!region_attenuates(&parent, &outside).unwrap());
    }

    #[test]
    fn two_body_circular_orbit() {
        let radius = 7.0e6;
        let v = (MU_EARTH / radius).sqrt();
        let period = 2.0 * std::f64::consts::PI * (radius.powi(3) / MU_EARTH).sqrt();
        let (r, _) = propagate_two_body([radius, 0.0, 0.0], [0.0, v, 0.0], period / 4.0, MU_EARTH).unwrap();
        // quarter period: +x rotates to +y, radius conserved
        assert!((norm(r) - radius).abs() / radius < 1e-6);
        assert!(r[0].abs() < 1.0);
        assert!((r[1] - radius).abs() / radius < 1e-6);
    }

    #[test]
    fn kinematic_two_body_dispatch() {
        let radius = 7.0e6;
        let v = (MU_EARTH / radius).sqrt();
        let (r_pred, _) = propagate_two_body([radius, 0.0, 0.0], [0.0, v, 0.0], 120.0, MU_EARTH).unwrap();
        let env = json!({"model": "two-body", "maxDeltaVMps": 0.5});
        assert!(kinematically_reachable([radius, 0.0, 0.0], r_pred, 120.0, &env, Some([0.0, v, 0.0]), 1.0).unwrap());
        let off = [r_pred[0], r_pred[1] + 10_000.0, r_pred[2]];
        assert!(!kinematically_reachable([radius, 0.0, 0.0], off, 120.0, &env, Some([0.0, v, 0.0]), 0.0).unwrap());
    }

    #[test]
    fn location_by_triangulation() {
        let obs = vec![
            json!({"observerPosition": [0.0, 0.0, 0.0], "measuredRangeM": 100.0}),
            json!({"observerPosition": [200.0, 0.0, 0.0], "measuredRangeM": 100.0}),
            json!({"observerPosition": [0.0, 200.0, 0.0], "measuredRangeM": 100.0}),
        ];
        assert_eq!(count_consistent(&obs, [100.0, 0.0, 0.0], 2.0), 2);
        assert!(location_confirmed(&obs, [100.0, 0.0, 0.0], 2.0, 2));
        assert!(!location_confirmed(&obs, [100.0, 0.0, 0.0], 2.0, 3));
    }

    #[test]
    fn beam_presence_roundtrip() {
        let (pk, did) = identity(&[13u8; 32]);
        let bw = 10.0_f64.to_radians();
        let att = build_beam_presence(&[13u8; 32], &did, "did:web:peer", "n", [1.0, 0.0, 0.0], bw, "2026-07-19T12:00:00Z").unwrap();
        assert!(verify_beam_presence(&att, &pk, [1.0, 0.02, 0.0], Some("n")).unwrap().is_some());
        assert!(verify_beam_presence(&att, &pk, [0.0, 1.0, 0.0], None).unwrap().is_none());
    }

    #[test]
    fn dead_man_revocation_fires() {
        let (pk, did) = identity(&[15u8; 32]);
        let cr = build_conditional_revocation(&[15u8; 32], &did, "cred-1", "did:web:node", 100, "2026-07-19T12:00:00Z").unwrap();
        let sub = verify_conditional_revocation(&cr, &pk).unwrap().unwrap();
        assert!(!conditional_revocation_active(&sub, 100, None).unwrap());
        assert!(conditional_revocation_active(&sub, 101, None).unwrap());
        assert!(!conditional_revocation_active(&sub, 101, Some(100)).unwrap());
    }

    #[test]
    fn range_observation_roundtrip() {
        let (pk, did) = identity(&[17u8; 32]);
        let o = build_range_observation(&[17u8; 32], &did, "did:web:t", [1.0, 2.0, 3.0], 10.0, "n", 1, "2026-07-19T12:00:00Z").unwrap();
        assert!(verify_range_observation(&o, &pk).unwrap().is_some());
    }

    #[test]
    fn accumulator_non_revocation() {
        let mut smt = SparseMerkleTree::new();
        smt.revoke("cred-x");
        smt.revoke("cred-y");
        let root = smt.root();
        assert!(verify_non_revocation_proof("cred-z", &smt.non_revocation_proof("cred-z"), &root));
        // a revoked credential's proof must NOT verify
        assert!(!verify_non_revocation_proof("cred-x", &smt.non_revocation_proof("cred-x"), &root));
        // incremental update changes the root
        let mut smt2 = SparseMerkleTree::new();
        smt2.revoke("a");
        let r1 = smt2.root();
        smt2.revoke("z");
        assert_ne!(smt2.root(), r1);
        smt2.unrevoke("z");
        assert!(verify_non_revocation_proof("z", &smt2.non_revocation_proof("z"), &smt2.root()));
    }

    #[test]
    fn signed_accumulator_root_end_to_end() {
        let (pk, did) = identity(&[19u8; 32]);
        let mut smt = SparseMerkleTree::new();
        smt.revoke("compromised");
        let signed = build_revocation_accumulator_root(&[19u8; 32], &did, &smt, 42, "2026-07-19T12:00:00Z").unwrap();
        let proof = smt.non_revocation_proof("good");
        assert!(verify_non_revocation("good", &proof, &signed, &pk).unwrap());
        let bad = smt.non_revocation_proof("compromised");
        assert!(!verify_non_revocation("compromised", &bad, &signed, &pk).unwrap());
    }

    #[test]
    fn quarantine_and_quorum() {
        let (pk, did) = identity(&[21u8; 32]);
        let d = build_distress_attestation(&[21u8; 32], &did, "did:web:bad", "out_of_envelope", "frame:abc", 5, "2026-07-19T12:00:00Z").unwrap();
        assert!(verify_distress_attestation(&d, &pk).unwrap().is_some());
        let members: HashSet<String> = ["did:web:m0", "did:web:m1", "did:web:m2", "did:web:m3"].iter().map(|s| s.to_string()).collect();
        let mut subs = vec![
            json!({"id": "did:web:bad", "observer": "did:web:m0", "epoch": 5}),
            json!({"id": "did:web:bad", "observer": "did:web:m1", "epoch": 5}),
            json!({"id": "did:web:bad", "observer": "did:web:m1", "epoch": 6}),
            json!({"id": "did:web:bad", "observer": "did:web:outsider", "epoch": 5}),
        ];
        assert!(!is_quarantined(&subs, "did:web:bad", 3, &members, None));
        subs.push(json!({"id": "did:web:bad", "observer": "did:web:m2", "epoch": 5}));
        assert!(is_quarantined(&subs, "did:web:bad", 3, &members, None));
        // quorum-of-orbits: distinct failure domains + no rollback
        let change = json!({"op": "revoke", "did": "did:web:x"});
        let mut ups = vec![
            json!({"scope": "rev", "change": change, "epoch": 10, "failureDomain": "orbit-A"}),
            json!({"scope": "rev", "change": change, "epoch": 10, "failureDomain": "orbit-A"}),
        ];
        assert!(!accept_trust_state_update(&ups, 9, 2));
        ups.push(json!({"scope": "rev", "change": change, "epoch": 10, "failureDomain": "orbit-B"}));
        assert!(accept_trust_state_update(&ups, 9, 2));
        assert!(!accept_trust_state_update(&ups, 11, 2)); // rollback
    }

    #[test]
    fn key_continuity_threshold() {
        let (pk, did) = identity(&[23u8; 32]);
        let members: Vec<String> = (0..3).map(|i| format!("did:web:m{i}")).collect();
        let pre = build_key_continuity_predelegation(&[23u8; 32], &did, "mission-1", &members, 2, "2026-07-19T12:00:00Z").unwrap();
        let pre_sub = verify_typed(&pre, &pk, KEY_CONTINUITY_PREDELEGATION_TYPE).unwrap().unwrap();
        let approvals = vec![
            json!({"id": "reissue-1", "member": "did:web:m0", "supersedes": "mission-1", "epoch": 20}),
            json!({"id": "reissue-1", "member": "did:web:m1", "supersedes": "mission-1", "epoch": 20}),
        ];
        assert!(verify_key_continuity(&pre_sub, "reissue-1", "mission-1", &approvals));
        assert!(!verify_key_continuity(&pre_sub, "reissue-1", "mission-1", &approvals[..1]));
    }

    #[test]
    fn edge_trust_gates() {
        let (pk, did) = identity(&[25u8; 32]);
        let good = build_time_quality_attestation(&[25u8; 32], &did, "gnss", 5.0, 0.5, "2026-07-19T12:00:00Z").unwrap();
        let sub = verify_time_quality_attestation(&good, &pk).unwrap().unwrap();
        assert!(time_quality_permits(&sub, CONSEQUENCE_CRITICAL, None));
        let poor = build_time_quality_attestation(&[25u8; 32], &did, "rc", 1e6, 120.0, "2026-07-19T12:00:00Z").unwrap();
        let psub = verify_time_quality_attestation(&poor, &pk).unwrap().unwrap();
        assert!(!time_quality_permits(&psub, CONSEQUENCE_CRITICAL, None));
        assert!(time_quality_permits(&psub, CONSEQUENCE_ROUTINE, None));
        // integrity levels
        assert_eq!(integrity_authority_level(0.1, 0.3, 0.7), INTEGRITY_FULL);
        assert_eq!(integrity_authority_level(0.4, 0.3, 0.7), INTEGRITY_NARROWED);
        assert_eq!(integrity_authority_level(0.8, 0.3, 0.7), INTEGRITY_SUSPECT);
    }

    #[test]
    fn autonomy_envelope_narrows() {
        let (pk, did) = identity(&[27u8; 32]);
        let steps = json!([
            {"maxStalenessEpochs": 10, "physicalScope": {"maxSpeedMps": 2.0, "allowedZones": ["a", "b"]}},
            {"maxStalenessEpochs": 100, "physicalScope": {"maxSpeedMps": 0.5, "allowedZones": ["a"]}}
        ]);
        let sched = build_autonomy_schedule(&[27u8; 32], &did, "did:web:node", &steps, "2026-07-19T12:00:00Z").unwrap();
        let sub = verify_autonomy_schedule(&sched, &pk).unwrap().unwrap();
        assert_eq!(select_envelope(&sub, 5).unwrap().get("maxSpeedMps").unwrap().as_f64(), Some(2.0));
        assert_eq!(select_envelope(&sub, 50).unwrap().get("maxSpeedMps").unwrap().as_f64(), Some(0.5));
        let action = PhysicalAction { force_n: None, speed_mps: Some(1.5), near_humans: false, zone: Some("b".into()), time_hm: None };
        assert!(autonomy_permits(&sub, 5, &action));
        assert!(!autonomy_permits(&sub, 50, &action));
        // widening schedule rejected
        let bad = json!([
            {"maxStalenessEpochs": 10, "physicalScope": {"maxSpeedMps": 0.5}},
            {"maxStalenessEpochs": 100, "physicalScope": {"maxSpeedMps": 2.0}}
        ]);
        assert!(build_autonomy_schedule(&[27u8; 32], &did, "did:web:node", &bad, "2026-07-19T12:00:00Z").is_err());
    }

    #[test]
    fn perception_and_mesh() {
        let subs = vec![
            json!({"id": "did:web:a", "value": 10.0}),
            json!({"id": "did:web:b", "value": 10.2}),
            json!({"id": "did:web:c", "value": 9.9}),
            json!({"id": "did:web:liar", "value": 50.0}),
        ];
        let (corr, flagged) = cross_check_perception(&subs, 1.0, 2);
        assert!(flagged.contains(&"did:web:liar".to_string()));
        assert_eq!(corr, vec!["did:web:a", "did:web:b", "did:web:c"]);
        // node standing
        let att = vec![
            json!({"id": "did:web:n", "attestor": "did:web:p1", "outcome": "ok", "epoch": 100}),
            json!({"id": "did:web:n", "attestor": "did:web:p2", "outcome": "ok", "epoch": 90}),
            json!({"id": "did:web:n", "attestor": "did:web:p1", "outcome": "ok", "epoch": 80}),
        ];
        let st = node_standing(&att, "did:web:n", 100, 10.0, &["ok", "success", "authenticated"]);
        assert!((st - 1.5).abs() < 1e-9);
    }

    #[test]
    fn bundle_trust_and_custody() {
        let (pk, did) = identity(&[29u8; 32]);
        let bc = bind_credential_to_bundle(&[29u8; 32], &did, "b-1", "sha256:abc", &json!({"action": "deliver"}), "2026-07-19T12:00:00Z").unwrap();
        assert!(verify_bundle_trust(&bc, &pk, "sha256:abc").unwrap().is_some());
        assert!(verify_bundle_trust(&bc, &pk, "sha256:TAMPER").unwrap().is_none());
        let transfers = vec![
            json!({"id": "b-1", "custodian": "did:web:relay1", "previousCustodian": did, "epoch": 1}),
            json!({"id": "b-1", "custodian": "did:web:relay2", "previousCustodian": "did:web:relay1", "epoch": 2}),
        ];
        assert!(custody_chain_ok(&transfers, "b-1", &did));
        let broken = vec![
            transfers[0].clone(),
            json!({"id": "b-1", "custodian": "did:web:relay2", "previousCustodian": "did:web:GHOST", "epoch": 2}),
        ];
        assert!(!custody_chain_ok(&broken, "b-1", &did));
    }
}
