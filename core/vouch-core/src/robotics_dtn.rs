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

use crate::data_integrity::{self, BuildProofOptions};
use crate::error::{CoreError, Result};
use crate::robotics::has_type;
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
}
