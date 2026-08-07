//! VLA accountability loop: provenance on load, a pre-actuation scope gate,
//! and a tamper-evident black box (Rust). Mirrors
//! examples/robotics_vla_accountability_loop.py.
//!
//! A robot driven by a vision-language-action model (here Gemini Robotics ER 2)
//! composes three Vouch robotics primitives into one accountable control loop:
//!
//!   1. Provenance on load: before autonomy is enabled, the robot verifies the
//!      signed ModelProvenanceAttestation for the exact weights and config it
//!      is about to run.
//!   2. Pre-actuation scope gate: every action the planner proposes is checked
//!      against the robot's signed PhysicalCapabilityScope before actuating;
//!      an over-speed or out-of-zone action is denied, not attempted.
//!   3. Tamper-evident black box: every decision, allowed or denied, is
//!      appended to an encrypted, hash-linked black-box log. Anyone can verify
//!      the chain; only a holder of the key can read the payloads.
//!
//! Run it:  cargo run --example robotics_vla_accountability_loop   (from core/vouch-core)

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use vouch_core::keys::Ed25519KeyPair;
use vouch_core::robotics::{
    build_physical_scope_credential, build_provenance_attestation, check_physical_action,
    verify_blackbox_chain, verify_provenance_attestation, BlackBoxLog, BuildPhysicalScope,
    BuildProvenance, PhysicalAction,
};

const VLA_MODEL_NAME: &str = "Gemini Robotics ER 2";
const NOW: &str = "2026-01-01T00:00:00Z";
const ROBOT_DID: &str = "did:web:ar7.example.com";
const ROBOT_SEED: [u8; 32] = [3u8; 32];
const BLACKBOX_KEY: [u8; 32] = [9u8; 32];

/// Multibase (base64url) SHA-256, the hash form Vouch credentials carry.
fn digest(data: &[u8]) -> String {
    format!("u{}", URL_SAFE_NO_PAD.encode(Sha256::digest(data)))
}

fn vla_config() -> Value {
    json!({"planner": "er-2", "temperature": 0.0, "max_plan_steps": 8})
}

/// What the planner proposes during one task episode. The first two stay
/// inside the envelope; the sprint exceeds the near-human speed cap and the
/// loading-bay fetch leaves the allowed zone, so the gate must deny both.
fn planned_actions() -> Vec<(&'static str, PhysicalAction)> {
    vec![
        (
            "pick up the cup",
            PhysicalAction {
                force_n: Some(20.0),
                speed_mps: Some(0.3),
                near_humans: true,
                zone: Some("cell-3".into()),
                ..Default::default()
            },
        ),
        (
            "hand cup to operator",
            PhysicalAction {
                force_n: Some(10.0),
                speed_mps: Some(0.2),
                near_humans: true,
                zone: Some("cell-3".into()),
                ..Default::default()
            },
        ),
        (
            "sprint to the dock",
            PhysicalAction {
                speed_mps: Some(2.5),
                near_humans: true,
                zone: Some("cell-3".into()),
                ..Default::default()
            },
        ),
        (
            "fetch from loading bay",
            PhysicalAction {
                force_n: Some(15.0),
                speed_mps: Some(0.5),
                zone: Some("loading-bay".into()),
                ..Default::default()
            },
        ),
    ]
}

fn main() {
    let robot_kp = Ed25519KeyPair::from_seed(&ROBOT_SEED);

    // 1. provenance on load: no verified provenance, no autonomy.
    let attestation = build_provenance_attestation(
        &ROBOT_SEED,
        &BuildProvenance {
            issuer_did: ROBOT_DID.into(),
            robot_did: ROBOT_DID.into(),
            model_name: VLA_MODEL_NAME.into(),
            weights_hash: digest(b"gemini-robotics-er-2-weights"),
            safety_policy: digest(b"factory-floor-safety-policy-v3"),
            config: Some(vla_config()),
            version: Some("2.0".into()),
            supersedes: None,
            valid_from: NOW.into(),
            valid_until: None,
        },
    )
    .expect("build provenance");
    let subject =
        verify_provenance_attestation(&attestation, &robot_kp.public_key(), Some(&vla_config()))
            .expect("verify provenance");
    let ok = subject.is_some();
    let model = subject
        .as_ref()
        .and_then(|s| s["vla"]["modelName"].as_str())
        .unwrap_or("");
    println!("provenance verifies: {ok}  model={model}");
    assert!(
        ok,
        "refusing to enable autonomy without verified provenance"
    );

    // 2. pre-actuation scope gate, with every decision black-boxed.
    let scope_cred = build_physical_scope_credential(
        &ROBOT_SEED,
        &BuildPhysicalScope {
            issuer_did: ROBOT_DID.into(),
            subject_did: ROBOT_DID.into(),
            max_force_n: Some(80.0),
            max_speed_mps: Some(1.5),
            max_speed_near_humans_mps: Some(0.5),
            allowed_zones: Some(vec!["cell-3".into()]),
            valid_from: NOW.into(),
            ..Default::default()
        },
    )
    .expect("build scope");
    let scope = scope_cred["credentialSubject"]["physicalScope"].clone();

    let mut blackbox = BlackBoxLog::new(&BLACKBOX_KEY, None).expect("black box");
    for (i, (task, action)) in planned_actions().iter().enumerate() {
        let result = check_physical_action(&scope, action);
        let event = if result.ok {
            "actuation_allowed"
        } else {
            "actuation_denied"
        };
        blackbox
            .append(
                event,
                &json!({
                    "task": task,
                    "zone": action.zone,
                    "speedMps": action.speed_mps,
                    "nearHumans": action.near_humans,
                    "reasons": result.reasons,
                }),
                &format!("2026-01-01T00:00:{:02}Z", i + 1),
            )
            .expect("append decision");
        let verdict = if result.ok { "ALLOW" } else { "DENY " };
        let why = if result.reasons.is_empty() {
            String::new()
        } else {
            format!("  ({})", result.reasons.join("; "))
        };
        println!("  [{verdict}] {task}{why}");
    }

    // 3. the black box is tamper-evident without the key.
    let entries: Vec<Value> = entries_of(&blackbox);
    let chain = verify_blackbox_chain(&entries, None);
    println!(
        "black-box chain verifies: {}  entries={}",
        chain.ok,
        entries.len()
    );

    // Rewriting history (the denied sprint becomes "allowed") breaks the chain.
    let mut tampered = entries.clone();
    tampered[2]["event"] = json!("actuation_allowed");
    let detected = verify_blackbox_chain(&tampered, None);
    println!(
        "tampered chain detected: {}  ({})",
        !detected.ok,
        detected.reason.unwrap_or_default()
    );
}

fn entries_of(log: &BlackBoxLog) -> Vec<Value> {
    log.entries().to_vec()
}
