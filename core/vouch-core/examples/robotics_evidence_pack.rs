//! Regulatory evidence pack for a robot, assembled from Vouch robotics
//! credentials (Rust). Mirrors examples/robotics_ai_act_evidence_pack.py.
//!
//! A robot presents signed credentials -- a hardware-rooted identity, a model
//! provenance attestation, a physical capability scope, a safety record
//! anchored to a tamper-evident ledger, a heartbeat carrying a motion digest,
//! and perception provenance for its sensor frames -- and the conformance
//! checker maps them onto all five built-in regulatory profiles (EU AI Act
//! high-risk, ISO 10218, ISO/TS 15066, EU Machinery Regulation 2023/1230,
//! UL 3300). An assessor then signs one point-in-time conformance attestation
//! per profile that an auditor or notified body can verify offline.
//!
//! Run it:  cargo run --example robotics_evidence_pack   (from core/vouch-core)

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use vouch_core::keys::Ed25519KeyPair;
use vouch_core::robotics::{
    build_conformance_attestation, build_perception_attestation, build_physical_scope_credential,
    build_provenance_attestation, build_robot_heartbeat, build_safety_record, check_conformance,
    hash_frame, mint_robot_identity, robot_identity_binding, verify_conformance_attestation,
    BuildConformanceAttestation, BuildPerception, BuildPhysicalScope, BuildProvenance,
    BuildRobotHeartbeat, BuildSafetyRecord, MintRobotIdentity, MotionCollector, MotionSample,
    PerceptionLog, SafetyEventLog,
};

/// The five built-in conformance profiles. The Rust core keeps the profile
/// registry private, so the ids are listed here.
const ALL_PROFILE_IDS: [&str; 5] = [
    "eu-ai-act-high-risk",
    "iso-10218",
    "iso-ts-15066",
    "eu-machinery-2023-1230",
    "ul-3300",
];

const NOW: &str = "2026-01-01T00:00:00Z";
const ROBOT_DID: &str = "did:web:ar7.example.com";
const ASSESSOR_DID: &str = "did:web:assessor.example.com";
const ROBOT_SEED: [u8; 32] = [3u8; 32];
const ROOT_SEED: [u8; 32] = [7u8; 32];
const ASSESSOR_SEED: [u8; 32] = [11u8; 32];

/// Multibase (base64url) SHA-256, the hash form Vouch credentials carry.
fn digest(data: &[u8]) -> String {
    format!("u{}", URL_SAFE_NO_PAD.encode(Sha256::digest(data)))
}

fn robot_config() -> Value {
    json!({"temperature": 0.0, "max_torque": 12.5})
}

/// Build the four base credentials: identity, model provenance, physical
/// scope, and a safety record over a tamper-evident ledger. These satisfy
/// eu-ai-act-high-risk, iso-10218, and eu-machinery-2023-1230, but leave gaps
/// in iso-ts-15066 (no motion monitoring) and ul-3300 (no perception
/// integrity).
fn build_base_credentials() -> Vec<Value> {
    let robot_kp = Ed25519KeyPair::from_seed(&ROBOT_SEED);
    let root_kp = Ed25519KeyPair::from_seed(&ROOT_SEED);

    // The (software) hardware root signs a binding over the robot DID and key.
    let binding = robot_identity_binding(ROBOT_DID, &robot_kp.public_multikey());
    let identity = mint_robot_identity(
        &ROBOT_SEED,
        &MintRobotIdentity {
            robot_did: ROBOT_DID.into(),
            make: "Acme Robotics".into(),
            model: "AR-7".into(),
            serial: "SN-000123".into(),
            owner: None,
            root_kind: "TPM".into(), // reference; use a real TPM in deployment
            root_public_multibase: root_kp.public_multikey(),
            attestation: root_kp.sign(&binding).to_vec(),
            lifecycle: None,
            valid_from: NOW.into(),
            valid_until: None,
        },
    )
    .expect("mint identity");

    let provenance = build_provenance_attestation(
        &ROBOT_SEED,
        &BuildProvenance {
            issuer_did: ROBOT_DID.into(),
            robot_did: ROBOT_DID.into(),
            model_name: "Gemini Robotics ER 2".into(),
            weights_hash: digest(b"gemini-robotics-er-2-weights"),
            safety_policy: digest(b"factory-floor-safety-policy-v3"),
            config: Some(robot_config()),
            version: Some("2.0".into()),
            supersedes: None,
            valid_from: NOW.into(),
            valid_until: None,
        },
    )
    .expect("build provenance");

    let scope = build_physical_scope_credential(
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

    let mut ledger = SafetyEventLog::new(None);
    ledger
        .append(
            "near_miss",
            "low",
            Some(&json!({"note": "pallet edge proximity"})),
            None,
            "2026-01-01T00:00:01Z",
        )
        .expect("append near_miss");
    ledger
        .append(
            "manual_override",
            "info",
            None,
            Some("did:web:operator.example.com"),
            "2026-01-01T00:00:02Z",
        )
        .expect("append manual_override");
    let record = build_safety_record(
        &ASSESSOR_SEED,
        &BuildSafetyRecord {
            issuer_did: ASSESSOR_DID.into(),
            robot_did: ROBOT_DID.into(),
            summary: ledger.summarize(),
            period_start: None,
            period_end: None,
            valid_from: NOW.into(),
            valid_until: None,
        },
    )
    .expect("build safety record");

    vec![identity, provenance, scope, record]
}

/// Build the two credentials that close the remaining gaps: a heartbeat whose
/// motion digest proves the last interval stayed inside the physical envelope
/// (ISO/TS 15066 continuous monitoring), and perception provenance binding a
/// captured camera frame to the robot's key (UL 3300 sensing integrity).
fn build_monitoring_credentials(scope_credential: &Value) -> Vec<Value> {
    let scope = scope_credential["credentialSubject"]["physicalScope"].clone();

    let mut collector = MotionCollector::new(Some(scope));
    collector
        .record(&MotionSample {
            force_n: Some(12.0),
            speed_mps: Some(0.4),
            near_humans: true,
            zone: Some("cell-3".into()),
            ..Default::default()
        })
        .expect("record sample");
    collector
        .record(&MotionSample {
            force_n: Some(25.0),
            speed_mps: Some(1.1),
            zone: Some("cell-3".into()),
            ..Default::default()
        })
        .expect("record sample");
    let heartbeat = build_robot_heartbeat(
        &ROBOT_SEED,
        &BuildRobotHeartbeat {
            robot_did: ROBOT_DID.into(),
            session_id: "shift-A".into(),
            interval_index: 0,
            interval_seconds: 30,
            motion_digest: collector.digest(),
            valid_from: NOW.into(),
        },
    )
    .expect("build heartbeat");

    let frame: &[u8] = b"\x89frame-bytes-from-the-front-camera";
    let mut log = PerceptionLog::new(None);
    log.record(
        "cam-front",
        "camera",
        Some(frame),
        None,
        "2026-01-01T00:00:03Z",
    )
    .expect("record frame");
    let perception = build_perception_attestation(
        &ROBOT_SEED,
        &BuildPerception {
            robot_did: ROBOT_DID.into(),
            sensor_id: "cam-front".into(),
            modality: "camera".into(),
            frame_hash: hash_frame(frame),
            captured_at: None,
            log_head: Some(log.head().to_string()),
            valid_from: NOW.into(),
            valid_until: None,
        },
    )
    .expect("build perception");

    vec![heartbeat, perception]
}

/// Render the report's clause-citation provenance, worst first.
///
/// CONFORMS answers "does the evidence cover the clauses this profile maps?",
/// which is a different and weaker claim than "does the robot comply with the
/// regulation". Printing the provenance beside the verdict keeps the two apart:
/// a profile whose clause numbers came from secondary sources, or which only
/// names topics, says so on the same line as the result.
fn citation_summary(report: &Value) -> String {
    ["descriptive", "unverified-secondary", "verified-primary"]
        .iter()
        .filter_map(|status| match report["citations"][status].as_i64() {
            Some(n) if n > 0 => Some(format!("{n} {status}")),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn print_summary(reports: &[(String, Value)]) {
    for (pid, report) in reports {
        let verdict = if report["conforms"].as_bool().unwrap_or(false) {
            "CONFORMS"
        } else {
            "GAPS"
        };
        println!(
            "  {:<24} {:<8} ({}/{})  {}",
            pid,
            verdict,
            report["satisfiedCount"],
            report["totalCount"],
            report["regime"].as_str().unwrap_or("")
        );
        println!("    citations: {}", citation_summary(report));
        for req in report["requirements"].as_array().into_iter().flatten() {
            if !req["satisfied"].as_bool().unwrap_or(false) {
                println!(
                    "    gap: {}: {}",
                    req["clause"].as_str().unwrap_or(""),
                    req["title"].as_str().unwrap_or("")
                );
            }
        }
    }
}

fn check_all_profiles(credentials: &[Value]) -> Vec<(String, Value)> {
    ALL_PROFILE_IDS
        .iter()
        .map(|pid| {
            let report = check_conformance(credentials, pid).expect("check conformance");
            (pid.to_string(), report)
        })
        .collect()
}

fn main() {
    let assessor_kp = Ed25519KeyPair::from_seed(&ASSESSOR_SEED);

    // The base credential set leaves gaps in two of the five profiles.
    let base = build_base_credentials();
    println!("base credential set (identity, provenance, scope, safety record):");
    print_summary(&check_all_profiles(&base));

    // The heartbeat and perception credentials close them.
    let mut credentials = base.clone();
    credentials.extend(build_monitoring_credentials(&base[2]));
    println!("\nfull evidence pack ({} credentials):", credentials.len());
    let reports = check_all_profiles(&credentials);
    print_summary(&reports);

    // One signed, offline-verifiable conformance attestation per profile.
    println!(
        "\nsigned attestations ({} profiles):",
        ALL_PROFILE_IDS.len()
    );
    for (pid, report) in &reports {
        let attestation = build_conformance_attestation(
            &ASSESSOR_SEED,
            &BuildConformanceAttestation {
                issuer_did: ASSESSOR_DID.into(),
                robot_did: ROBOT_DID.into(),
                report: report.clone(),
                valid_from: NOW.into(),
                valid_until: None,
            },
        )
        .expect("build attestation");
        let subject = verify_conformance_attestation(&attestation, &assessor_kp.public_key())
            .expect("verify attestation");
        let report_digest = subject
            .as_ref()
            .and_then(|s| s["reportDigest"].as_str())
            .unwrap_or("");
        println!(
            "  {:<24} verifies={}  reportDigest={}...",
            pid,
            subject.is_some(),
            &report_digest[..16.min(report_digest.len())]
        );
    }
}
