//! Integration tests mirroring the runnable robotics examples
//! (examples/robotics_evidence_pack.rs and
//! examples/robotics_vla_accountability_loop.rs), and the Python
//! tests/test_examples_robotics.py: the full evidence pack conforms to all
//! five built-in profiles, each signed conformance attestation verifies, the
//! VLA gate allows the safe actions and denies the over-speed and out-of-zone
//! ones, and the black-box chain verifies and detects tampering.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use vouch_core::keys::Ed25519KeyPair;
use vouch_core::robotics::{
    build_conformance_attestation, build_perception_attestation, build_physical_scope_credential,
    build_provenance_attestation, build_robot_heartbeat, build_safety_record, check_conformance,
    check_physical_action, hash_frame, mint_robot_identity, robot_identity_binding,
    verify_blackbox_chain, verify_conformance_attestation, BlackBoxLog,
    BuildConformanceAttestation, BuildPerception, BuildPhysicalScope, BuildProvenance,
    BuildRobotHeartbeat, BuildSafetyRecord, MintRobotIdentity, MotionCollector, MotionSample,
    PerceptionLog, PhysicalAction, SafetyEventLog,
};

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

fn digest(data: &[u8]) -> String {
    format!("u{}", URL_SAFE_NO_PAD.encode(Sha256::digest(data)))
}

fn scope_credential() -> Value {
    build_physical_scope_credential(
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
    .expect("build scope")
}

/// The six-credential evidence pack the example assembles: identity,
/// provenance, scope, safety record, heartbeat, and perception provenance.
fn evidence_pack() -> Vec<Value> {
    let robot_kp = Ed25519KeyPair::from_seed(&ROBOT_SEED);
    let root_kp = Ed25519KeyPair::from_seed(&ROOT_SEED);

    let binding = robot_identity_binding(ROBOT_DID, &robot_kp.public_multikey());
    let identity = mint_robot_identity(
        &ROBOT_SEED,
        &MintRobotIdentity {
            robot_did: ROBOT_DID.into(),
            make: "Acme Robotics".into(),
            model: "AR-7".into(),
            serial: "SN-000123".into(),
            owner: None,
            root_kind: "TPM".into(),
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
            config: Some(json!({"temperature": 0.0, "max_torque": 12.5})),
            version: Some("2.0".into()),
            supersedes: None,
            valid_from: NOW.into(),
            valid_until: None,
        },
    )
    .expect("build provenance");

    let scope = scope_credential();

    let mut ledger = SafetyEventLog::new(None);
    ledger
        .append("near_miss", "low", None, None, "2026-01-01T00:00:01Z")
        .expect("append");
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

    let mut collector =
        MotionCollector::new(Some(scope["credentialSubject"]["physicalScope"].clone()));
    collector
        .record(&MotionSample {
            force_n: Some(12.0),
            speed_mps: Some(0.4),
            near_humans: true,
            zone: Some("cell-3".into()),
            ..Default::default()
        })
        .expect("record");
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

    vec![identity, provenance, scope, record, heartbeat, perception]
}

#[test]
fn evidence_pack_conforms_to_all_five_profiles() {
    let credentials = evidence_pack();
    for pid in ALL_PROFILE_IDS {
        let report = check_conformance(&credentials, pid).expect("check conformance");
        assert_eq!(
            report["conforms"],
            json!(true),
            "profile {pid} does not conform: {report}"
        );
        assert_eq!(report["satisfiedCount"], report["totalCount"]);
    }
}

#[test]
fn base_credentials_leave_the_expected_gaps() {
    let credentials = evidence_pack();
    let base = &credentials[..4];
    for (pid, want) in [
        ("iso-ts-15066", false),
        ("ul-3300", false),
        ("eu-ai-act-high-risk", true),
    ] {
        let report = check_conformance(base, pid).expect("check conformance");
        assert_eq!(report["conforms"], json!(want), "profile {pid}");
    }
}

#[test]
fn every_signed_attestation_verifies() {
    let credentials = evidence_pack();
    let assessor_kp = Ed25519KeyPair::from_seed(&ASSESSOR_SEED);
    let robot_kp = Ed25519KeyPair::from_seed(&ROBOT_SEED);

    for pid in ALL_PROFILE_IDS {
        let report = check_conformance(&credentials, pid).expect("check conformance");
        let attestation = build_conformance_attestation(
            &ASSESSOR_SEED,
            &BuildConformanceAttestation {
                issuer_did: ASSESSOR_DID.into(),
                robot_did: ROBOT_DID.into(),
                report,
                valid_from: NOW.into(),
                valid_until: None,
            },
        )
        .expect("build attestation");

        let subject = verify_conformance_attestation(&attestation, &assessor_kp.public_key())
            .expect("verify attestation")
            .unwrap_or_else(|| panic!("attestation for {pid} does not verify"));
        assert_eq!(subject["profileId"], json!(pid));
        assert_eq!(subject["conforms"], json!(true));

        let wrong = verify_conformance_attestation(&attestation, &robot_kp.public_key())
            .expect("verify under wrong key");
        assert!(
            wrong.is_none(),
            "attestation for {pid} verified under the wrong key"
        );
    }
}

#[test]
fn vla_gate_allows_safe_and_denies_unsafe_actions() {
    let scope = scope_credential()["credentialSubject"]["physicalScope"].clone();

    let cases: Vec<(&str, PhysicalAction, bool, &str)> = vec![
        (
            "pick up the cup",
            PhysicalAction {
                force_n: Some(20.0),
                speed_mps: Some(0.3),
                near_humans: true,
                zone: Some("cell-3".into()),
                ..Default::default()
            },
            true,
            "",
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
            true,
            "",
        ),
        (
            "sprint to the dock",
            PhysicalAction {
                speed_mps: Some(2.5),
                near_humans: true,
                zone: Some("cell-3".into()),
                ..Default::default()
            },
            false,
            "speed_exceeded",
        ),
        (
            "fetch from loading bay",
            PhysicalAction {
                force_n: Some(15.0),
                speed_mps: Some(0.5),
                zone: Some("loading-bay".into()),
                ..Default::default()
            },
            false,
            "zone_not_allowed",
        ),
    ];

    let mut blackbox = BlackBoxLog::new(&[9u8; 32], None).expect("black box");
    for (i, (task, action, want_ok, want_reason)) in cases.iter().enumerate() {
        let result = check_physical_action(&scope, action);
        assert_eq!(result.ok, *want_ok, "{task}: reasons {:?}", result.reasons);
        if !want_reason.is_empty() {
            assert!(
                result.reasons.iter().any(|r| r.contains(want_reason)),
                "{task}: reasons {:?} missing {want_reason}",
                result.reasons
            );
        }
        blackbox
            .append(
                if result.ok {
                    "actuation_allowed"
                } else {
                    "actuation_denied"
                },
                &json!({"task": task, "reasons": result.reasons}),
                &format!("2026-01-01T00:00:{:02}Z", i + 1),
            )
            .expect("append decision");
    }

    let entries: Vec<Value> = blackbox.entries().to_vec();
    assert_eq!(entries.len(), cases.len());
    let chain = verify_blackbox_chain(&entries, None);
    assert!(chain.ok, "chain does not verify: {:?}", chain.reason);

    let mut tampered = entries.clone();
    tampered[2]["event"] = json!("actuation_allowed");
    let detected = verify_blackbox_chain(&tampered, None);
    assert!(!detected.ok, "tampered chain still verifies");
    assert!(detected.reason.unwrap_or_default().contains("tampered"));
}
