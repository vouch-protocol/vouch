package robotics

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// These tests mirror the runnable example commands under
// examples/robotics-evidence-pack and examples/robotics-vla-accountability-loop
// (and the Python tests/test_examples_robotics.py): the full evidence pack
// conforms to all five built-in profiles, each signed attestation verifies,
// the VLA gate allows the safe actions and denies the over-speed and
// out-of-zone ones, and the black-box chain verifies and detects tampering.

var exampleProfileIDs = []string{
	"eu-ai-act-high-risk",
	"iso-10218",
	"iso-ts-15066",
	"eu-machinery-2023-1230",
	"ul-3300",
}

func exampleDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "u" + base64.RawURLEncoding.EncodeToString(sum[:])
}

// exampleEvidencePack builds the six-credential evidence pack the example
// command assembles: identity, provenance, scope, safety record, heartbeat,
// and perception provenance.
func exampleEvidencePack(t *testing.T, robot, authority *signer.Signer, robotDID string) []map[string]any {
	t.Helper()

	rootSeed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(rootSeed); err != nil {
		t.Fatal(err)
	}
	root, err := NewSoftwareRoot(rootSeed, "TPM")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := MintRobotIdentity(robot, root, MintOptions{
		Make: "Acme Robotics", Model: "AR-7", Serial: "SN-000123",
	})
	if err != nil {
		t.Fatal(err)
	}

	prov, err := BuildProvenanceAttestation(robot, BuildProvenanceOptions{
		RobotDID:     robotDID,
		ModelName:    "Gemini Robotics ER 2",
		WeightsHash:  exampleDigest([]byte("gemini-robotics-er-2-weights")),
		SafetyPolicy: exampleDigest([]byte("factory-floor-safety-policy-v3")),
		Config:       map[string]any{"temperature": 0.0, "max_torque": 12.5},
		Version:      "2.0",
	})
	if err != nil {
		t.Fatal(err)
	}

	scope, err := BuildPhysicalScopeCredential(robot, BuildPhysicalScopeOptions{
		SubjectDID:            robotDID,
		MaxForceN:             fptr(80.0),
		MaxSpeedMps:           fptr(1.5),
		MaxSpeedNearHumansMps: fptr(0.5),
		AllowedZones:          []string{"cell-3"},
	})
	if err != nil {
		t.Fatal(err)
	}

	ledger := NewSafetyEventLog("")
	if _, err := ledger.Append("near_miss", AppendSafetyOptions{Severity: "low"}); err != nil {
		t.Fatal(err)
	}
	record, err := BuildSafetyRecord(authority, BuildSafetyRecordOptions{
		RobotDID: robotDID, Summary: ledger.Summarize(),
	})
	if err != nil {
		t.Fatal(err)
	}

	scopeObj := scope["credentialSubject"].(map[string]any)["physicalScope"].(map[string]any)
	collector := NewMotionCollector(scopeObj)
	if err := collector.Record(MotionRecord{
		ForceN: fptr(12.0), SpeedMps: fptr(0.4), NearHumans: true, Zone: "cell-3",
	}); err != nil {
		t.Fatal(err)
	}
	heartbeat, err := BuildRobotHeartbeat(robot, BuildHeartbeatOptions{
		SessionID: "shift-A", IntervalIndex: 0, MotionDigest: collector.Digest(), IntervalSeconds: 30,
	})
	if err != nil {
		t.Fatal(err)
	}

	frame := []byte("\x89frame-bytes-from-the-front-camera")
	plog := NewPerceptionLog("")
	if _, err := plog.Record(RecordOptions{SensorID: "cam-front", Modality: "camera", Frame: frame}); err != nil {
		t.Fatal(err)
	}
	perception, err := BuildPerceptionAttestation(robot, BuildPerceptionOptions{
		RobotDID: robotDID, SensorID: "cam-front", Modality: "camera",
		FrameHash: HashFrame(frame), LogHead: plog.Head(),
	})
	if err != nil {
		t.Fatal(err)
	}

	return []map[string]any{identity, prov, scope, record, heartbeat, perception}
}

func TestEvidencePackConformsToAllProfiles(t *testing.T) {
	robotDID := "did:web:ar7.example.com"
	robot := newRobot(t, robotDID)
	authority := newRobot(t, "did:web:assessor.example.com")
	creds := exampleEvidencePack(t, robot, authority, robotDID)

	for _, pid := range exampleProfileIDs {
		report, err := CheckConformance(creds, pid)
		if err != nil {
			t.Fatalf("CheckConformance(%s): %v", pid, err)
		}
		if !report["conforms"].(bool) {
			t.Errorf("profile %s does not conform: %v", pid, report)
		}
	}

	// Without the heartbeat and perception credentials, iso-ts-15066 and
	// ul-3300 must report gaps while eu-ai-act-high-risk still conforms.
	base := creds[:4]
	for pid, wantConforms := range map[string]bool{
		"iso-ts-15066": false, "ul-3300": false, "eu-ai-act-high-risk": true,
	} {
		report, err := CheckConformance(base, pid)
		if err != nil {
			t.Fatalf("CheckConformance(%s): %v", pid, err)
		}
		if report["conforms"].(bool) != wantConforms {
			t.Errorf("base set: profile %s conforms=%v, want %v", pid, report["conforms"], wantConforms)
		}
	}
}

func TestEvidencePackAttestationsVerify(t *testing.T) {
	robotDID := "did:web:ar7.example.com"
	robot := newRobot(t, robotDID)
	assessor := newRobot(t, "did:web:assessor.example.com")
	creds := exampleEvidencePack(t, robot, assessor, robotDID)

	for _, pid := range exampleProfileIDs {
		report, err := CheckConformance(creds, pid)
		if err != nil {
			t.Fatalf("CheckConformance(%s): %v", pid, err)
		}
		att, err := BuildConformanceAttestation(assessor, BuildConformanceAttestationOptions{
			RobotDID: robotDID, Report: report,
		})
		if err != nil {
			t.Fatalf("BuildConformanceAttestation(%s): %v", pid, err)
		}
		ok, subject := VerifyConformanceAttestation(att, assessor.PublicKeyEd25519())
		if !ok {
			t.Fatalf("attestation for %s does not verify", pid)
		}
		if subject["profileId"] != pid || subject["conforms"] != true {
			t.Errorf("attestation subject for %s wrong: %v", pid, subject)
		}
		if wrongOK, _ := VerifyConformanceAttestation(att, robot.PublicKeyEd25519()); wrongOK {
			t.Errorf("attestation for %s verified under the wrong key", pid)
		}
	}
}

func TestVlaLoopGateAndBlackbox(t *testing.T) {
	robotDID := "did:web:ar7.example.com"
	robot := newRobot(t, robotDID)

	scopeCred, err := BuildPhysicalScopeCredential(robot, BuildPhysicalScopeOptions{
		SubjectDID:            robotDID,
		MaxForceN:             fptr(80.0),
		MaxSpeedMps:           fptr(1.5),
		MaxSpeedNearHumansMps: fptr(0.5),
		AllowedZones:          []string{"cell-3"},
	})
	if err != nil {
		t.Fatal(err)
	}
	scope := scopeCred["credentialSubject"].(map[string]any)["physicalScope"].(map[string]any)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	blackbox, err := NewBlackBoxLog(key, "")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		task       string
		action     PhysicalAction
		wantOK     bool
		wantReason string
	}{
		{"pick up the cup", PhysicalAction{ForceN: fptr(20.0), SpeedMps: fptr(0.3), NearHumans: true, Zone: "cell-3"}, true, ""},
		{"hand cup to operator", PhysicalAction{ForceN: fptr(10.0), SpeedMps: fptr(0.2), NearHumans: true, Zone: "cell-3"}, true, ""},
		{"sprint to the dock", PhysicalAction{SpeedMps: fptr(2.5), NearHumans: true, Zone: "cell-3"}, false, "speed_exceeded"},
		{"fetch from loading bay", PhysicalAction{ForceN: fptr(15.0), SpeedMps: fptr(0.5), Zone: "loading-bay"}, false, "zone_not_allowed"},
	}
	for _, c := range cases {
		result := CheckPhysicalAction(scope, c.action)
		if result.OK != c.wantOK {
			t.Errorf("%s: ok=%v, want %v (reasons %v)", c.task, result.OK, c.wantOK, result.Reasons)
		}
		if c.wantReason != "" && !strings.Contains(strings.Join(result.Reasons, ";"), c.wantReason) {
			t.Errorf("%s: reasons %v missing %q", c.task, result.Reasons, c.wantReason)
		}
		event := "actuation_denied"
		if result.OK {
			event = "actuation_allowed"
		}
		if _, err := blackbox.Append(event, map[string]any{"task": c.task, "reasons": result.Reasons}, ""); err != nil {
			t.Fatal(err)
		}
	}

	entries := blackbox.Entries()
	if len(entries) != len(cases) {
		t.Fatalf("expected %d entries, got %d", len(cases), len(entries))
	}
	if chain := VerifyBlackboxChain(entries, ""); !chain.OK {
		t.Fatalf("chain does not verify: %s", chain.Reason)
	}

	tampered := make([]map[string]any, len(entries))
	for i, e := range entries {
		copied := make(map[string]any, len(e))
		for k, v := range e {
			copied[k] = v
		}
		tampered[i] = copied
	}
	tampered[2]["event"] = "actuation_allowed"
	if chain := VerifyBlackboxChain(tampered, ""); chain.OK {
		t.Fatal("tampered chain still verifies")
	} else if !strings.Contains(chain.Reason, "tampered") {
		t.Errorf("unexpected tamper reason: %s", chain.Reason)
	}
}
