package robotics

import "testing"

// vectorConfigHash is the configHash the Python module pinned in the shared
// interop vector for the config {temperature, max_torque, guardrails}.
const vectorConfigHash = "uMh9_H2Lk51-m9SpBhiEa1oqIwwwA7yT27e2QFS0YKUs"

// TestConfigHashInteropVector is the cross-language interop proof for Phase 5.2:
// Go must reproduce the exact configHash that Python pinned in the shared vector
// from the same config object. This exercises JCS canonicalization of floats
// (0.0, 12.5) and arrays across languages.
func TestConfigHashInteropVector(t *testing.T) {
	v := loadVector(t)
	config := v["config"].(map[string]any)
	got, err := ConfigHash(config)
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := v["expected_config_hash"].(string); got != want {
		t.Fatalf("config hash mismatch: got %s want %s", got, want)
	}
	if got != vectorConfigHash {
		t.Fatalf("config hash %s does not match the pinned constant", got)
	}
}

func TestProvenanceRoundTrip(t *testing.T) {
	s := newRobot(t, "did:web:robot.example.com")
	config := loadVector(t)["config"].(map[string]any)
	att, err := BuildProvenanceAttestation(s, BuildProvenanceOptions{
		RobotDID:     "did:web:robot.example.com",
		ModelName:    "openvla-7b",
		WeightsHash:  "uABCDEF",
		SafetyPolicy: "did:web:authority.example.com#policy-v3",
		Config:       config,
		Version:      "2026.06",
	})
	if err != nil {
		t.Fatal(err)
	}
	ok, subject := VerifyProvenanceAttestation(att, s.PublicKeyEd25519(), config)
	if !ok {
		t.Fatal("round-trip verify failed")
	}
	vla := subject["vla"].(map[string]any)
	if vla["configHash"] != vectorConfigHash {
		t.Fatalf("embedded configHash mismatch: %v", vla["configHash"])
	}
}

// TestProvenanceConfigTamperFails: a verifier presented a different config than
// the one that was signed must reject, even though the proof itself is valid.
func TestProvenanceConfigTamperFails(t *testing.T) {
	s := newRobot(t, "did:web:robot.example.com")
	config := loadVector(t)["config"].(map[string]any)
	att, err := BuildProvenanceAttestation(s, BuildProvenanceOptions{
		RobotDID: "did:web:robot.example.com", ModelName: "openvla-7b",
		WeightsHash: "uABCDEF", SafetyPolicy: "policy", Config: config,
	})
	if err != nil {
		t.Fatal(err)
	}
	tampered := map[string]any{"temperature": 1.0, "max_torque": 99.0}
	if ok, _ := VerifyProvenanceAttestation(att, s.PublicKeyEd25519(), tampered); ok {
		t.Fatal("expected verification to fail when config does not match configHash")
	}
}

// TestProvenanceWrongTypeFails: a credential that is not a ModelProvenanceAttestation
// must be rejected by the type guard.
func TestProvenanceWrongTypeFails(t *testing.T) {
	s := newRobot(t, "did:web:robot.example.com")
	att, err := BuildProvenanceAttestation(s, BuildProvenanceOptions{
		RobotDID: "did:web:robot.example.com", ModelName: "m", WeightsHash: "w", SafetyPolicy: "p",
	})
	if err != nil {
		t.Fatal(err)
	}
	att["type"] = []any{"VerifiableCredential"}
	if ok, _ := VerifyProvenanceAttestation(att, s.PublicKeyEd25519(), nil); ok {
		t.Fatal("expected a non-provenance type to fail")
	}
}
