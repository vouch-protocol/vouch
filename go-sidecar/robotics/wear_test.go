package robotics

import (
	"testing"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

var (
	wearT0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	wearT1 = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
)

var wearScope = map[string]any{
	"maxForceN":             80.0,
	"maxSpeedMps":           1.5,
	"maxSpeedNearHumansMps": 0.25,
	"allowedZones":          []any{"cell-3"},
	"shiftWindows":          []any{map[string]any{"start": "08:00", "end": "18:00"}},
}

func newWearAttestation(t *testing.T, robot *signer.Signer, level float64, prev string) map[string]any {
	t.Helper()
	att, err := BuildWearAttestation(robot, BuildWearAttestationOptions{
		RobotDID:   robot.DID(),
		WearLevel:  level,
		Metrics:    map[string]any{"actuatorWear": level, "cycleCount": 120000},
		PrevProof:  prev,
		AttestedAt: wearT0,
	})
	if err != nil {
		t.Fatal(err)
	}
	return att
}

// TestWearInteropVector is the cross-language interop proof: Go verifies the
// robot-signed wear history minted by the Python module and pinned in the shared
// interop vector, and reproduces the wear-narrowed physical scope.
func TestWearInteropVector(t *testing.T) {
	v := loadVector(t)

	rawChain, ok := v["wear_chain"].([]any)
	if !ok || len(rawChain) == 0 {
		t.Fatal("vector is missing wear_chain")
	}
	chain := make([]map[string]any, len(rawChain))
	for i, c := range rawChain {
		chain[i] = c.(map[string]any)
	}

	pub := ed25519FromJWK(t, v["robot_public_key_jwk"].(map[string]any))
	chainOK, latest := VerifyWearChain(chain, pub)
	if !chainOK {
		t.Fatal("expected the Python-minted wear chain to verify in Go")
	}
	if level, _ := scopeNum(latest, "wearLevel"); level != 0.3 {
		t.Fatalf("latest wear level = %v, want 0.3", level)
	}

	inputScope := v["wear_input_scope"].(map[string]any)
	level := v["wear_attenuation_level"].(float64)
	expected := v["expected_attenuated_scope"].(map[string]any)

	narrowed, err := AttenuateForWear(inputScope, level)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range deratedCaps {
		want, _ := scopeNum(expected, key)
		got, ok := scopeNum(narrowed, key)
		if !ok || got != want {
			t.Fatalf("attenuated %s = %v, want %v", key, got, want)
		}
	}
	if !Attenuates(inputScope, narrowed) {
		t.Fatal("expected the reproduced scope to attenuate the input scope")
	}
}

func TestWearAttestationVerifies(t *testing.T) {
	robot := newRobot(t, "did:web:robot-a.example.com")
	att := newWearAttestation(t, robot, 0.2, "")

	ok, subject := VerifyWearAttestation(att, robot.PublicKeyEd25519())
	if !ok {
		t.Fatal("expected the wear attestation to verify")
	}
	if level, _ := scopeNum(subject, "wearLevel"); level != 0.2 {
		t.Fatalf("unexpected wear level: %v", level)
	}
	metrics, _ := subject["metrics"].(map[string]any)
	if cycles, _ := scopeNum(metrics, "cycleCount"); cycles != 120000 {
		t.Fatalf("unexpected cycle count: %v", cycles)
	}
}

func TestWearAttestationWrongKeyRejected(t *testing.T) {
	robot := newRobot(t, "did:web:robot-a.example.com")
	other := newRobot(t, "did:web:robot-b.example.com")
	att := newWearAttestation(t, robot, 0.2, "")

	if ok, _ := VerifyWearAttestation(att, other.PublicKeyEd25519()); ok {
		t.Fatal("expected an attestation checked under the wrong key to be rejected")
	}
}

func TestWearAttestationOutOfRangeRejected(t *testing.T) {
	robot := newRobot(t, "did:web:robot-a.example.com")
	if _, err := BuildWearAttestation(robot, BuildWearAttestationOptions{
		RobotDID:  robot.DID(),
		WearLevel: 1.5,
	}); err == nil {
		t.Fatal("expected an out-of-range wear level to be rejected")
	}
}

func TestWearAttestationTamperedLevelRejected(t *testing.T) {
	robot := newRobot(t, "did:web:robot-a.example.com")
	att := newWearAttestation(t, robot, 0.2, "")

	subject := att["credentialSubject"].(map[string]any)
	subject["wearLevel"] = 0.9

	if ok, _ := VerifyWearAttestation(att, robot.PublicKeyEd25519()); ok {
		t.Fatal("expected a tampered wear level to fail verification")
	}
}

func TestWearChainLinksByProof(t *testing.T) {
	robot := newRobot(t, "did:web:robot-a.example.com")
	a := newWearAttestation(t, robot, 0.1, "")
	proof := a["proof"].(map[string]any)["proofValue"].(string)
	b, err := BuildWearAttestation(robot, BuildWearAttestationOptions{
		RobotDID:   robot.DID(),
		WearLevel:  0.3,
		PrevProof:  proof,
		AttestedAt: wearT1,
	})
	if err != nil {
		t.Fatal(err)
	}

	ok, latest := VerifyWearChain([]map[string]any{a, b}, robot.PublicKeyEd25519())
	if !ok {
		t.Fatal("expected the wear chain to verify")
	}
	if level, _ := scopeNum(latest, "wearLevel"); level != 0.3 {
		t.Fatalf("latest wear level = %v, want 0.3", level)
	}
}

func TestWearChainBrokenLinkRejected(t *testing.T) {
	robot := newRobot(t, "did:web:robot-a.example.com")
	a := newWearAttestation(t, robot, 0.1, "")
	b, err := BuildWearAttestation(robot, BuildWearAttestationOptions{
		RobotDID:   robot.DID(),
		WearLevel:  0.3,
		PrevProof:  "uWRONG",
		AttestedAt: wearT1,
	})
	if err != nil {
		t.Fatal(err)
	}

	if ok, _ := VerifyWearChain([]map[string]any{a, b}, robot.PublicKeyEd25519()); ok {
		t.Fatal("expected a broken chain link to be rejected")
	}
}

func TestAttenuateForWearNarrowsCaps(t *testing.T) {
	narrowed, err := AttenuateForWear(wearScope, 0.25)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := scopeNum(narrowed, "maxForceN"); got != 60.0 {
		t.Fatalf("maxForceN = %v, want 60.0", got)
	}
	if got, _ := scopeNum(narrowed, "maxSpeedMps"); got != 1.125 {
		t.Fatalf("maxSpeedMps = %v, want 1.125", got)
	}
	if got, _ := scopeNum(narrowed, "maxSpeedNearHumansMps"); got != 0.1875 {
		t.Fatalf("maxSpeedNearHumansMps = %v, want 0.1875", got)
	}
	if zones := toStrSlice(narrowed["allowedZones"]); len(zones) != 1 || zones[0] != "cell-3" {
		t.Fatalf("allowedZones = %v, want [cell-3]", zones)
	}
	if !Attenuates(wearScope, narrowed) {
		t.Fatal("expected the narrowed scope to attenuate the original")
	}
}

func TestAttenuateForWearZeroIsIdentityOnCaps(t *testing.T) {
	narrowed, err := AttenuateForWear(wearScope, 0.0)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := scopeNum(narrowed, "maxForceN"); got != 80.0 {
		t.Fatalf("maxForceN = %v, want 80.0", got)
	}
	if !Attenuates(wearScope, narrowed) {
		t.Fatal("expected the zero-wear scope to attenuate the original")
	}
}

func TestAttenuateForWearFullStillAttenuates(t *testing.T) {
	narrowed, err := AttenuateForWear(wearScope, 1.0)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := scopeNum(narrowed, "maxForceN"); got != 0.0 {
		t.Fatalf("maxForceN = %v, want 0.0", got)
	}
	if !Attenuates(wearScope, narrowed) {
		t.Fatal("expected the full-wear scope to attenuate the original")
	}
}

func TestAttenuateForWearOutOfRangeRejected(t *testing.T) {
	if _, err := AttenuateForWear(wearScope, 1.5); err == nil {
		t.Fatal("expected an out-of-range wear level to be rejected")
	}
}
