package robotics

import (
	"testing"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

var fusionT0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// TestFusionInteropVector is the cross-language interop proof: Go reproduces the
// deterministic fused-sensor computations minted by the Python module and pinned
// in the shared interop vector, and verifies the Python-signed attestation.
func TestFusionInteropVector(t *testing.T) {
	v := loadVector(t)

	inputHashes := stringSlice(v["fused_input_frame_hashes"])
	if len(inputHashes) == 0 {
		t.Fatal("vector is missing fused_input_frame_hashes")
	}
	expectedDigest := v["expected_fusion_inputs_digest"].(string)
	expectedOutputHash := v["expected_fused_output_hash"].(string)

	digest, err := FusionInputsDigest(inputHashes)
	if err != nil {
		t.Fatal(err)
	}
	if digest != expectedDigest {
		t.Fatalf("fusion inputs digest = %q, want %q", digest, expectedDigest)
	}

	// The vector pins the fused-output hash but not the raw output, so reproduce
	// the hash from the same input the Python module hashed.
	if got := HashFusedOutput([]byte("world-model-0")); got != expectedOutputHash {
		t.Fatalf("fused output hash = %q, want %q", got, expectedOutputHash)
	}

	cred := v["fused_perception_attestation"].(map[string]any)
	pub := ed25519FromJWK(t, v["robot_public_key_jwk"].(map[string]any))
	ok, subject := VerifyFusedAttestation(cred, pub, nil)
	if !ok {
		t.Fatal("expected the Python-minted fused attestation to verify in Go")
	}
	if subject["fusionMethod"] != "occupancy-grid-v1" {
		t.Fatalf("unexpected fusion method: %v", subject["fusionMethod"])
	}
	if subject["inputsDigest"] != expectedDigest {
		t.Fatalf("subject inputsDigest = %v, want %q", subject["inputsDigest"], expectedDigest)
	}
}

func fusionInputs(t *testing.T) []string {
	t.Helper()
	frames := [][]byte{[]byte("cam-front-0"), []byte("lidar-top-0"), []byte("radar-0")}
	hashes := make([]string, len(frames))
	for i, f := range frames {
		hashes[i] = HashFrame(f)
	}
	return hashes
}

func newFusedAttestation(t *testing.T, robot *signer.Signer, inputs []string) map[string]any {
	t.Helper()
	att, err := BuildFusedAttestation(robot, BuildFusedAttestationOptions{
		RobotDID:         robot.DID(),
		FusionMethod:     "occupancy-grid-v1",
		InputFrameHashes: inputs,
		FusedOutput:      []byte("world-model-0"),
		CapturedAt:       fusionT0,
	})
	if err != nil {
		t.Fatal(err)
	}
	return att
}

func TestFusedAttestationVerifiesAndCarriesInputs(t *testing.T) {
	robot := newRobot(t, "did:web:robot-a.example.com")
	inputs := fusionInputs(t)
	att := newFusedAttestation(t, robot, inputs)

	ok, subject := VerifyFusedAttestation(att, robot.PublicKeyEd25519(), nil)
	if !ok {
		t.Fatal("expected the fused attestation to verify")
	}
	if subject["fusionMethod"] != "occupancy-grid-v1" {
		t.Fatalf("unexpected fusion method: %v", subject["fusionMethod"])
	}
	if subject["fusedOutputHash"] != HashFusedOutput([]byte("world-model-0")) {
		t.Fatalf("unexpected fused output hash: %v", subject["fusedOutputHash"])
	}
}

func TestFusedAttestationVerifiesWithRawOutput(t *testing.T) {
	robot := newRobot(t, "did:web:robot-a.example.com")
	att := newFusedAttestation(t, robot, fusionInputs(t))

	if ok, _ := VerifyFusedAttestation(att, robot.PublicKeyEd25519(), []byte("world-model-0")); !ok {
		t.Fatal("expected the fused attestation to verify with the matching raw output")
	}
}

func TestFusedAttestationWrongRawOutputRejected(t *testing.T) {
	robot := newRobot(t, "did:web:robot-a.example.com")
	att := newFusedAttestation(t, robot, fusionInputs(t))

	if ok, _ := VerifyFusedAttestation(att, robot.PublicKeyEd25519(), []byte("tampered-world-model")); ok {
		t.Fatal("expected a mismatched raw output to be rejected")
	}
}

func TestFusedAttestationWrongKeyRejected(t *testing.T) {
	robot := newRobot(t, "did:web:robot-a.example.com")
	other := newRobot(t, "did:web:robot-b.example.com")
	att := newFusedAttestation(t, robot, fusionInputs(t))

	if ok, _ := VerifyFusedAttestation(att, other.PublicKeyEd25519(), nil); ok {
		t.Fatal("expected an attestation checked under the wrong key to be rejected")
	}
}

func TestFusedAttestationTamperedInputsBreakDigest(t *testing.T) {
	robot := newRobot(t, "did:web:robot-a.example.com")
	att := newFusedAttestation(t, robot, fusionInputs(t))

	// Swap an input frame hash without re-signing: the reproduced digest no
	// longer matches the attested inputsDigest.
	subject := att["credentialSubject"].(map[string]any)
	inputs := subject["inputFrameHashes"].([]any)
	inputs[0] = HashFrame([]byte("substituted-frame"))

	if ok, _ := VerifyFusedAttestation(att, robot.PublicKeyEd25519(), nil); ok {
		t.Fatal("expected a tampered input list to break the digest and fail verification")
	}
}

func TestFusionInputsDigestOrderSensitive(t *testing.T) {
	inputs := fusionInputs(t)
	forward, err := FusionInputsDigest(inputs)
	if err != nil {
		t.Fatal(err)
	}
	reversed := []string{inputs[2], inputs[1], inputs[0]}
	backward, err := FusionInputsDigest(reversed)
	if err != nil {
		t.Fatal(err)
	}
	if forward == backward {
		t.Fatal("expected the inputs digest to be order-sensitive")
	}
}

func TestFusionInputsDigestRejectsEmpty(t *testing.T) {
	if _, err := FusionInputsDigest(nil); err == nil {
		t.Fatal("expected an empty input list to be rejected")
	}
	if _, err := FusionInputsDigest([]string{"uAAAA", ""}); err == nil {
		t.Fatal("expected an empty input element to be rejected")
	}
}

func TestVerifyFusionInputsAllRecorded(t *testing.T) {
	robot := newRobot(t, "did:web:robot-a.example.com")
	log := NewPerceptionLog("")
	frames := [][]byte{[]byte("cam-front-0"), []byte("lidar-top-0"), []byte("radar-0")}
	modalities := []string{"camera", "lidar", "radar"}
	inputs := make([]string, len(frames))
	for i, f := range frames {
		if _, err := log.Record(RecordOptions{
			SensorID:  "sensor-" + modalities[i],
			Modality:  modalities[i],
			Frame:     f,
			Timestamp: "2026-01-01T00:00:00Z",
		}); err != nil {
			t.Fatal(err)
		}
		inputs[i] = HashFrame(f)
	}
	att := newFusedAttestation(t, robot, inputs)

	ok, missing := VerifyFusionInputs(att, log.Entries())
	if !ok {
		t.Fatalf("expected every fused input to be recorded, missing: %v", missing)
	}
	if len(missing) != 0 {
		t.Fatalf("expected no missing inputs, got %v", missing)
	}
}

func TestVerifyFusionInputsNamesUnrecorded(t *testing.T) {
	robot := newRobot(t, "did:web:robot-a.example.com")
	log := NewPerceptionLog("")
	frame := []byte("cam-front-0")
	if _, err := log.Record(RecordOptions{
		SensorID:  "sensor-camera",
		Modality:  "camera",
		Frame:     frame,
		Timestamp: "2026-01-01T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	phantom := HashFrame([]byte("never-captured"))
	att := newFusedAttestation(t, robot, []string{HashFrame(frame), phantom})

	ok, missing := VerifyFusionInputs(att, log.Entries())
	if ok {
		t.Fatal("expected an unrecorded fused input to be named")
	}
	if len(missing) != 1 || missing[0] != phantom {
		t.Fatalf("expected the phantom input to be named, got %v", missing)
	}
}
