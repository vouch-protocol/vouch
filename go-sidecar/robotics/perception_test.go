package robotics

import (
	"reflect"
	"testing"
)

// sampleFrame reconstructs the generator's sample frame: bytes(range(64)).
func sampleFrame() []byte {
	b := make([]byte, 64)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// buildVectorPerceptionLog reconstructs the generator's two-record perception
// log with the same fixed timestamps, so its entries and head are deterministic.
// The first record hashes the raw sample frame; the second supplies a precomputed
// frame hash, matching generate.py.
func buildVectorPerceptionLog(t *testing.T) *PerceptionLog {
	t.Helper()
	plog := NewPerceptionLog("")
	if _, err := plog.Record(RecordOptions{
		SensorID:  "cam-front",
		Modality:  "camera",
		Frame:     sampleFrame(),
		Timestamp: "2026-01-01T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := plog.Record(RecordOptions{
		SensorID:  "lidar-top",
		Modality:  "lidar",
		FrameHash: HashFrame([]byte("scan-0")),
		Timestamp: "2026-01-01T00:00:01Z",
	}); err != nil {
		t.Fatal(err)
	}
	return plog
}

// TestPerceptionMatchesVector reconstructs the generator's frame hash and
// perception log and asserts the frame hash, the entries, and the head equal the
// pinned vector fields. This is the cross-language interop proof.
func TestPerceptionMatchesVector(t *testing.T) {
	v := loadVector(t)

	if got := HashFrame(sampleFrame()); got != v["expected_frame_hash"].(string) {
		t.Fatalf("frame hash mismatch: got %q, want %q", got, v["expected_frame_hash"])
	}

	plog := buildVectorPerceptionLog(t)

	gotEntries := jsonRoundTripList(t, plog.Entries())
	wantEntries := v["perception_log_entries"].([]any)
	if len(gotEntries) != len(wantEntries) {
		t.Fatalf("entry count mismatch: got %d, want %d", len(gotEntries), len(wantEntries))
	}
	for i := range gotEntries {
		if !reflect.DeepEqual(gotEntries[i], wantEntries[i].(map[string]any)) {
			t.Fatalf("entry %d mismatch:\n got=%v\nwant=%v", i, gotEntries[i], wantEntries[i])
		}
	}

	if plog.Head() != v["expected_perception_log_head"].(string) {
		t.Fatalf("log head mismatch: got %q, want %q", plog.Head(), v["expected_perception_log_head"])
	}
}

func TestPerceptionLogVerifiesAndTamperDetected(t *testing.T) {
	plog := buildVectorPerceptionLog(t)
	if r := VerifyPerceptionLog(plog.Entries(), ""); !r.OK {
		t.Fatalf("expected a fresh perception log to verify: %s", r.Reason)
	}
	entries := plog.Entries()
	entries[1]["frameHash"] = HashFrame([]byte("tampered"))
	if r := VerifyPerceptionLog(entries, ""); r.OK {
		t.Fatal("expected a tampered perception entry to fail the chain")
	}
}

func TestPerceptionLogRejectsBadInput(t *testing.T) {
	plog := NewPerceptionLog("")
	if _, err := plog.Record(RecordOptions{SensorID: "cam", Modality: "sonar", Frame: []byte("x")}); err == nil {
		t.Fatal("expected an unknown modality to be rejected")
	}
	if _, err := plog.Record(RecordOptions{Modality: "camera", Frame: []byte("x")}); err == nil {
		t.Fatal("expected a missing sensorId to be rejected")
	}
	if _, err := plog.Record(RecordOptions{SensorID: "cam", Modality: "camera"}); err == nil {
		t.Fatal("expected a missing frame and frameHash to be rejected")
	}
	if _, err := plog.Record(RecordOptions{SensorID: "cam", Modality: "camera", Frame: []byte("x"), FrameHash: HashFrame([]byte("x"))}); err == nil {
		t.Fatal("expected supplying both frame and frameHash to be rejected")
	}
}

func TestPerceptionAttestationBuildVerifyRoundTrip(t *testing.T) {
	s := newRobot(t, "did:web:robot.example.com")
	plog := buildVectorPerceptionLog(t)
	frame := sampleFrame()
	cred, err := BuildPerceptionAttestation(s, BuildPerceptionOptions{
		RobotDID:  "did:web:robot.example.com",
		SensorID:  "cam-front",
		Modality:  "camera",
		FrameHash: HashFrame(frame),
		LogHead:   plog.Head(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(cred["type"], PerceptionType) {
		t.Fatal("missing PerceptionProvenanceCredential type")
	}

	// Verify without the frame, then with the matching frame.
	ok, subject := VerifyPerceptionAttestation(cred, s.PublicKeyEd25519(), nil)
	if !ok {
		t.Fatal("perception attestation round-trip verify failed")
	}
	if subject["logHead"] != plog.Head() {
		t.Fatalf("log head did not survive into the subject: %v", subject["logHead"])
	}
	if ok, _ := VerifyPerceptionAttestation(cred, s.PublicKeyEd25519(), frame); !ok {
		t.Fatal("expected verification with the matching frame to succeed")
	}
}

func TestPerceptionAttestationRejectsWrongFrameAndTamper(t *testing.T) {
	s := newRobot(t, "did:web:robot.example.com")
	frame := sampleFrame()
	cred, err := BuildPerceptionAttestation(s, BuildPerceptionOptions{
		RobotDID:  "did:web:robot.example.com",
		SensorID:  "cam-front",
		Modality:  "camera",
		FrameHash: HashFrame(frame),
	})
	if err != nil {
		t.Fatal(err)
	}

	// A different frame does not reproduce the attested hash.
	if ok, _ := VerifyPerceptionAttestation(cred, s.PublicKeyEd25519(), []byte("not-the-frame")); ok {
		t.Fatal("expected a mismatched frame to fail verification")
	}

	// Tampering with the signed frame hash breaks the proof.
	cred["credentialSubject"].(map[string]any)["frameHash"] = HashFrame([]byte("swapped"))
	if ok, _ := VerifyPerceptionAttestation(cred, s.PublicKeyEd25519(), nil); ok {
		t.Fatal("expected a tampered frameHash to fail the proof")
	}
}
