package robotics

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

var halosStack = map[string]any{
	"igxSom":    "IGX-Thor-SoM",
	"halosCore": "Halos Core Linux 1.0",
	"blueprint": []any{"SAIM", "SEI", "SDM"},
}

var halosWindow = map[string]string{
	"from": "2026-07-12T00:00:00Z",
	"to":   "2026-07-12T01:00:00Z",
}

type halosScenario struct {
	robot *signer.Signer
	rec   *SafetyEventRecorder
	ev    map[string]any
}

func newHalosScenario(t *testing.T) halosScenario {
	t.Helper()
	robot := newRobot(t, "did:web:robot.example.com")
	rec, err := NewSafetyEventRecorder(filled(9))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rec.Record("SAIM", "camera_blockage_cleared", map[string]any{"cam": 2}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := rec.Record("SEI", "multi_camera_fused", map[string]any{"objects": 3}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := rec.Record("SDM", "slow_stop", map[string]any{"reason": "out_of_distribution"}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := rec.Record("estop", "emergency_stop", map[string]any{"by": "operator-7"}, ""); err != nil {
		t.Fatal(err)
	}
	ev, err := BuildSafetyEvidence(robot, BuildSafetyEvidenceOptions{
		HalosStack:    halosStack,
		Window:        halosWindow,
		Recorder:      rec,
		RobotIdentity: "urn:uuid:robot-id",
	})
	if err != nil {
		t.Fatal(err)
	}
	return halosScenario{robot: robot, rec: rec, ev: ev}
}

func TestHalosHappyPathSealsAndVerifies(t *testing.T) {
	s := newHalosScenario(t)
	ok, subject := VerifySafetyEvidence(s.ev, s.robot.PublicKeyEd25519(), VerifySafetyEvidenceOptions{Entries: s.rec.Entries()})
	if !ok {
		t.Fatal("expected the sealed evidence to verify")
	}
	if subject["id"] != s.robot.DID() {
		t.Fatalf("unexpected subject id: %v", subject["id"])
	}
	if n, _ := toInt(subject["entryCount"]); n != 4 {
		t.Fatalf("unexpected entry count: %v", subject["entryCount"])
	}
	if subject["blackboxHead"] != s.rec.Head() {
		t.Fatalf("sealed head did not match the recorder head: %v", subject["blackboxHead"])
	}
	if subject["robotIdentity"] != "urn:uuid:robot-id" {
		t.Fatalf("robot identity did not survive into the subject: %v", subject["robotIdentity"])
	}
	if !hasType(s.ev["type"], HalosSafetyEvidenceType) {
		t.Fatal("missing HalosSafetyEvidenceCredential type")
	}
}

func TestHalosSignatureOnlyPathWithoutEntries(t *testing.T) {
	s := newHalosScenario(t)
	ok, subject := VerifySafetyEvidence(s.ev, s.robot.PublicKeyEd25519(), VerifySafetyEvidenceOptions{})
	if !ok {
		t.Fatal("expected signature-only verification to pass")
	}
	if n, _ := toInt(subject["entryCount"]); n != 4 {
		t.Fatalf("unexpected entry count: %v", subject["entryCount"])
	}
}

func TestHalosUnknownEventSourceRejected(t *testing.T) {
	rec, err := NewSafetyEventRecorder(filled(9))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rec.Record("bogus", "whatever", map[string]any{}, ""); err == nil {
		t.Fatal("expected an unknown Halos event source to be rejected")
	}
}

func TestHalosTamperedEntryRejected(t *testing.T) {
	s := newHalosScenario(t)
	entries := s.rec.Entries()
	entries[1]["event"] = "forged_event"
	if ok, _ := VerifySafetyEvidence(s.ev, s.robot.PublicKeyEd25519(), VerifySafetyEvidenceOptions{Entries: entries}); ok {
		t.Fatal("expected a tampered entry to be rejected")
	}
}

func TestHalosTruncatedRecordRejected(t *testing.T) {
	s := newHalosScenario(t)
	entries := s.rec.Entries()
	entries = entries[:len(entries)-1]
	if ok, _ := VerifySafetyEvidence(s.ev, s.robot.PublicKeyEd25519(), VerifySafetyEvidenceOptions{Entries: entries}); ok {
		t.Fatal("expected a truncated record to be rejected")
	}
}

func TestHalosAppendedAfterSealRejected(t *testing.T) {
	s := newHalosScenario(t)
	// Seal, then keep recording: the presented log no longer matches the seal.
	if _, err := s.rec.Record("operator", "resume", map[string]any{"by": "operator-7"}, ""); err != nil {
		t.Fatal(err)
	}
	if ok, _ := VerifySafetyEvidence(s.ev, s.robot.PublicKeyEd25519(), VerifySafetyEvidenceOptions{Entries: s.rec.Entries()}); ok {
		t.Fatal("expected a record extended after sealing to be rejected")
	}
}

func TestHalosReorderedEntriesRejected(t *testing.T) {
	s := newHalosScenario(t)
	entries := s.rec.Entries()
	entries[0], entries[2] = entries[2], entries[0]
	if ok, _ := VerifySafetyEvidence(s.ev, s.robot.PublicKeyEd25519(), VerifySafetyEvidenceOptions{Entries: entries}); ok {
		t.Fatal("expected reordered entries to be rejected")
	}
}

func TestHalosWrongRobotKeyRejected(t *testing.T) {
	s := newHalosScenario(t)
	other := newRobot(t, "did:web:other.example.com")
	if ok, _ := VerifySafetyEvidence(s.ev, other.PublicKeyEd25519(), VerifySafetyEvidenceOptions{Entries: s.rec.Entries()}); ok {
		t.Fatal("expected verification under the wrong robot key to fail")
	}
}

func TestHalosForgedEvidenceNotAttributableToRobot(t *testing.T) {
	// An attacker seals the robot's real head under its own key. Verifying with
	// the robot's key fails, so the evidence cannot be attributed to the robot.
	s := newHalosScenario(t)
	attacker := newRobot(t, "did:web:attacker.example.com")
	forged, err := BuildSafetyEvidence(attacker, BuildSafetyEvidenceOptions{
		HalosStack:    halosStack,
		Window:        halosWindow,
		BlackboxHead:  s.rec.Head(),
		EntryCount:    s.rec.Count(),
		HasEntryCount: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := VerifySafetyEvidence(forged, s.robot.PublicKeyEd25519(), VerifySafetyEvidenceOptions{Entries: s.rec.Entries()}); ok {
		t.Fatal("expected forged evidence to not be attributable to the robot")
	}
}

func TestHalosHeadMismatchRejected(t *testing.T) {
	s := newHalosScenario(t)
	bad, err := BuildSafetyEvidence(s.robot, BuildSafetyEvidenceOptions{
		HalosStack:    halosStack,
		Window:        halosWindow,
		BlackboxHead:  "uAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		EntryCount:    s.rec.Count(),
		HasEntryCount: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := VerifySafetyEvidence(bad, s.robot.PublicKeyEd25519(), VerifySafetyEvidenceOptions{Entries: s.rec.Entries()}); ok {
		t.Fatal("expected a sealed head that does not match the entries to be rejected")
	}
}

func TestHalosMissingStackOrWindowRejected(t *testing.T) {
	robot := newRobot(t, "did:web:robot.example.com")
	if _, err := BuildSafetyEvidence(robot, BuildSafetyEvidenceOptions{
		HalosStack: map[string]any{}, Window: halosWindow, BlackboxHead: "u", HasEntryCount: true,
	}); err == nil {
		t.Fatal("expected a missing halos stack to be rejected")
	}
	if _, err := BuildSafetyEvidence(robot, BuildSafetyEvidenceOptions{
		HalosStack: halosStack, Window: map[string]string{}, BlackboxHead: "u", HasEntryCount: true,
	}); err == nil {
		t.Fatal("expected a missing window to be rejected")
	}
}

func TestHalosPayloadsConfidentialButChainPublic(t *testing.T) {
	// The chain verifies from the encrypted entries without the key, while the
	// payloads open only with the black-box key.
	s := newHalosScenario(t)
	entries := s.rec.Entries()
	blob, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "operator-7") {
		t.Fatal("payload leaked in the encrypted entries")
	}
	opened, err := s.rec.OpenEntry(entries[3])
	if err != nil {
		t.Fatal(err)
	}
	if opened["source"] != "estop" {
		t.Fatalf("unexpected opened source: %v", opened["source"])
	}
	detail, _ := opened["detail"].(map[string]any)
	if detail["by"] != "operator-7" {
		t.Fatalf("unexpected opened detail: %v", detail)
	}
}

// pythonHalosVector was produced by the Python reference (vouch/robotics/halos.py)
// from a fixed Ed25519 seed (bytes 0x00..0x1f) and a fixed created timestamp, so
// Go verifies a credential and black-box chain it did not itself produce.
const pythonHalosVector = `{
  "credential": {
    "@context": ["https://www.w3.org/ns/credentials/v2", "https://vouch-protocol.com/contexts/v1"],
    "type": ["VerifiableCredential", "HalosSafetyEvidenceCredential"],
    "issuer": "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd",
    "validFrom": "2026-07-12T00:50:00Z",
    "credentialSubject": {
      "id": "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd",
      "blackboxHead": "u82fjhvgrn0z7P-mnnZbLLee30hikdpF8COrLgbYWYv4",
      "entryCount": 4,
      "halosStack": {
        "igxSom": "IGX-Thor-SoM",
        "halosCore": "Halos Core Linux 1.0",
        "blueprint": ["SAIM", "SEI", "SDM"]
      },
      "window": {"from": "2026-07-12T00:00:00Z", "to": "2026-07-12T01:00:00Z"},
      "robotIdentity": "urn:uuid:robot-id"
    },
    "proof": {
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-jcs-2022",
      "created": "2026-07-12T00:50:00Z",
      "verificationMethod": "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd#key-1",
      "proofPurpose": "assertionMethod",
      "proofValue": "zwZDBkeCbWz26pJni7iiueDaMT3zpNMz8EF7KqeaVxpttQbqv6FR8weZT7sDAp6AbD4pQDN2HNVF8dyZbe2S1gvZ"
    }
  },
  "entries": [
    {"version": "1.0", "seq": 0, "timestamp": "2026-07-12T00:10:00Z", "event": "camera_blockage_cleared", "ciphertext": "uN6UCEOV0Zc7ncB-i388PHo9o2wmfS8WOlxtO59mL-fspPWlYvPUWzh3wZpzlacOX8dXFn4llu6PUgbhP_Y2EYA", "prevHash": "uAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "entryHash": "uo0RaFa1FdMUfZqu-xRpTHylocM-JpONylczvx4rE3ts"},
    {"version": "1.0", "seq": 1, "timestamp": "2026-07-12T00:20:00Z", "event": "multi_camera_fused", "ciphertext": "uy0rELnEUcMADjg07QGGOa5-saZ5QQlu2-l-IBL67icySRxMXm4RHvTHA7BSbnY1Po8rohlOXuWouP58YWSwRg8hM-g", "prevHash": "uo0RaFa1FdMUfZqu-xRpTHylocM-JpONylczvx4rE3ts", "entryHash": "uj8OqxWIId9iqNxz0uADLvcg8MGA3xM6cg-236DwnFFE"},
    {"version": "1.0", "seq": 2, "timestamp": "2026-07-12T00:30:00Z", "event": "slow_stop", "ciphertext": "uTFOWlyw1DQ-JqN__u6GKViUB6GWpVhFB20UepI8T7gfHMMOuulywBrgaL_ldF4KOX-QE9nvB39HR1VF7MqVtBkSaQ3ov7BzD_YyUs6Im4eypzheGG-w", "prevHash": "uj8OqxWIId9iqNxz0uADLvcg8MGA3xM6cg-236DwnFFE", "entryHash": "uOmuDhcXxLB5CgtLwWfQ88idpH2wJPDrpGvS-smoboOs"},
    {"version": "1.0", "seq": 3, "timestamp": "2026-07-12T00:40:00Z", "event": "emergency_stop", "ciphertext": "u1iORDTzr9ZsRVceldvJL4qSoojs3IeLNkcSnwSfIhRUyB4BiyJeOWhE4_3HSBfhOVOWvkX25nyFPhbEXTSYdb7suwshOj3e0w66u", "prevHash": "uOmuDhcXxLB5CgtLwWfQ88idpH2wJPDrpGvS-smoboOs", "entryHash": "u82fjhvgrn0z7P-mnnZbLLee30hikdpF8COrLgbYWYv4"}
  ],
  "robot_public_key_jwk": {"kty": "OKP", "crv": "Ed25519", "x": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"}
}`

// TestHalosVerifyPythonVector is the cross-language proof: Go verifies a
// HalosSafetyEvidenceCredential and its black-box chain produced by the Python
// reference, and rejects the same record once one entry is tampered.
func TestHalosVerifyPythonVector(t *testing.T) {
	var v struct {
		Credential        map[string]any   `json:"credential"`
		Entries           []map[string]any `json:"entries"`
		RobotPublicKeyJWK map[string]any   `json:"robot_public_key_jwk"`
	}
	if err := json.Unmarshal([]byte(pythonHalosVector), &v); err != nil {
		t.Fatal(err)
	}
	pub := ed25519FromJWK(t, v.RobotPublicKeyJWK)

	ok, subject := VerifySafetyEvidence(v.Credential, pub, VerifySafetyEvidenceOptions{Entries: v.Entries})
	if !ok {
		t.Fatal("expected the Python-produced Halos evidence to verify in Go")
	}
	if subject["robotIdentity"] != "urn:uuid:robot-id" {
		t.Fatalf("unexpected subject: %v", subject)
	}

	// Tamper with one entry: the chain no longer matches the sealed head.
	v.Entries[1]["event"] = "forged_event"
	if ok, _ := VerifySafetyEvidence(v.Credential, pub, VerifySafetyEvidenceOptions{Entries: v.Entries}); ok {
		t.Fatal("expected a tampered Python entry to be rejected in Go")
	}
}
