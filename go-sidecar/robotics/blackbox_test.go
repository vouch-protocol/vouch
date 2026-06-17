package robotics

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGenesisPrevHash(t *testing.T) {
	// Multibase ('u') of 32 zero bytes is 'u' followed by 43 'A' base64url chars,
	// identical to the Python and TypeScript constant.
	want := "u" + strings.Repeat("A", 43)
	if GenesisPrevHash != want {
		t.Fatalf("GenesisPrevHash = %q, want %q", GenesisPrevHash, want)
	}
}

func newLog(t *testing.T) *BlackBoxLog {
	t.Helper()
	log, err := NewBlackBoxLog(filled(0x11), "")
	if err != nil {
		t.Fatal(err)
	}
	return log
}

func TestBlackboxAppendOpenRoundTrip(t *testing.T) {
	log := newLog(t)
	payload := map[string]any{"speed": 1.5, "joint": "elbow", "fault": false}
	entry, err := log.Append("motion", payload, "2026-06-17T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if entry["event"] != "motion" || entry["seq"].(int) != 0 {
		t.Fatalf("unexpected entry metadata: %v", entry)
	}
	opened, err := log.OpenEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	if opened["joint"] != "elbow" || opened["speed"].(float64) != 1.5 || opened["fault"].(bool) != false {
		t.Fatalf("decrypted payload mismatch: %v", opened)
	}
}

func TestBlackboxChainVerifies(t *testing.T) {
	log := newLog(t)
	for i, ev := range []string{"boot", "motion", "stop"} {
		if _, err := log.Append(ev, map[string]any{"i": i}, ""); err != nil {
			t.Fatal(err)
		}
	}
	if r := VerifyBlackboxChain(log.Entries(), ""); !r.OK {
		t.Fatalf("expected a fresh chain to verify: %s", r.Reason)
	}
}

func TestBlackboxTamperDetected(t *testing.T) {
	log := newLog(t)
	_, _ = log.Append("boot", map[string]any{"i": 0}, "")
	_, _ = log.Append("motion", map[string]any{"i": 1}, "")
	entries := log.Entries()

	// Tamper with a recorded field without recomputing the hash.
	entries[1]["event"] = "tampered"
	if r := VerifyBlackboxChain(entries, ""); r.OK {
		t.Fatal("expected a tampered entry to fail the chain")
	}
}

// TestBlackboxChainAfterJSONRoundTrip is the cross-language check: entries written
// in Go are serialized and decoded (seq becomes float64, as it would from a
// Python- or TypeScript-written log), and the JCS hash chain must still verify.
func TestBlackboxChainAfterJSONRoundTrip(t *testing.T) {
	log := newLog(t)
	for i, ev := range []string{"boot", "motion", "stop", "shutdown"} {
		if _, err := log.Append(ev, map[string]any{"i": i, "t": float64(i) * 0.5}, ""); err != nil {
			t.Fatal(err)
		}
	}
	blob, err := json.Marshal(log.Entries())
	if err != nil {
		t.Fatal(err)
	}
	var wire []map[string]any
	if err := json.Unmarshal(blob, &wire); err != nil {
		t.Fatal(err)
	}
	if r := VerifyBlackboxChain(wire, ""); !r.OK {
		t.Fatalf("expected JSON-decoded chain to verify: %s", r.Reason)
	}
	// And the payload still decrypts from the decoded entry.
	opened, err := OpenEntry(wire[1], filled(0x11))
	if err != nil {
		t.Fatal(err)
	}
	if opened["i"].(float64) != 1 {
		t.Fatalf("decoded entry payload mismatch: %v", opened)
	}
}

func TestBlackboxWrongKeyFails(t *testing.T) {
	log := newLog(t)
	entry, _ := log.Append("boot", map[string]any{"secret": "x"}, "")
	if _, err := OpenEntry(entry, filled(0x22)); err == nil {
		t.Fatal("expected decryption with the wrong key to fail")
	}
}

func TestBlackboxBadKeyLength(t *testing.T) {
	if _, err := NewBlackBoxLog(make([]byte, 16), ""); err == nil {
		t.Fatal("expected a 16-byte key to be rejected")
	}
}

func TestKillswitchBuildVerify(t *testing.T) {
	authority := newRobot(t, "did:web:safety.example.com")
	cred, err := BuildKillswitchCredential(authority, BuildKillswitchOptions{
		Target: "did:web:robot.example.com", Reason: "human in path", Scope: []string{"arm", "drive"},
	})
	if err != nil {
		t.Fatal(err)
	}
	trusted := map[string]bool{"did:web:safety.example.com": true}
	ok, subject := VerifyKillswitchCredential(cred, authority.PublicKeyEd25519(), trusted)
	if !ok {
		t.Fatal("a trusted authority's kill switch should verify")
	}
	if subject["command"] != EmergencyStop || subject["issuedBy"] != "did:web:safety.example.com" {
		t.Fatalf("unexpected kill-switch subject: %v", subject)
	}
}

func TestKillswitchUntrustedAuthorityRejected(t *testing.T) {
	authority := newRobot(t, "did:web:rogue.example.com")
	cred, err := BuildKillswitchCredential(authority, BuildKillswitchOptions{
		Target: "did:web:robot.example.com", Reason: "spoofed stop",
	})
	if err != nil {
		t.Fatal(err)
	}
	trusted := map[string]bool{"did:web:safety.example.com": true}
	// Signature is valid, but the issuer is not an attested authority.
	if ok, _ := VerifyKillswitchCredential(cred, authority.PublicKeyEd25519(), trusted); ok {
		t.Fatal("expected an untrusted authority's kill switch to be rejected")
	}
}

func TestKillswitchWrongTypeRejected(t *testing.T) {
	authority := newRobot(t, "did:web:safety.example.com")
	cred, err := BuildKillswitchCredential(authority, BuildKillswitchOptions{
		Target: "did:web:robot.example.com", Reason: "x",
	})
	if err != nil {
		t.Fatal(err)
	}
	cred["type"] = []any{"VerifiableCredential"}
	if ok, _ := VerifyKillswitchCredential(cred, authority.PublicKeyEd25519(), nil); ok {
		t.Fatal("expected a non-killswitch type to be rejected")
	}
}
