package robotics

import (
	"reflect"
	"testing"
)

// buildVectorLog reconstructs the generator's two-event safety ledger with the
// same fixed timestamps, so its entries, head, and summary are deterministic.
func buildVectorLog(t *testing.T) *SafetyEventLog {
	t.Helper()
	log := NewSafetyEventLog("")
	if _, err := log.Append("near_miss", AppendSafetyOptions{
		Severity:  "low",
		Details:   map[string]any{"zone": "cell-3"},
		Timestamp: "2026-01-01T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append("envelope_breach", AppendSafetyOptions{
		Severity:  "high",
		Timestamp: "2026-01-01T00:01:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	return log
}

// TestSafetyLedgerMatchesVector reconstructs the generator's ledger and asserts
// the entries, the head hash, and the summary equal the pinned vector fields.
func TestSafetyLedgerMatchesVector(t *testing.T) {
	v := loadVector(t)
	log := buildVectorLog(t)

	gotEntries := jsonRoundTripList(t, log.Entries())
	wantEntries := v["safety_log_entries"].([]any)
	if len(gotEntries) != len(wantEntries) {
		t.Fatalf("entry count mismatch: got %d, want %d", len(gotEntries), len(wantEntries))
	}
	for i := range gotEntries {
		if !reflect.DeepEqual(gotEntries[i], wantEntries[i].(map[string]any)) {
			t.Fatalf("entry %d mismatch:\n got=%v\nwant=%v", i, gotEntries[i], wantEntries[i])
		}
	}

	if log.Head() != v["expected_safety_log_head"].(string) {
		t.Fatalf("log head mismatch: got %q, want %q", log.Head(), v["expected_safety_log_head"])
	}

	gotSummary := jsonRoundTrip(t, log.Summarize())
	wantSummary := v["expected_safety_summary"].(map[string]any)
	if !reflect.DeepEqual(gotSummary, wantSummary) {
		t.Fatalf("summary mismatch:\n got=%v\nwant=%v", gotSummary, wantSummary)
	}
}

func TestSafetyLogVerifiesAndTamperDetected(t *testing.T) {
	log := buildVectorLog(t)
	if r := VerifySafetyLog(log.Entries(), ""); !r.OK {
		t.Fatalf("expected a fresh safety ledger to verify: %s", r.Reason)
	}
	entries := log.Entries()
	entries[1]["severity"] = "low"
	if r := VerifySafetyLog(entries, ""); r.OK {
		t.Fatal("expected a tampered safety entry to fail the chain")
	}
}

func TestSafetyLogRejectsBadEventType(t *testing.T) {
	log := NewSafetyEventLog("")
	if _, err := log.Append("explosion", AppendSafetyOptions{}); err == nil {
		t.Fatal("expected an unknown event type to be rejected")
	}
	if _, err := log.Append("incident", AppendSafetyOptions{Severity: "catastrophic"}); err == nil {
		t.Fatal("expected an unknown severity to be rejected")
	}
}

func TestSafetyRecordBuildVerifyRoundTrip(t *testing.T) {
	s := newRobot(t, "did:web:owner.example.com")
	log := buildVectorLog(t)
	cred, err := BuildSafetyRecord(s, BuildSafetyRecordOptions{
		RobotDID: "did:web:robot.example.com",
		Summary:  log.Summarize(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(cred["type"], SafetyRecordType) {
		t.Fatal("missing RobotSafetyRecordCredential type")
	}
	ok, subject := VerifySafetyRecord(cred, s.PublicKeyEd25519())
	if !ok {
		t.Fatal("safety-record round-trip verify failed")
	}
	if subject["id"] != "did:web:robot.example.com" {
		t.Fatalf("unexpected subject id: %v", subject["id"])
	}
	if subject["logHead"] != log.Head() {
		t.Fatalf("summary head did not survive into the subject: %v", subject["logHead"])
	}
}

func jsonRoundTripList(t *testing.T, list []map[string]any) []map[string]any {
	t.Helper()
	out := make([]map[string]any, len(list))
	for i, e := range list {
		out[i] = jsonRoundTrip(t, e)
	}
	return out
}
