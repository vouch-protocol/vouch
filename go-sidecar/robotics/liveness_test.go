package robotics

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

// vectorScope reconstructs the physical_scope the generator used, as a Go map.
func vectorScope() map[string]any {
	return map[string]any{
		"maxForceN":             80.0,
		"maxSpeedMps":           1.5,
		"maxSpeedNearHumansMps": 0.25,
		"allowedZones":          []any{"cell-3"},
	}
}

// TestMotionDigestMatchesVector reconstructs the generator's two recorded
// samples against the pinned scope and asserts the motion digest equals the
// vector's expected_motion_digest field after a JSON round-trip.
func TestMotionDigestMatchesVector(t *testing.T) {
	v := loadVector(t)
	c := NewMotionCollector(vectorScope())
	if err := c.Record(MotionRecord{ForceN: fptr(12.0), SpeedMps: fptr(0.4), NearHumans: false, Zone: "cell-3"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Record(MotionRecord{ForceN: fptr(20.0), SpeedMps: fptr(0.2), NearHumans: true, Zone: "cell-3"}); err != nil {
		t.Fatal(err)
	}
	got := jsonRoundTrip(t, c.Digest())
	want := v["expected_motion_digest"].(map[string]any)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("motion digest mismatch:\n got=%v\nwant=%v", got, want)
	}
}

func TestMotionDigestCountsBreaches(t *testing.T) {
	c := NewMotionCollector(vectorScope())
	// In-envelope.
	_ = c.Record(MotionRecord{ForceN: fptr(10.0), SpeedMps: fptr(0.4), Zone: "cell-3"})
	// Over the force cap.
	_ = c.Record(MotionRecord{ForceN: fptr(120.0), Zone: "cell-3"})
	// Disallowed zone.
	_ = c.Record(MotionRecord{ForceN: fptr(5.0), Zone: "cell-9"})
	d := c.Digest()
	if d["breachCount"].(int) != 2 {
		t.Fatalf("expected 2 breaches, got %v", d["breachCount"])
	}
	if d["zoneBreaches"].(int) != 1 {
		t.Fatalf("expected 1 zone breach, got %v", d["zoneBreaches"])
	}
	if d["withinEnvelope"].(bool) {
		t.Fatal("expected withinEnvelope false after breaches")
	}
}

func TestHeartbeatBuildVerifyRoundTrip(t *testing.T) {
	s := newRobot(t, "did:web:robot.example.com")
	c := NewMotionCollector(vectorScope())
	_ = c.Record(MotionRecord{ForceN: fptr(12.0), SpeedMps: fptr(0.4), Zone: "cell-3"})
	cred, err := BuildRobotHeartbeat(s, BuildHeartbeatOptions{
		SessionID:       "sess-1",
		IntervalIndex:   3,
		MotionDigest:    c.Digest(),
		IntervalSeconds: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(cred["type"], RobotHeartbeatType) {
		t.Fatal("missing RobotHeartbeatCredential type")
	}
	ok, subject := VerifyRobotHeartbeat(cred, s.PublicKeyEd25519())
	if !ok {
		t.Fatal("heartbeat round-trip verify failed")
	}
	if subject["sessionId"] != "sess-1" {
		t.Fatalf("unexpected sessionId: %v", subject["sessionId"])
	}
}

func TestHeartbeatWrongTypeRejected(t *testing.T) {
	s := newRobot(t, "did:web:robot.example.com")
	c := NewMotionCollector(nil)
	_ = c.Record(MotionRecord{ForceN: fptr(1.0)})
	cred, err := BuildRobotHeartbeat(s, BuildHeartbeatOptions{
		SessionID: "x", IntervalIndex: 0, MotionDigest: c.Digest(), IntervalSeconds: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	cred["type"] = []any{"VerifiableCredential"}
	if ok, _ := VerifyRobotHeartbeat(cred, s.PublicKeyEd25519()); ok {
		t.Fatal("expected a non-heartbeat type to be rejected")
	}
}

func TestIsLiveFreshAndInEnvelope(t *testing.T) {
	s := newRobot(t, "did:web:robot.example.com")
	c := NewMotionCollector(vectorScope())
	_ = c.Record(MotionRecord{ForceN: fptr(12.0), SpeedMps: fptr(0.4), Zone: "cell-3"})
	issued := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cred, err := BuildRobotHeartbeat(s, BuildHeartbeatOptions{
		SessionID: "s", IntervalIndex: 0, MotionDigest: c.Digest(), IntervalSeconds: 30, ValidFrom: issued,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Within the grace window: fresh and in-envelope is live.
	live, err := IsLive(cred, IsLiveOptions{Now: issued.Add(45 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if !live {
		t.Fatal("expected a fresh in-envelope heartbeat to be live")
	}

	// Past the grace window (2 * 30s = 60s): stale.
	live, _ = IsLive(cred, IsLiveOptions{Now: issued.Add(120 * time.Second)})
	if live {
		t.Fatal("expected a stale heartbeat to not be live")
	}
}

func TestIsLiveBreachNotLive(t *testing.T) {
	s := newRobot(t, "did:web:robot.example.com")
	c := NewMotionCollector(vectorScope())
	// A breach: force over the 80 N cap.
	_ = c.Record(MotionRecord{ForceN: fptr(120.0), Zone: "cell-3"})
	issued := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cred, err := BuildRobotHeartbeat(s, BuildHeartbeatOptions{
		SessionID: "s", IntervalIndex: 0, MotionDigest: c.Digest(), IntervalSeconds: 30, ValidFrom: issued,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Fresh but out of envelope: not live.
	if live, _ := IsLive(cred, IsLiveOptions{Now: issued.Add(10 * time.Second)}); live {
		t.Fatal("expected an out-of-envelope heartbeat to not be live even when fresh")
	}
}

func jsonRoundTrip(t *testing.T, v map[string]any) map[string]any {
	t.Helper()
	blob, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(blob, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
