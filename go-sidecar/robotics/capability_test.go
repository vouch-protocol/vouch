package robotics

import (
	"encoding/json"
	"testing"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

func fptr(v float64) *float64 { return &v }

// buildScope mints a representative PhysicalCapabilityScope and returns its inner
// physicalScope object.
func buildScope(t *testing.T) map[string]any {
	t.Helper()
	s := newRobot(t, "did:web:fleet.example.com")
	cred, err := BuildPhysicalScopeCredential(s, BuildPhysicalScopeOptions{
		SubjectDID:            "did:web:robot.example.com",
		MaxForceN:             fptr(80),
		MaxSpeedMps:           fptr(2.0),
		MaxSpeedNearHumansMps: fptr(0.5),
		AllowedZones:          []string{"warehouse-a", "dock-3"},
		ShiftWindows:          []ShiftWindow{{Start: "08:00", End: "18:00"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	subj, _ := cred["credentialSubject"].(map[string]any)
	scope, ok := subj["physicalScope"].(map[string]any)
	if !ok {
		t.Fatal("credential missing physicalScope")
	}
	return scope
}

func TestBuildVerifyPhysicalScope(t *testing.T) {
	s := newRobot(t, "did:web:fleet.example.com")
	cred, err := BuildPhysicalScopeCredential(s, BuildPhysicalScopeOptions{
		SubjectDID: "did:web:robot.example.com",
		MaxForceN:  fptr(80),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(cred["type"], PhysicalScopeType) {
		t.Fatal("missing PhysicalCapabilityScope type")
	}
	ok, err := signer.VerifyDataIntegrityProof(cred, s.PublicKeyEd25519())
	if err != nil || !ok {
		t.Fatalf("scope credential did not verify: ok=%v err=%v", ok, err)
	}
}

func TestCheckPhysicalAction(t *testing.T) {
	scope := buildScope(t)

	if r := CheckPhysicalAction(scope, PhysicalAction{ForceN: fptr(50), SpeedMps: fptr(1.5), Zone: "warehouse-a", TimeHm: "09:30"}); !r.OK {
		t.Fatalf("expected within-scope action to pass: %v", r.Reasons)
	}
	if r := CheckPhysicalAction(scope, PhysicalAction{ForceN: fptr(120)}); r.OK {
		t.Fatal("expected force over the cap to fail")
	}
	// Near humans the tighter 0.5 m/s cap applies; 1.5 m/s is fine far from
	// humans but not near them.
	if r := CheckPhysicalAction(scope, PhysicalAction{SpeedMps: fptr(1.5), NearHumans: true}); r.OK {
		t.Fatal("expected near-humans speed over 0.5 m/s to fail")
	}
	if r := CheckPhysicalAction(scope, PhysicalAction{SpeedMps: fptr(1.5), NearHumans: false}); !r.OK {
		t.Fatalf("expected 1.5 m/s away from humans to pass: %v", r.Reasons)
	}
	if r := CheckPhysicalAction(scope, PhysicalAction{Zone: "loading-bay-9"}); r.OK {
		t.Fatal("expected a disallowed zone to fail")
	}
	if r := CheckPhysicalAction(scope, PhysicalAction{TimeHm: "23:00"}); r.OK {
		t.Fatal("expected a time outside the shift window to fail")
	}
}

func TestAttenuates(t *testing.T) {
	parent := map[string]any{
		"maxForceN":             80.0,
		"maxSpeedMps":           2.0,
		"maxSpeedNearHumansMps": 0.5,
		"allowedZones":          []any{"warehouse-a", "dock-3"},
		"shiftWindows":          []any{map[string]any{"start": "08:00", "end": "18:00"}},
	}

	narrower := map[string]any{
		"maxForceN":             50.0,
		"maxSpeedMps":           1.0,
		"maxSpeedNearHumansMps": 0.3,
		"allowedZones":          []any{"warehouse-a"},
		"shiftWindows":          []any{map[string]any{"start": "09:00", "end": "17:00"}},
	}
	if !Attenuates(parent, narrower) {
		t.Fatal("a strictly narrower child should attenuate")
	}

	broaderForce := map[string]any{"maxForceN": 100.0, "maxSpeedMps": 1.0, "maxSpeedNearHumansMps": 0.3, "allowedZones": []any{"warehouse-a"}}
	if Attenuates(parent, broaderForce) {
		t.Fatal("a child with a higher force cap must not attenuate")
	}

	missingCap := map[string]any{"maxForceN": 50.0, "allowedZones": []any{"warehouse-a"}}
	if Attenuates(parent, missingCap) {
		t.Fatal("a child missing a parent cap must not attenuate")
	}

	newZone := map[string]any{"maxForceN": 50.0, "maxSpeedMps": 1.0, "maxSpeedNearHumansMps": 0.3, "allowedZones": []any{"loading-bay-9"}}
	if Attenuates(parent, newZone) {
		t.Fatal("a child introducing a zone outside the parent set must not attenuate")
	}

	wideWindow := map[string]any{
		"maxForceN": 50.0, "maxSpeedMps": 1.0, "maxSpeedNearHumansMps": 0.3,
		"allowedZones": []any{"warehouse-a"},
		"shiftWindows": []any{map[string]any{"start": "06:00", "end": "20:00"}},
	}
	if Attenuates(parent, wideWindow) {
		t.Fatal("a child window wider than every parent window must not attenuate")
	}
}

// TestCheckAfterJSONRoundTrip exercises the realistic cross-language path: a scope
// serialized to JSON and decoded (numbers become float64, arrays []any of
// map[string]any), exactly as it arrives after a Python- or TypeScript-issued
// credential is verified in Go. Check and Attenuates must behave identically.
func TestCheckAfterJSONRoundTrip(t *testing.T) {
	scope := buildScope(t)
	blob, err := json.Marshal(scope)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatal(err)
	}

	if r := CheckPhysicalAction(decoded, PhysicalAction{SpeedMps: fptr(0.4), NearHumans: true, Zone: "dock-3", TimeHm: "10:00"}); !r.OK {
		t.Fatalf("decoded scope should still pass a valid action: %v", r.Reasons)
	}
	if r := CheckPhysicalAction(decoded, PhysicalAction{ForceN: fptr(200)}); r.OK {
		t.Fatal("decoded scope should still reject an over-force action")
	}

	narrower := map[string]any{
		"maxForceN": 40.0, "maxSpeedMps": 1.0, "maxSpeedNearHumansMps": 0.3,
		"allowedZones": []any{"dock-3"},
		"shiftWindows": []any{map[string]any{"start": "09:00", "end": "12:00"}},
	}
	if !Attenuates(decoded, narrower) {
		t.Fatal("attenuation check must work on a JSON-decoded parent scope")
	}
}
