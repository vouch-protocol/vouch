package robotics

import (
	"testing"
	"time"
)

func f64(v float64) *float64 { return &v }

// TestVerifyLeaseInteropVector is the cross-language interop proof for the lease:
// Go verifies the DelegationLeaseCredential signed by the Python module and pinned
// in the shared interop vector.
func TestVerifyLeaseInteropVector(t *testing.T) {
	v := loadVector(t)
	pub := ed25519FromJWK(t, v["robot_public_key_jwk"].(map[string]any))
	cred := v["delegation_lease_credential"].(map[string]any)
	ok, subject := VerifyDelegationLease(cred, pub, VerifyLeaseOptions{})
	if !ok {
		t.Fatal("expected the Python-signed lease interop vector to verify in Go")
	}
	if subject["leaseId"] != "lease-vector-1" {
		t.Fatalf("unexpected leaseId: %v", subject["leaseId"])
	}
}

// TestVerifyQuorumInteropVector is the cross-language interop proof for the quorum:
// Go authorizes the action from the Python-signed approvals pinned in the vector.
func TestVerifyQuorumInteropVector(t *testing.T) {
	v := loadVector(t)
	actionID := v["quorum_action_id"].(string)

	rawApprovals := v["quorum_approvals"].([]any)
	approvals := make([]map[string]any, len(rawApprovals))
	for i, a := range rawApprovals {
		approvals[i] = a.(map[string]any)
	}

	keys := map[string]any{}
	for did, jwk := range v["quorum_approver_keys"].(map[string]any) {
		keys[did] = jwk
	}

	authorized, approvers, err := VerifyActionAuthorization(approvals, VerifyAuthorizationOptions{
		ActionID:     actionID,
		RobotDID:     "did:web:robot.example.com",
		ApproverKeys: keys,
		Threshold:    2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !authorized {
		t.Fatal("expected the Python-signed quorum interop vector to authorize in Go")
	}
	if len(approvers) != 2 {
		t.Fatalf("expected 2 distinct approvers, got %d: %v", len(approvers), approvers)
	}
}

func TestLeaseRoundTrip(t *testing.T) {
	s := newRobot(t, "did:web:robot.example.com")
	cred, err := BuildDelegationLease(s, BuildLeaseOptions{
		RobotDID:     "did:web:robot.example.com",
		LeaseID:      "lease-1",
		Scope:        vectorScope(),
		ValidSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	ok, subject := VerifyDelegationLease(cred, s.PublicKeyEd25519(), VerifyLeaseOptions{})
	if !ok {
		t.Fatal("round-trip lease verify failed")
	}

	// An action within scope is permitted; one over force is not.
	if !LeasePermits(subject, PhysicalAction{ForceN: f64(50)}, cred, LeasePermitsOptions{}) {
		t.Fatal("expected an in-scope action to be permitted")
	}
	if LeasePermits(subject, PhysicalAction{ForceN: f64(200)}, cred, LeasePermitsOptions{}) {
		t.Fatal("expected an over-force action to be denied")
	}
}

func TestLeaseExpired(t *testing.T) {
	s := newRobot(t, "did:web:robot.example.com")
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cred, err := BuildDelegationLease(s, BuildLeaseOptions{
		RobotDID:     "did:web:robot.example.com",
		LeaseID:      "lease-exp",
		Scope:        vectorScope(),
		ValidSeconds: 60,
		ValidFrom:    start,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Past the window.
	if ok, _ := VerifyDelegationLease(cred, s.PublicKeyEd25519(), VerifyLeaseOptions{Now: start.Add(120 * time.Second)}); ok {
		t.Fatal("expected an expired lease to fail verification")
	}
}

func TestLeaseNotYetValid(t *testing.T) {
	s := newRobot(t, "did:web:robot.example.com")
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cred, err := BuildDelegationLease(s, BuildLeaseOptions{
		RobotDID:     "did:web:robot.example.com",
		LeaseID:      "lease-future",
		Scope:        vectorScope(),
		ValidSeconds: 60,
		ValidFrom:    start,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Before the window opens.
	if ok, _ := VerifyDelegationLease(cred, s.PublicKeyEd25519(), VerifyLeaseOptions{Now: start.Add(-60 * time.Second)}); ok {
		t.Fatal("expected a not-yet-valid lease to fail verification")
	}
}

func TestSubLeaseAttenuationAccept(t *testing.T) {
	s := newRobot(t, "did:web:robot.example.com")
	parent := vectorScope()
	// A narrower child: lower force, same zone subset.
	child := map[string]any{
		"maxForceN":             40.0,
		"maxSpeedMps":           1.0,
		"maxSpeedNearHumansMps": 0.25,
		"allowedZones":          []any{"cell-3"},
	}
	cred, err := BuildDelegationLease(s, BuildLeaseOptions{
		RobotDID:      "did:web:robot.example.com",
		LeaseID:       "sub-lease-1",
		Scope:         child,
		ValidSeconds:  3600,
		ParentLeaseID: "lease-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	ok, subject := VerifyDelegationLease(cred, s.PublicKeyEd25519(), VerifyLeaseOptions{ParentScope: parent})
	if !ok {
		t.Fatal("expected a properly attenuated sub-lease to verify")
	}
	if subject["parentLeaseId"] != "lease-1" {
		t.Fatalf("unexpected parentLeaseId: %v", subject["parentLeaseId"])
	}
}

func TestSubLeaseAttenuationReject(t *testing.T) {
	s := newRobot(t, "did:web:robot.example.com")
	parent := vectorScope()
	// A broader child (higher force, and a zone the parent never granted): not a
	// valid attenuation.
	child := map[string]any{
		"maxForceN":    500.0,
		"allowedZones": []any{"cell-3", "cell-9"},
	}
	cred, err := BuildDelegationLease(s, BuildLeaseOptions{
		RobotDID:      "did:web:robot.example.com",
		LeaseID:       "sub-lease-bad",
		Scope:         child,
		ValidSeconds:  3600,
		ParentLeaseID: "lease-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := VerifyDelegationLease(cred, s.PublicKeyEd25519(), VerifyLeaseOptions{ParentScope: parent}); ok {
		t.Fatal("expected a widening sub-lease to fail attenuation")
	}
}

// quorumSetup builds three approvers and an approval each over the same action.
func quorumSetup(t *testing.T, action, robot string) (map[string]any, []map[string]any) {
	t.Helper()
	dids := []string{
		"did:web:a1.example.com",
		"did:web:a2.example.com",
		"did:web:a3.example.com",
	}
	keys := map[string]any{}
	var approvals []map[string]any
	for _, did := range dids {
		s := newRobot(t, did)
		approval, err := BuildActionApproval(s, BuildApprovalOptions{ActionID: action, RobotDID: robot})
		if err != nil {
			t.Fatal(err)
		}
		keys[did] = s.PublicKeyEd25519()
		approvals = append(approvals, approval)
	}
	return keys, approvals
}

func TestQuorumThresholdNotMet(t *testing.T) {
	keys, approvals := quorumSetup(t, "act-1", "did:web:robot.example.com")
	// Threshold 4 over only 3 approvers cannot be met.
	authorized, _, err := VerifyActionAuthorization(approvals, VerifyAuthorizationOptions{
		ActionID:     "act-1",
		RobotDID:     "did:web:robot.example.com",
		ApproverKeys: keys,
		Threshold:    4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if authorized {
		t.Fatal("expected the action to be unauthorized below threshold")
	}
}

func TestQuorumDuplicateCountsOnce(t *testing.T) {
	keys, approvals := quorumSetup(t, "act-2", "did:web:robot.example.com")
	// Submit the first approver twice plus the second: two distinct approvers.
	dupd := []map[string]any{approvals[0], approvals[0], approvals[1]}
	authorized, approvers, err := VerifyActionAuthorization(dupd, VerifyAuthorizationOptions{
		ActionID:     "act-2",
		RobotDID:     "did:web:robot.example.com",
		ApproverKeys: keys,
		Threshold:    2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !authorized || len(approvers) != 2 {
		t.Fatalf("expected 2 distinct approvers, got authorized=%v approvers=%v", authorized, approvers)
	}

	// The same duplicated set cannot satisfy a threshold of 3.
	if a, _, _ := VerifyActionAuthorization(dupd, VerifyAuthorizationOptions{
		ActionID: "act-2", RobotDID: "did:web:robot.example.com", ApproverKeys: keys, Threshold: 3,
	}); a {
		t.Fatal("expected duplicated approver not to count twice toward threshold 3")
	}
}

func TestQuorumApproverOutsideSetIgnored(t *testing.T) {
	keys, approvals := quorumSetup(t, "act-3", "did:web:robot.example.com")
	// Only the first two approvers are in the attested set.
	set := map[string]bool{
		"did:web:a1.example.com": true,
		"did:web:a2.example.com": true,
	}
	authorized, approvers, err := VerifyActionAuthorization(approvals, VerifyAuthorizationOptions{
		ActionID:     "act-3",
		RobotDID:     "did:web:robot.example.com",
		ApproverKeys: keys,
		Threshold:    2,
		ApproverSet:  set,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !authorized || len(approvers) != 2 {
		t.Fatalf("expected 2 in-set approvers, got authorized=%v approvers=%v", authorized, approvers)
	}
	for _, did := range approvers {
		if did == "did:web:a3.example.com" {
			t.Fatal("expected the out-of-set approver to be ignored")
		}
	}

	// With the third also required, the out-of-set approver cannot lift it to 3.
	if a, _, _ := VerifyActionAuthorization(approvals, VerifyAuthorizationOptions{
		ActionID: "act-3", RobotDID: "did:web:robot.example.com", ApproverKeys: keys, Threshold: 3, ApproverSet: set,
	}); a {
		t.Fatal("expected an out-of-set approver to be excluded from the count")
	}
}

func TestQuorumRejectNotCounted(t *testing.T) {
	a1 := newRobot(t, "did:web:a1.example.com")
	a2 := newRobot(t, "did:web:a2.example.com")
	approve, err := BuildActionApproval(a1, BuildApprovalOptions{ActionID: "act-4", RobotDID: "did:web:robot.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	reject, err := BuildActionApproval(a2, BuildApprovalOptions{ActionID: "act-4", RobotDID: "did:web:robot.example.com", Decision: Reject})
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]any{
		"did:web:a1.example.com": a1.PublicKeyEd25519(),
		"did:web:a2.example.com": a2.PublicKeyEd25519(),
	}
	authorized, approvers, err := VerifyActionAuthorization([]map[string]any{approve, reject}, VerifyAuthorizationOptions{
		ActionID:     "act-4",
		RobotDID:     "did:web:robot.example.com",
		ApproverKeys: keys,
		Threshold:    2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if authorized {
		t.Fatal("expected a reject not to count toward the quorum")
	}
	if len(approvers) != 1 {
		t.Fatalf("expected only the single approve to count, got %v", approvers)
	}
}
