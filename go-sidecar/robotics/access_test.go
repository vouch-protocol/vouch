package robotics

import (
	"testing"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

var (
	accessT0       = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	accessInWindow = time.Date(2026, 1, 1, 0, 5, 0, 0, time.UTC)
	accessAfter    = time.Date(2026, 1, 1, 2, 0, 0, 0, time.UTC)
)

// TestAccessInteropVectors is the cross-language interop proof: Go authorizes the
// access grant plus request minted by the Python module and pinned in the shared
// interop vector.
func TestAccessInteropVectors(t *testing.T) {
	v := loadVector(t)

	grant := v["access_grant_credential"].(map[string]any)
	request := v["access_request_credential"].(map[string]any)
	operatorPub := ed25519FromJWK(t, v["access_operator_key"].(map[string]any))
	robotPub := ed25519FromJWK(t, v["access_robot_key"].(map[string]any))

	res := AuthorizeAccess(grant, request, operatorPub, robotPub, AuthorizeAccessOptions{Now: accessInWindow})
	if !res.Ok {
		t.Fatalf("expected the Python-minted grant and request to authorize in Go, reasons: %v", res.Reasons)
	}
}

func newAccessGrant(t *testing.T, operator *signer.Signer, robotDID string) map[string]any {
	t.Helper()
	grant, err := BuildAccessGrant(operator, BuildAccessGrantOptions{
		RobotDID:     robotDID,
		Resource:     "door-3",
		Operations:   []string{"open", "close"},
		Zone:         "cell-3",
		ValidSeconds: 3600,
		GrantedAt:    accessT0,
	})
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func TestAccessGrantVerifiesInWindow(t *testing.T) {
	operator := newRobot(t, "did:web:facility-ops.example.com")
	robot := newRobot(t, "did:web:robot-a.example.com")
	grant := newAccessGrant(t, operator, robot.DID())

	ok, subject := VerifyAccessGrant(grant, operator.PublicKeyEd25519(), VerifyAccessGrantOptions{Now: accessInWindow})
	if !ok {
		t.Fatal("expected the grant to verify in window")
	}
	if subject["resource"] != "door-3" {
		t.Fatalf("unexpected resource: %v", subject["resource"])
	}
}

func TestAccessGrantOutOfWindowRejected(t *testing.T) {
	operator := newRobot(t, "did:web:facility-ops.example.com")
	robot := newRobot(t, "did:web:robot-a.example.com")
	grant := newAccessGrant(t, operator, robot.DID())

	if ok, _ := VerifyAccessGrant(grant, operator.PublicKeyEd25519(), VerifyAccessGrantOptions{Now: accessAfter}); ok {
		t.Fatal("expected an out-of-window grant to be rejected")
	}
}

func TestAccessGrantWrongOperatorKeyRejected(t *testing.T) {
	operator := newRobot(t, "did:web:facility-ops.example.com")
	robot := newRobot(t, "did:web:robot-a.example.com")
	stranger := newRobot(t, "did:web:stranger.example.com")
	grant := newAccessGrant(t, operator, robot.DID())

	if ok, _ := VerifyAccessGrant(grant, stranger.PublicKeyEd25519(), VerifyAccessGrantOptions{Now: accessInWindow}); ok {
		t.Fatal("expected a grant checked under the wrong operator key to be rejected")
	}
}

func newAccessRequest(t *testing.T, robot *signer.Signer, operation, resource string) map[string]any {
	t.Helper()
	request, err := BuildAccessRequest(robot, BuildAccessRequestOptions{
		RobotDID:    robot.DID(),
		Resource:    resource,
		Operation:   operation,
		RequestedAt: accessInWindow,
	})
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestAccessPermittedOperationAuthorized(t *testing.T) {
	operator := newRobot(t, "did:web:facility-ops.example.com")
	robot := newRobot(t, "did:web:robot-a.example.com")
	grant := newAccessGrant(t, operator, robot.DID())
	request := newAccessRequest(t, robot, "open", "door-3")

	res := AuthorizeAccess(grant, request, operator.PublicKeyEd25519(), robot.PublicKeyEd25519(), AuthorizeAccessOptions{Now: accessInWindow})
	if !res.Ok {
		t.Fatalf("expected a permitted operation to authorize, reasons: %v", res.Reasons)
	}
	if len(res.Reasons) != 0 {
		t.Fatalf("expected no reasons, got %v", res.Reasons)
	}
}

func TestAccessOperationNotInGrantRefused(t *testing.T) {
	operator := newRobot(t, "did:web:facility-ops.example.com")
	robot := newRobot(t, "did:web:robot-a.example.com")
	grant := newAccessGrant(t, operator, robot.DID())
	request := newAccessRequest(t, robot, "unlock_admin", "door-3")

	res := AuthorizeAccess(grant, request, operator.PublicKeyEd25519(), robot.PublicKeyEd25519(), AuthorizeAccessOptions{Now: accessInWindow})
	if res.Ok {
		t.Fatal("expected an operation outside the grant to be refused")
	}
	if !containsReason(res.Reasons, "operation not permitted by the grant") {
		t.Fatalf("expected the operation reason, got %v", res.Reasons)
	}
}

func TestAccessWrongResourceRefused(t *testing.T) {
	operator := newRobot(t, "did:web:facility-ops.example.com")
	robot := newRobot(t, "did:web:robot-a.example.com")
	grant := newAccessGrant(t, operator, robot.DID())
	request := newAccessRequest(t, robot, "open", "door-9")

	res := AuthorizeAccess(grant, request, operator.PublicKeyEd25519(), robot.PublicKeyEd25519(), AuthorizeAccessOptions{Now: accessInWindow})
	if res.Ok {
		t.Fatal("expected a mismatched resource to be refused")
	}
	if !containsReason(res.Reasons, "grant and request name different resources") {
		t.Fatalf("expected the resource reason, got %v", res.Reasons)
	}
}

func TestAccessOutOfWindowRefused(t *testing.T) {
	operator := newRobot(t, "did:web:facility-ops.example.com")
	robot := newRobot(t, "did:web:robot-a.example.com")
	grant := newAccessGrant(t, operator, robot.DID())
	request := newAccessRequest(t, robot, "open", "door-3")

	res := AuthorizeAccess(grant, request, operator.PublicKeyEd25519(), robot.PublicKeyEd25519(), AuthorizeAccessOptions{Now: accessAfter})
	if res.Ok {
		t.Fatal("expected an out-of-window authorization to be refused")
	}
	if !containsReason(res.Reasons, "grant invalid or out of window") {
		t.Fatalf("expected the window reason, got %v", res.Reasons)
	}
}

func TestAccessRequestFromDifferentRobotRefused(t *testing.T) {
	operator := newRobot(t, "did:web:facility-ops.example.com")
	robot := newRobot(t, "did:web:robot-a.example.com")
	other := newRobot(t, "did:web:robot-b.example.com")
	grant := newAccessGrant(t, operator, robot.DID())
	forged := newAccessRequest(t, other, "open", "door-3")

	res := AuthorizeAccess(grant, forged, operator.PublicKeyEd25519(), other.PublicKeyEd25519(), AuthorizeAccessOptions{Now: accessInWindow})
	if res.Ok {
		t.Fatal("expected a request from a different robot to be refused")
	}
	if !containsReason(res.Reasons, "grant and request name different robots") {
		t.Fatalf("expected the robot-mismatch reason, got %v", res.Reasons)
	}
}

func TestAccessSubGrantMayOnlyNarrow(t *testing.T) {
	operator := newRobot(t, "did:web:facility-ops.example.com")
	robot := newRobot(t, "did:web:robot-a.example.com")
	robotDID := robot.DID()

	parent, err := BuildAccessGrant(operator, BuildAccessGrantOptions{
		RobotDID:     robotDID,
		Resource:     "door-3",
		Operations:   []string{"open", "close"},
		Zone:         "cell-3",
		ValidSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	narrower, err := BuildAccessGrant(operator, BuildAccessGrantOptions{
		RobotDID:     robotDID,
		Resource:     "door-3",
		Operations:   []string{"open"},
		Zone:         "cell-3",
		ValidSeconds: 1800,
	})
	if err != nil {
		t.Fatal(err)
	}
	wider, err := BuildAccessGrant(operator, BuildAccessGrantOptions{
		RobotDID:     robotDID,
		Resource:     "door-3",
		Operations:   []string{"open", "close", "unlock_admin"},
		ValidSeconds: 1800,
	})
	if err != nil {
		t.Fatal(err)
	}
	otherResource, err := BuildAccessGrant(operator, BuildAccessGrantOptions{
		RobotDID:     robotDID,
		Resource:     "door-9",
		Operations:   []string{"open"},
		ValidSeconds: 1800,
	})
	if err != nil {
		t.Fatal(err)
	}

	if !AttenuatesGrant(parent, narrower) {
		t.Fatal("expected a narrower sub-grant to attenuate the parent")
	}
	if AttenuatesGrant(parent, wider) {
		t.Fatal("expected a wider sub-grant to be rejected")
	}
	if AttenuatesGrant(parent, otherResource) {
		t.Fatal("expected a sub-grant on a different resource to be rejected")
	}
}

func containsReason(reasons []string, want string) bool {
	for _, r := range reasons {
		if r == want {
			return true
		}
	}
	return false
}
