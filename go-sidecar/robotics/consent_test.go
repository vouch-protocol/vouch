package robotics

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

var (
	consentT0       = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	consentInWindow = time.Date(2026, 1, 1, 0, 5, 0, 0, time.UTC)
	consentAfter    = time.Date(2026, 1, 1, 2, 0, 0, 0, time.UTC)
)

func consentToken(t *testing.T, bystander *signer.Signer, captureHash, robotDID string) map[string]any {
	t.Helper()
	tok, err := BuildConsentToken(bystander, BuildConsentTokenOptions{
		BystanderDID: bystander.DID(),
		CaptureHash:  captureHash,
		RobotDID:     robotDID,
		ValidSeconds: 3600,
		GrantedAt:    consentT0,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestConsentInteropVector is the cross-language interop proof: Go reproduces the
// capture hash and verifies the bystander-signed consent token and the
// robot-signed consent evidence minted by the Python module and pinned in the
// shared interop vector.
func TestConsentInteropVector(t *testing.T) {
	v := loadVector(t)

	expectedHash := v["expected_consent_capture_hash"].(string)
	if got := HashCapture([]byte("bystander-frame-0")); got != expectedHash {
		t.Fatalf("capture hash = %v, want %v", got, expectedHash)
	}

	token := v["consent_token_credential"].(map[string]any)
	evidence := v["consent_evidence_credential"].(map[string]any)
	robotPub := ed25519FromJWK(t, v["robot_public_key_jwk"].(map[string]any))
	bystanderPub := ed25519FromJWK(t, v["consent_bystander_key"].(map[string]any))

	evidenceSubject := evidence["credentialSubject"].(map[string]any)
	robotDID := evidenceSubject["id"].(string)

	tokOK, tokSubject := VerifyConsentToken(token, bystanderPub, expectedHash, robotDID, consentInWindow)
	if !tokOK {
		t.Fatal("expected the Python-minted consent token to verify in Go")
	}
	if tokSubject["robotDid"] != robotDID {
		t.Fatalf("token robotDid = %v, want %v", tokSubject["robotDid"], robotDID)
	}

	bystanderDID := token["issuer"].(string)
	evOK, evSubject := VerifyConsentEvidence(evidence, robotPub, VerifyConsentEvidenceOptions{
		Capture:       []byte("bystander-frame-0"),
		ConsentTokens: []map[string]any{token},
		BystanderKeys: map[string]ed25519.PublicKey{bystanderDID: bystanderPub},
		Now:           consentInWindow,
	})
	if !evOK {
		t.Fatal("expected the Python-minted consent evidence to verify in Go")
	}
	if evSubject["basis"] != "explicit-consent" {
		t.Fatalf("evidence basis = %v, want explicit-consent", evSubject["basis"])
	}
}

func TestConsentTokenVerifiesForItsCapture(t *testing.T) {
	bystander := newRobot(t, "did:web:person-1.example.com")
	robotDID := "did:web:robot-a.example.com"
	captureHash := HashCapture([]byte("frame-0"))
	token := consentToken(t, bystander, captureHash, robotDID)

	ok, subject := VerifyConsentToken(token, bystander.PublicKeyEd25519(), captureHash, robotDID, consentInWindow)
	if !ok {
		t.Fatal("expected the consent token to verify")
	}
	if subject["robotDid"] != robotDID {
		t.Fatalf("robotDid = %v, want %v", subject["robotDid"], robotDID)
	}
}

func TestConsentTokenRejectedForOtherCapture(t *testing.T) {
	bystander := newRobot(t, "did:web:person-1.example.com")
	robotDID := "did:web:robot-a.example.com"
	token := consentToken(t, bystander, HashCapture([]byte("frame-0")), robotDID)

	if ok, _ := VerifyConsentToken(token, bystander.PublicKeyEd25519(), HashCapture([]byte("different-frame")), robotDID, consentInWindow); ok {
		t.Fatal("expected a token checked against another capture to be rejected")
	}
}

func TestConsentTokenRejectedForOtherRobot(t *testing.T) {
	bystander := newRobot(t, "did:web:person-1.example.com")
	captureHash := HashCapture([]byte("frame-0"))
	token := consentToken(t, bystander, captureHash, "did:web:robot-a.example.com")

	if ok, _ := VerifyConsentToken(token, bystander.PublicKeyEd25519(), captureHash, "did:web:robot-z.example.com", consentInWindow); ok {
		t.Fatal("expected a token checked against another robot to be rejected")
	}
}

func TestConsentTokenOutOfWindowRejected(t *testing.T) {
	bystander := newRobot(t, "did:web:person-1.example.com")
	robotDID := "did:web:robot-a.example.com"
	captureHash := HashCapture([]byte("frame-0"))
	token := consentToken(t, bystander, captureHash, robotDID)

	if ok, _ := VerifyConsentToken(token, bystander.PublicKeyEd25519(), captureHash, robotDID, consentAfter); ok {
		t.Fatal("expected a token checked outside its window to be rejected")
	}
}

func TestExplicitConsentEvidenceVerifies(t *testing.T) {
	bystander := newRobot(t, "did:web:person-1.example.com")
	robot := newRobot(t, "did:web:robot-a.example.com")
	capture := []byte("frame-0")
	captureHash := HashCapture(capture)
	token := consentToken(t, bystander, captureHash, robot.DID())

	ev, err := BuildConsentEvidence(robot, BuildConsentEvidenceOptions{
		RobotDID:      robot.DID(),
		CaptureHash:   captureHash,
		Basis:         "explicit-consent",
		ConsentTokens: []map[string]any{token},
		ValidFrom:     consentT0,
	})
	if err != nil {
		t.Fatal(err)
	}

	ok, subject := VerifyConsentEvidence(ev, robot.PublicKeyEd25519(), VerifyConsentEvidenceOptions{
		Capture:       capture,
		ConsentTokens: []map[string]any{token},
		BystanderKeys: map[string]ed25519.PublicKey{bystander.DID(): bystander.PublicKeyEd25519()},
		Now:           consentInWindow,
	})
	if !ok {
		t.Fatal("expected the explicit-consent evidence to verify")
	}
	if subject["basis"] != "explicit-consent" {
		t.Fatalf("basis = %v, want explicit-consent", subject["basis"])
	}
}

func TestExplicitConsentRequiresAToken(t *testing.T) {
	robot := newRobot(t, "did:web:robot-a.example.com")
	if _, err := BuildConsentEvidence(robot, BuildConsentEvidenceOptions{
		RobotDID:    robot.DID(),
		CaptureHash: HashCapture([]byte("frame-0")),
		Basis:       "explicit-consent",
		ValidFrom:   consentT0,
	}); err == nil {
		t.Fatal("expected explicit-consent without a token to be rejected at build")
	}
}

func TestRedactedBasisNeedsNoToken(t *testing.T) {
	robot := newRobot(t, "did:web:robot-a.example.com")
	capture := []byte("frame-0")
	ev, err := BuildConsentEvidence(robot, BuildConsentEvidenceOptions{
		RobotDID:      robot.DID(),
		CaptureHash:   HashCapture(capture),
		Basis:         "redacted",
		RedactionHash: HashCapture([]byte("blurred-frame")),
		ValidFrom:     consentT0,
	})
	if err != nil {
		t.Fatal(err)
	}

	ok, subject := VerifyConsentEvidence(ev, robot.PublicKeyEd25519(), VerifyConsentEvidenceOptions{Capture: capture})
	if !ok {
		t.Fatal("expected the redacted-basis evidence to verify")
	}
	if subject["basis"] != "redacted" {
		t.Fatalf("basis = %v, want redacted", subject["basis"])
	}
}

func TestConsentWrongCaptureRejected(t *testing.T) {
	robot := newRobot(t, "did:web:robot-a.example.com")
	ev, err := BuildConsentEvidence(robot, BuildConsentEvidenceOptions{
		RobotDID:    robot.DID(),
		CaptureHash: HashCapture([]byte("frame-0")),
		Basis:       "posted-notice",
		ValidFrom:   consentT0,
	})
	if err != nil {
		t.Fatal(err)
	}

	if ok, _ := VerifyConsentEvidence(ev, robot.PublicKeyEd25519(), VerifyConsentEvidenceOptions{Capture: []byte("a-different-capture")}); ok {
		t.Fatal("expected evidence checked against a different capture to be rejected")
	}
}

func TestConsentUnknownBasisRejectedAtBuild(t *testing.T) {
	robot := newRobot(t, "did:web:robot-a.example.com")
	if _, err := BuildConsentEvidence(robot, BuildConsentEvidenceOptions{
		RobotDID:    robot.DID(),
		CaptureHash: HashCapture([]byte("frame-0")),
		Basis:       "whatever",
		ValidFrom:   consentT0,
	}); err == nil {
		t.Fatal("expected an unknown basis to be rejected at build")
	}
}

func TestConsentTokenForAnotherCaptureDoesNotSatisfyEvidence(t *testing.T) {
	bystander := newRobot(t, "did:web:person-1.example.com")
	robot := newRobot(t, "did:web:robot-a.example.com")
	capture := []byte("frame-0")
	captureHash := HashCapture(capture)

	stray := consentToken(t, bystander, HashCapture([]byte("other-capture")), robot.DID())
	ev, err := BuildConsentEvidence(robot, BuildConsentEvidenceOptions{
		RobotDID:      robot.DID(),
		CaptureHash:   captureHash,
		Basis:         "explicit-consent",
		ConsentTokens: []map[string]any{stray},
		ValidFrom:     consentT0,
	})
	if err != nil {
		t.Fatal(err)
	}

	// The stray token is committed, but it is bound to a different capture, so
	// verifying it against this evidence's capture fails.
	if ok, _ := VerifyConsentEvidence(ev, robot.PublicKeyEd25519(), VerifyConsentEvidenceOptions{
		Capture:       capture,
		ConsentTokens: []map[string]any{stray},
		BystanderKeys: map[string]ed25519.PublicKey{bystander.DID(): bystander.PublicKeyEd25519()},
		Now:           consentInWindow,
	}); ok {
		t.Fatal("expected a token bound to another capture not to satisfy the evidence")
	}
}
