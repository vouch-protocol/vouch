package robotics

import (
	"strings"
	"testing"
	"time"
)

func buildSamplePassport(t *testing.T) (map[string]any, []byte) {
	t.Helper()
	robot := newRobot(t, "did:web:robot.example.com")
	pass, err := BuildPassport(robot, BuildPassportOptions{
		RobotDID:          "did:web:robot.example.com",
		Make:              "Acme Robotics",
		Model:             "AR-7",
		Owner:             "did:web:owner.example.com",
		AuthorizedActions: []string{"lift", "carry"},
		Certification:     "ISO-10218",
	})
	if err != nil {
		t.Fatal(err)
	}
	return pass, robot.PublicKeyEd25519()
}

func TestPassportBuildVerify(t *testing.T) {
	pass, pub := buildSamplePassport(t)
	ok, summary := VerifyPassport(pass, pub, time.Time{})
	if !ok {
		t.Fatal("passport should verify")
	}
	if summary.Owner != "did:web:owner.example.com" || summary.Make != "Acme Robotics" {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	if len(summary.AuthorizedActions) != 2 || summary.AuthorizedActions[0] != "lift" {
		t.Fatalf("unexpected actions: %v", summary.AuthorizedActions)
	}
	if summary.Status != StatusActive {
		t.Fatalf("default status should be active, got %s", summary.Status)
	}
}

// TestPassportEncodeDecodeVerify is the offline-scan path and the cross-language
// shape check in one: encode to a vouch-passport: URI, decode it (JSON-decoded,
// so authorizedActions is []any), and verify the decoded form.
func TestPassportEncodeDecodeVerify(t *testing.T) {
	pass, pub := buildSamplePassport(t)
	uri, err := EncodePassport(pass)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(uri, PassportURIScheme+"u") {
		t.Fatalf("URI missing scheme/multibase prefix: %s", uri[:20])
	}
	decoded, err := DecodePassport(uri)
	if err != nil {
		t.Fatal(err)
	}
	ok, summary := VerifyPassport(decoded, pub, time.Time{})
	if !ok {
		t.Fatal("decoded passport should verify")
	}
	if len(summary.AuthorizedActions) != 2 {
		t.Fatalf("actions lost across decode: %v", summary.AuthorizedActions)
	}
	// And the convenience URI verifier agrees.
	if ok, _ := VerifyPassportURI(uri, pub, time.Time{}); !ok {
		t.Fatal("VerifyPassportURI should verify a freshly encoded passport")
	}
}

func TestPassportExpired(t *testing.T) {
	robot := newRobot(t, "did:web:robot.example.com")
	issued := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pass, err := BuildPassport(robot, BuildPassportOptions{
		RobotDID: "did:web:robot.example.com", Make: "Acme", Model: "AR-7",
		Owner: "did:web:owner.example.com", AuthorizedActions: []string{"lift"},
		ValidSeconds: 60, ValidFrom: issued,
	})
	if err != nil {
		t.Fatal(err)
	}
	pub := robot.PublicKeyEd25519()
	// Within the window: valid.
	if ok, _ := VerifyPassport(pass, pub, issued.Add(30*time.Second)); !ok {
		t.Fatal("passport should be valid inside its window")
	}
	// Past validUntil: expired.
	if ok, _ := VerifyPassport(pass, pub, issued.Add(120*time.Second)); ok {
		t.Fatal("expired passport should fail")
	}
}

func TestPassportSuspendedStillVerifies(t *testing.T) {
	robot := newRobot(t, "did:web:robot.example.com")
	pass, err := BuildPassport(robot, BuildPassportOptions{
		RobotDID: "did:web:robot.example.com", Make: "Acme", Model: "AR-7",
		Owner: "did:web:owner.example.com", AuthorizedActions: []string{"lift"},
		Status: StatusSuspended,
	})
	if err != nil {
		t.Fatal(err)
	}
	ok, summary := VerifyPassport(pass, robot.PublicKeyEd25519(), time.Time{})
	if !ok {
		t.Fatal("a suspended passport still verifies (status surfaced, not rejected)")
	}
	if summary.Status != StatusSuspended {
		t.Fatalf("status should be surfaced as suspended, got %s", summary.Status)
	}
}

func TestPassportTamperRejected(t *testing.T) {
	pass, pub := buildSamplePassport(t)
	// Change the owner after signing.
	pass["credentialSubject"].(map[string]any)["owner"] = "did:web:attacker.example.com"
	if ok, _ := VerifyPassport(pass, pub, time.Time{}); ok {
		t.Fatal("a tampered passport must fail verification")
	}
}

func TestPassportWrongTypeRejected(t *testing.T) {
	pass, pub := buildSamplePassport(t)
	pass["type"] = []any{"VerifiableCredential"}
	if ok, _ := VerifyPassport(pass, pub, time.Time{}); ok {
		t.Fatal("a non-passport type must be rejected")
	}
}

func TestDecodePassportRejectsBadURI(t *testing.T) {
	if _, err := DecodePassport("https://example.com/not-a-passport"); err == nil {
		t.Fatal("expected a non-vouch-passport URI to be rejected")
	}
}
