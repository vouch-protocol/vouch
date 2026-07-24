// Tests that a robot credential signed with SignPq verifies through the normal
// robot-identity path as well as through the post-quantum-specific verifier.

package robotics

import (
	"testing"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

func mintedRobotIdentity(t *testing.T) (map[string]any, *SoftwareRootOfTrust, *signer.Signer) {
	t.Helper()
	s := newRobot(t, "did:web:robot.example.com")
	root, err := NewSoftwareRoot(filled(7), "TPM")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := MintRobotIdentity(s, root, MintOptions{
		Make: "Acme", Model: "AR-7", Serial: "SN-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return cred, root, s
}

func TestSignPqThenVerifyRobotIdentity(t *testing.T) {
	cred, _, s := mintedRobotIdentity(t)

	signed, err := SignPq(cred, s)
	if err != nil {
		t.Fatal(err)
	}
	if !IsPq(signed) {
		t.Fatal("expected a post-quantum credential")
	}

	ok, subject := VerifyRobotIdentity(signed, s.PublicKeyEd25519(), s.PublicKeyMLDSA44())
	if !ok {
		t.Fatal("a SignPq robot credential must verify through VerifyRobotIdentity")
	}
	if subject["make"] != "Acme" {
		t.Fatalf("unexpected subject: %v", subject)
	}

	// A Multikey string resolves the same way the raw key does.
	mlMultikey, err := s.PublicKeyMLDSA44Multikey()
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := VerifyRobotIdentity(signed, s.PublicKeyEd25519(), mlMultikey); !ok {
		t.Fatal("expected a Multikey ML-DSA-44 argument to verify")
	}
}

func TestVerifyRobotIdentityRejectsTamperedProofSet(t *testing.T) {
	cred, _, s := mintedRobotIdentity(t)

	signed, err := SignPq(cred, s)
	if err != nil {
		t.Fatal(err)
	}
	signed["credentialSubject"].(map[string]any)["make"] = "Evil Corp"

	if ok, _ := VerifyRobotIdentity(signed, s.PublicKeyEd25519(), s.PublicKeyMLDSA44()); ok {
		t.Fatal("expected a tampered proof set to fail through VerifyRobotIdentity")
	}
}

// Without an ML-DSA-44 key a post-quantum robot credential must be reported
// invalid, never accepted on the strength of its Ed25519 proof alone.
func TestVerifyRobotIdentityNeedsMLDSAKeyForProofSet(t *testing.T) {
	cred, _, s := mintedRobotIdentity(t)

	signed, err := SignPq(cred, s)
	if err != nil {
		t.Fatal(err)
	}

	if ok, _ := VerifyRobotIdentity(signed, s.PublicKeyEd25519()); ok {
		t.Fatal("a proof set must not verify without an ML-DSA-44 key")
	}
}

// The classical path is untouched.
func TestVerifyRobotIdentityClassicalUnaffected(t *testing.T) {
	cred, _, s := mintedRobotIdentity(t)

	if ok, _ := VerifyRobotIdentity(cred, s.PublicKeyEd25519()); !ok {
		t.Fatal("expected a classical robot credential to verify with no ML-DSA-44 key")
	}
}
