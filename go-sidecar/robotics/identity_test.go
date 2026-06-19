package robotics

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

func loadVector(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "test-vectors", "robotics", "vector.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v map[string]any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	return v
}

func ed25519FromJWK(t *testing.T, jwk map[string]any) ed25519.PublicKey {
	t.Helper()
	x, _ := jwk["x"].(string)
	raw, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		t.Fatalf("decode jwk x: %v", err)
	}
	return ed25519.PublicKey(raw)
}

func newRobot(t *testing.T, did string) *signer.Signer {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	s, err := signer.New(signer.Config{DID: did, Ed25519Seed: seed})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func filled(b byte) []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = b
	}
	return s
}

// TestVerifyInteropVector is the cross-language interop proof: Go verifies the
// RobotIdentityCredential minted by the Python module and pinned in the shared
// interop vector.
func TestVerifyInteropVector(t *testing.T) {
	v := loadVector(t)
	pub := ed25519FromJWK(t, v["robot_public_key_jwk"].(map[string]any))
	cred := v["robot_identity_credential"].(map[string]any)
	ok, subject := VerifyRobotIdentity(cred, pub)
	if !ok {
		t.Fatal("expected the Python-minted interop vector to verify in Go")
	}
	if subject["make"] != "Acme Robotics" {
		t.Fatalf("unexpected make: %v", subject["make"])
	}
}

func TestMintVerifyRoundTrip(t *testing.T) {
	s := newRobot(t, "did:web:robot.example.com")
	root, err := NewSoftwareRoot(filled(7), "TPM")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := MintRobotIdentity(s, root, MintOptions{
		Make: "Acme", Model: "AR-7", Serial: "SN-1", Owner: "did:web:owner.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	ok, _ := VerifyRobotIdentity(cred, s.PublicKeyEd25519())
	if !ok {
		t.Fatal("round-trip verify failed")
	}
}

func TestForgedHardwareRootFails(t *testing.T) {
	s := newRobot(t, "did:web:robot.example.com")
	root, _ := NewSoftwareRoot(filled(7), "TPM")
	cred, err := MintRobotIdentity(s, root, MintOptions{Make: "A", Model: "B", Serial: "C"})
	if err != nil {
		t.Fatal(err)
	}

	// Point the hardware-root key at an attacker's; the attestation, signed by
	// the real root over the binding, no longer verifies.
	attacker, _ := NewSoftwareRoot(filled(9), "TPM")
	amb, _ := attacker.PublicKeyMultibase()
	hw := cred["credentialSubject"].(map[string]any)["hardwareRoot"].(map[string]any)
	hw["publicKeyMultibase"] = amb
	// Re-sign the credential proof so only the hardware attestation is wrong.
	delete(cred, "proof")
	resigned, err := s.AttachProof(cred)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := VerifyRobotIdentity(resigned, s.PublicKeyEd25519()); ok {
		t.Fatal("expected a forged hardware root to fail verification")
	}
}
