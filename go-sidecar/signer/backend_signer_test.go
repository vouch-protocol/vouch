// Tests for backend signing: the Ed25519 key lives outside the Signer and a
// callback produces the signature. Mirrors the Python tests in
// tests/test_secure_key_custody.py.

package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestNewBackendSignsAndVerifies(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	calls := 0
	sign := func(digest []byte) []byte {
		calls++
		return ed25519.Sign(priv, digest)
	}

	s, err := NewBackend("did:web:agent.example.com", pub, sign, 300)
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}

	cred, err := s.Sign(SignOptions{
		Action:   "read",
		Target:   "t",
		Resource: "https://api.example.com/v1/users",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected the sign callback to be used once, got %d", calls)
	}

	ok, err := VerifyDataIntegrityProof(cred, pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("backend-signed credential failed verification")
	}
}

func TestNewBackendRejectsBadInput(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	_, _ = rand.Read(seed)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	sign := func(d []byte) []byte { return nil }

	if _, err := NewBackend("", pub, sign, 0); err == nil {
		t.Fatal("expected error for empty DID")
	}
	if _, err := NewBackend("did:web:x", []byte{1, 2, 3}, sign, 0); err == nil {
		t.Fatal("expected error for short public key")
	}
	if _, err := NewBackend("did:web:x", pub, nil, 0); err == nil {
		t.Fatal("expected error for nil sign callback")
	}
}

func TestBackendSignerBlocksCompositeAndHybrid(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	_, _ = rand.Read(seed)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	s, err := NewBackend("did:web:x", pub, func(d []byte) []byte { return ed25519.Sign(priv, d) }, 0)
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}

	if _, err := s.SignToken(SignRequest{}); err == nil {
		t.Fatal("expected composite Sign to be blocked for a backend Signer")
	}
	if _, err := s.SignHybrid(SignOptions{
		Action: "a", Target: "b", Resource: "c",
	}); err == nil {
		t.Fatal("expected hybrid to be blocked for a backend Signer")
	}
}

func TestBuildProofRequiresKeyOrCallback(t *testing.T) {
	cred, err := BuildVouchCredential(BuildVouchCredentialOptions{
		IssuerDID: "did:web:x",
		Intent: map[string]any{
			"action": "a", "target": "b", "resource": "https://x/r",
		},
	})
	if err != nil {
		t.Fatalf("BuildVouchCredential: %v", err)
	}
	if _, err := BuildDataIntegrityProof(cred, BuildProofOptions{VerificationMethod: "did:web:x#key-1"}); err == nil {
		t.Fatal("expected error when neither PrivateKey nor Sign is set")
	}
}
