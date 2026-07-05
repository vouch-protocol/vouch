package signer

import (
	"testing"
	"time"
)

func TestGenerateIdentityDidWeb(t *testing.T) {
	id, err := GenerateIdentity("agent.example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if id.DID != "did:web:agent.example.com" {
		t.Fatalf("unexpected DID: %s", id.DID)
	}
	if len(id.Seed) != 32 {
		t.Fatalf("expected 32-byte seed, got %d", len(id.Seed))
	}
}

func TestGenerateIdentityDidKey(t *testing.T) {
	id, err := GenerateIdentity("")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if !IsDIDKey(id.DID) {
		t.Fatalf("expected a did:key, got %s", id.DID)
	}
	pub, err := Ed25519FromDIDKey(id.DID)
	if err != nil {
		t.Fatalf("Ed25519FromDIDKey: %v", err)
	}
	if string(pub) != string(id.PublicKey) {
		t.Fatal("decoded did:key public key does not match the original")
	}
}

func TestVerifyCredentialWithExplicitKeyAndTimeWindow(t *testing.T) {
	id, err := GenerateIdentity("agent.example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	s, err := New(Config{DID: id.DID, Ed25519Seed: id.Seed, DefaultExpirySeconds: 300})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cred, err := s.Sign(SignOptions{
		Action: "read", Target: "t", Resource: "https://x/y",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	ok, passport, err := VerifyCredential(cred, id.PublicKey, formatISO8601(time.Now()), 30)
	if err != nil {
		t.Fatalf("VerifyCredential: %v", err)
	}
	if !ok {
		t.Fatal("expected valid credential")
	}
	if passport.Action() != "read" || passport.Resource() != "https://x/y" {
		t.Fatalf("unexpected passport intent: %+v", passport.Intent)
	}
	if passport.Issuer != id.DID {
		t.Fatalf("unexpected issuer: %s", passport.Issuer)
	}
}

func TestVerifyResolvesDidKeyOffline(t *testing.T) {
	id, err := GenerateIdentity("") // did:key
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	s, err := New(Config{DID: id.DID, Ed25519Seed: id.Seed, DefaultExpirySeconds: 300})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cred, err := s.Sign(SignOptions{
		Action: "write", Target: "t", Resource: "r",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	ok, passport, err := Verify(cred, nil, 30)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok || passport.Issuer != id.DID {
		t.Fatalf("expected did:key to resolve offline and verify; ok=%v", ok)
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	a, _ := GenerateIdentity("a.example.com")
	b, _ := GenerateIdentity("b.example.com")
	sa, _ := New(Config{DID: a.DID, Ed25519Seed: a.Seed, DefaultExpirySeconds: 300})
	cred, err := sa.Sign(SignOptions{Action: "read", Target: "t", Resource: "https://x/y"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ok, _, err := VerifyCredential(cred, b.PublicKey, formatISO8601(time.Now()), 30)
	if err != nil {
		t.Fatalf("VerifyCredential: %v", err)
	}
	if ok {
		t.Fatal("expected verification with the wrong key to fail")
	}
}
