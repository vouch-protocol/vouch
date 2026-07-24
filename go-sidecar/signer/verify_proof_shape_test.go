// Tests that the generic verification path dispatches on proof shape, so a
// post-quantum credential carrying a proof set verifies the same way a
// classical one does.

package signer

import (
	"errors"
	"testing"
	"time"
)

func TestVerifyCredentialAcceptsProofSet(t *testing.T) {
	s := newTestSigner(t, "")
	cred, err := s.SignHybrid(SignOptions{Intent: validIntent()})
	if err != nil {
		t.Fatal(err)
	}

	ok, passport, err := VerifyCredential(
		cred, s.PublicKeyEd25519(), formatISO8601(time.Now()), 30, s.PublicKeyMLDSA44(),
	)
	if err != nil {
		t.Fatalf("VerifyCredential: %v", err)
	}
	if !ok {
		t.Fatal("expected a post-quantum credential to verify through the generic path")
	}
	if passport.Issuer != s.DID() {
		t.Fatalf("unexpected issuer: %s", passport.Issuer)
	}
}

func TestVerifyAcceptsProofSet(t *testing.T) {
	s := newTestSigner(t, "")
	cred, err := s.SignHybrid(SignOptions{Intent: validIntent()})
	if err != nil {
		t.Fatal(err)
	}

	ok, _, err := Verify(cred, s.PublicKeyEd25519(), 30, s.PublicKeyMLDSA44())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("expected a post-quantum credential to verify through Verify")
	}
}

// A tampered proof-set credential must fail through the generic path.
func TestVerifyCredentialRejectsTamperedProofSet(t *testing.T) {
	s := newTestSigner(t, "")
	cred, err := s.SignHybrid(SignOptions{Intent: validIntent()})
	if err != nil {
		t.Fatal(err)
	}
	subject := cred["credentialSubject"].(map[string]any)
	intent := subject["intent"].(map[string]any)
	intent["resource"] = "https://evil.example.com/x"

	ok, _, err := VerifyCredential(
		cred, s.PublicKeyEd25519(), formatISO8601(time.Now()), 30, s.PublicKeyMLDSA44(),
	)
	if err != nil {
		t.Fatalf("VerifyCredential: %v", err)
	}
	if ok {
		t.Fatal("expected a tampered proof set to fail through the generic path")
	}
}

// A proof set whose Ed25519 half is signed by a foreign key must fail even
// though the ML-DSA-44 half is good.
func TestVerifyCredentialRejectsProofSetWithBadHalf(t *testing.T) {
	s := newTestSigner(t, "")
	other := newTestSigner(t, "did:web:other.example.com")
	cred, err := s.SignHybrid(SignOptions{Intent: validIntent()})
	if err != nil {
		t.Fatal(err)
	}

	ok, _, err := VerifyCredential(
		cred, other.PublicKeyEd25519(), formatISO8601(time.Now()), 30, s.PublicKeyMLDSA44(),
	)
	if err != nil {
		t.Fatalf("VerifyCredential: %v", err)
	}
	if ok {
		t.Fatal("expected a proof set with a failing half to be rejected")
	}
}

// Without an ML-DSA-44 key a proof set must report the missing key, never pass
// on the strength of its Ed25519 proof alone.
func TestVerifyCredentialReportsMissingMLDSAKey(t *testing.T) {
	s := newTestSigner(t, "")
	cred, err := s.SignHybrid(SignOptions{Intent: validIntent()})
	if err != nil {
		t.Fatal(err)
	}

	ok, _, err := VerifyCredential(cred, s.PublicKeyEd25519(), formatISO8601(time.Now()), 30)
	if ok {
		t.Fatal("a proof set must not verify without an ML-DSA-44 key")
	}
	if !errors.Is(err, ErrMissingMLDSA44Key) {
		t.Fatalf("expected ErrMissingMLDSA44Key, got %v", err)
	}
}

// The classical path is untouched: no ML-DSA-44 key is needed or expected.
func TestVerifyCredentialClassicalUnaffected(t *testing.T) {
	s := newTestSigner(t, "")
	cred, err := s.Sign(SignOptions{Intent: validIntent()})
	if err != nil {
		t.Fatal(err)
	}

	ok, _, err := VerifyCredential(cred, s.PublicKeyEd25519(), formatISO8601(time.Now()), 30)
	if err != nil {
		t.Fatalf("VerifyCredential: %v", err)
	}
	if !ok {
		t.Fatal("expected a classical credential to verify with no ML-DSA-44 key")
	}
}

// The pre-alignment composite proof also verifies through the generic path.
func TestVerifyProofAcceptsCompositeProof(t *testing.T) {
	s := newTestSigner(t, "")
	cred, err := BuildVouchCredential(BuildVouchCredentialOptions{
		IssuerDID:    s.DID(),
		Intent:       validIntent(),
		ValidSeconds: 300,
	})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := BuildHybridDataIntegrityProof(cred, BuildHybridProofOptions{
		Ed25519PrivateKey:  s.ed25519Private,
		MLDSA44PrivateKey:  s.mldsa44Private,
		VerificationMethod: s.VerificationMethodID(),
	})
	if err != nil {
		t.Fatal(err)
	}
	cred["proof"] = proofToMap(proof)

	ok, err := VerifyProof(cred, s.PublicKeyEd25519(), s.PublicKeyMLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected the composite proof to verify through the generic path")
	}

	if _, err := VerifyProof(cred, s.PublicKeyEd25519(), nil); !errors.Is(err, ErrMissingMLDSA44Key) {
		t.Fatalf("expected ErrMissingMLDSA44Key, got %v", err)
	}
}
