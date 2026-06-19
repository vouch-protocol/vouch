// Tests for the hybrid Ed25519 + ML-DSA-44 Data Integrity cryptosuite
// (Specification §13.2). Mirrors the eddsa-jcs-2022 tests in
// credential_test.go, plus hybrid-specific properties (both signatures
// required, format size, classical-only and PQ-only tampers fail).

package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

// ---------------------------------------------------------------------------
// Multikey export for ML-DSA-44
// ---------------------------------------------------------------------------

func TestEncodeMLDSA44PublicLength(t *testing.T) {
	if _, err := EncodeMLDSA44Public(make([]byte, 1311)); err == nil {
		t.Fatal("expected error on 1311-byte key")
	}
	if _, err := EncodeMLDSA44Public(make([]byte, 1313)); err == nil {
		t.Fatal("expected error on 1313-byte key")
	}
}

func TestEncodeMLDSA44PublicRoundtrip(t *testing.T) {
	raw := make([]byte, 1312)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	mk, err := EncodeMLDSA44Public(raw)
	if err != nil {
		t.Fatal(err)
	}
	if mk == "" || mk[0] != 'z' {
		t.Fatalf("expected z-prefix, got %q", mk[:1])
	}
	alg, decoded, err := MultikeyDecode(mk)
	if err != nil {
		t.Fatal(err)
	}
	if alg != "ML-DSA-44" {
		t.Fatalf("expected ML-DSA-44, got %q", alg)
	}
	if len(decoded) != 1312 {
		t.Fatalf("expected 1312 bytes, got %d", len(decoded))
	}
}

func TestSignerExposesMLDSA44Multikey(t *testing.T) {
	s := newTestSigner(t, "")
	mk, err := s.PublicKeyMLDSA44Multikey()
	if err != nil {
		t.Fatal(err)
	}
	alg, _, err := MultikeyDecode(mk)
	if err != nil {
		t.Fatal(err)
	}
	if alg != "ML-DSA-44" {
		t.Fatalf("expected ML-DSA-44, got %q", alg)
	}
}

// ---------------------------------------------------------------------------
// Hybrid issuance
// ---------------------------------------------------------------------------

func TestSignCredentialHybridShape(t *testing.T) {
	s := newTestSigner(t, "")
	cred, err := s.SignCredentialHybrid(SignCredentialOptions{Intent: validIntent()})
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := cred["proof"].(map[string]any)
	if proof["cryptosuite"] != CryptosuiteHybridEddsaMldsa44 {
		t.Fatalf("expected hybrid cryptosuite, got %v", proof["cryptosuite"])
	}
	if proof["type"] != ProofTypeDataIntegrity {
		t.Fatalf("expected DataIntegrityProof type, got %v", proof["type"])
	}
	pv, _ := proof["proofValue"].(string)
	if !strings.HasPrefix(pv, "z") {
		t.Fatalf("proofValue not z-prefixed: %v", pv)
	}
	combined, err := b58Decode(pv[1:])
	if err != nil {
		t.Fatal(err)
	}
	if len(combined) != hybridSignatureSize {
		t.Fatalf("hybrid sig size %d, expected %d", len(combined), hybridSignatureSize)
	}
}

// ---------------------------------------------------------------------------
// Hybrid verification roundtrip
// ---------------------------------------------------------------------------

func TestVerifyHybridValidCredential(t *testing.T) {
	s := newTestSigner(t, "")
	cred, err := s.SignCredentialHybrid(SignCredentialOptions{Intent: validIntent()})
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyHybridDataIntegrityProof(
		cred, s.PublicKeyEd25519(), s.PublicKeyMLDSA44(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected hybrid verification to succeed")
	}
}

func TestVerifyHybridRejectsTamperedIntent(t *testing.T) {
	s := newTestSigner(t, "")
	cred, _ := s.SignCredentialHybrid(SignCredentialOptions{Intent: validIntent()})

	subject := cred["credentialSubject"].(map[string]any)
	intent := subject["intent"].(map[string]any)
	intent["resource"] = "https://evil.example.com/x"

	ok, _ := VerifyHybridDataIntegrityProof(
		cred, s.PublicKeyEd25519(), s.PublicKeyMLDSA44(),
	)
	if ok {
		t.Fatal("expected tampered credential to fail")
	}
}

func TestVerifyHybridRejectsWrongEd25519Key(t *testing.T) {
	s := newTestSigner(t, "")
	other := newTestSigner(t, "did:web:other.example.com")
	cred, _ := s.SignCredentialHybrid(SignCredentialOptions{Intent: validIntent()})

	ok, _ := VerifyHybridDataIntegrityProof(
		cred, other.PublicKeyEd25519(), s.PublicKeyMLDSA44(),
	)
	if ok {
		t.Fatal("expected verification with foreign Ed25519 key to fail")
	}
}

func TestVerifyHybridRejectsWrongMLDSAKey(t *testing.T) {
	s := newTestSigner(t, "")
	other := newTestSigner(t, "did:web:other.example.com")
	cred, _ := s.SignCredentialHybrid(SignCredentialOptions{Intent: validIntent()})

	ok, _ := VerifyHybridDataIntegrityProof(
		cred, s.PublicKeyEd25519(), other.PublicKeyMLDSA44(),
	)
	if ok {
		t.Fatal("expected verification with foreign ML-DSA-44 key to fail")
	}
}

// ---------------------------------------------------------------------------
// Independence from eddsa-jcs-2022 path
// ---------------------------------------------------------------------------

func TestHybridAndEddsaJcsCoexist(t *testing.T) {
	s := newTestSigner(t, "")

	// Modern eddsa-jcs-2022 path still works.
	credEd, err := s.SignCredential(SignCredentialOptions{Intent: validIntent()})
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyDataIntegrityProof(credEd, s.PublicKeyEd25519())
	if err != nil || !ok {
		t.Fatalf("eddsa-jcs-2022 path broken: ok=%v err=%v", ok, err)
	}

	// Hybrid path also works on the same signer.
	credHyb, err := s.SignCredentialHybrid(SignCredentialOptions{Intent: validIntent()})
	if err != nil {
		t.Fatal(err)
	}
	ok, err = VerifyHybridDataIntegrityProof(
		credHyb, s.PublicKeyEd25519(), s.PublicKeyMLDSA44(),
	)
	if err != nil || !ok {
		t.Fatalf("hybrid path broken: ok=%v err=%v", ok, err)
	}

	// Hybrid credentials MUST NOT verify with the eddsa-jcs-2022 verifier
	// (different cryptosuite identifier).
	_, err = VerifyDataIntegrityProof(credHyb, s.PublicKeyEd25519())
	if err == nil {
		t.Fatal("expected eddsa verifier to reject hybrid cryptosuite identifier")
	}
}

// ---------------------------------------------------------------------------
// Hybrid verificationMethod pair derivation
// ---------------------------------------------------------------------------

func TestHybridVerificationMethodPair(t *testing.T) {
	cases := []struct {
		input    string
		expectedEd  string
		expectedMLD string
	}{
		{
			input:    "did:web:agent.example.com#key-1",
			expectedEd: "did:web:agent.example.com#key-1",
			expectedMLD: "did:web:agent.example.com#key-2",
		},
		{
			input:    "did:web:agent.example.com#abc",
			expectedEd: "did:web:agent.example.com#abc",
			expectedMLD: "did:web:agent.example.com#key-2",
		},
		{
			input:    "did:web:agent.example.com",
			expectedEd: "did:web:agent.example.com",
			expectedMLD: "did:web:agent.example.com#key-2",
		},
	}
	for _, c := range cases {
		ed, mld := HybridVerificationMethodPair(c.input)
		if ed != c.expectedEd || mld != c.expectedMLD {
			t.Errorf(
				"input=%q expected (%q, %q) got (%q, %q)",
				c.input, c.expectedEd, c.expectedMLD, ed, mld,
			)
		}
	}
}

// ---------------------------------------------------------------------------
// Direct primitive (independent of Signer)
// ---------------------------------------------------------------------------

func TestBuildAndVerifyHybridProofDirect(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mlPub, mlPriv, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cred := map[string]any{
		"@context":  []any{VCContextV2, VouchContextV1},
		"id":     "urn:uuid:test",
		"type":    []any{VCType, VouchCredentialType},
		"issuer":   "did:web:test.example.com",
		"validFrom": "2026-04-26T00:00:00Z",
		"validUntil": "2026-04-26T00:05:00Z",
		"credentialSubject": map[string]any{
			"id":      "did:web:test.example.com",
			"vouchVersion": "1.0",
			"intent":    validIntent(),
		},
	}

	proof, err := BuildHybridDataIntegrityProof(cred, BuildHybridProofOptions{
		Ed25519PrivateKey: edPriv,
		MLDSA44PrivateKey: mlPriv,
		VerificationMethod: "did:web:test.example.com#key-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	cred["proof"] = proofToMap(proof)

	ok, err := VerifyHybridDataIntegrityProof(cred, edPub, mlPub)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("direct hybrid proof verification failed")
	}
}
