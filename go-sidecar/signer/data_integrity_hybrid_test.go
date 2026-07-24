// Tests for the post-quantum Ed25519 + ML-DSA-44 proof set. Mirrors the
// eddsa-jcs-2022 tests in credential_test.go, plus the proof-set properties
// (both signatures required, per-suite encodings, each half verifiable on its
// own) and the pre-alignment shapes that must stay verifiable.

package signer

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

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

// hybridProofs pulls the two proofs out of a proof set, keyed by cryptosuite.
func hybridProofs(t *testing.T, cred map[string]any) (ed, ml map[string]any) {
	t.Helper()
	proofs, ok := proofSet(cred["proof"])
	if !ok {
		t.Fatalf("expected a proof array, got %T", cred["proof"])
	}
	if len(proofs) != 2 {
		t.Fatalf("expected 2 proofs, got %d", len(proofs))
	}
	for _, p := range proofs {
		switch cs, _ := p["cryptosuite"].(string); cs {
		case CryptosuiteEddsaJcs2022:
			ed = p
		case CryptosuiteMLDSA44Jcs2024:
			ml = p
		}
	}
	if ed == nil {
		t.Fatal("proof set has no eddsa-jcs-2022 proof")
	}
	if ml == nil {
		t.Fatal("proof set has no mldsa44-jcs-2024 proof")
	}
	return ed, ml
}

func TestSignHybridShape(t *testing.T) {
	s := newTestSigner(t, "")
	cred, err := s.SignHybrid(SignOptions{Intent: validIntent()})
	if err != nil {
		t.Fatal(err)
	}
	ed, ml := hybridProofs(t, cred)

	if ed["type"] != ProofTypeDataIntegrity || ml["type"] != ProofTypeDataIntegrity {
		t.Fatalf("expected DataIntegrityProof type, got %v and %v", ed["type"], ml["type"])
	}

	// eddsa-jcs-2022 keeps base58btc ("z").
	edPV, _ := ed["proofValue"].(string)
	if !strings.HasPrefix(edPV, "z") {
		t.Fatalf("eddsa proofValue not z-prefixed: %v", edPV)
	}
	edSig, err := b58Decode(edPV[1:])
	if err != nil {
		t.Fatal(err)
	}
	if len(edSig) != ed25519SignatureSize {
		t.Fatalf("Ed25519 sig size %d, expected %d", len(edSig), ed25519SignatureSize)
	}

	// mldsa44-jcs-2024 uses base64url-nopad ("u").
	mlPV, _ := ml["proofValue"].(string)
	if !strings.HasPrefix(mlPV, "u") {
		t.Fatalf("ML-DSA-44 proofValue not u-prefixed: %v", mlPV)
	}
	mlSig, err := base64.RawURLEncoding.DecodeString(mlPV[1:])
	if err != nil {
		t.Fatal(err)
	}
	if len(mlSig) != mldsa44SignatureSize {
		t.Fatalf("ML-DSA-44 sig size %d, expected %d", len(mlSig), mldsa44SignatureSize)
	}

	// The two proofs point at the parallel key slots on the same DID.
	if ed["verificationMethod"] != s.VerificationMethodID() {
		t.Fatalf("unexpected Ed25519 verificationMethod: %v", ed["verificationMethod"])
	}
	if ml["verificationMethod"] != s.MLDSA44VerificationMethodID() {
		t.Fatalf("unexpected ML-DSA-44 verificationMethod: %v", ml["verificationMethod"])
	}

	// The composite identifier is never emitted.
	if ed["cryptosuite"] == CryptosuiteHybridEddsaMldsa44 || ml["cryptosuite"] == CryptosuiteHybridEddsaMldsa44 {
		t.Fatal("the composite cryptosuite must never be emitted")
	}
}

// Each proof in the set verifies on its own, so a verifier that understands
// only one of the two cryptosuites can still check that half.
func TestDualProofHalvesVerifyIndependently(t *testing.T) {
	s := newTestSigner(t, "")
	cred, err := s.SignHybrid(SignOptions{Intent: validIntent()})
	if err != nil {
		t.Fatal(err)
	}
	ed, _ := hybridProofs(t, cred)

	edOnly := copyMap(cred)
	edOnly["proof"] = ed
	ok, err := VerifyDataIntegrityProof(edOnly, s.PublicKeyEd25519())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("the eddsa-jcs-2022 half of the proof set should verify on its own")
	}
}

// ---------------------------------------------------------------------------
// Hybrid verification roundtrip
// ---------------------------------------------------------------------------

func TestVerifyHybridValidCredential(t *testing.T) {
	s := newTestSigner(t, "")
	cred, err := s.SignHybrid(SignOptions{Intent: validIntent()})
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyDualProof(
		cred, s.PublicKeyEd25519(), s.PublicKeyMLDSA44(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected dual proof verification to succeed")
	}
}

func TestVerifyHybridRejectsTamperedIntent(t *testing.T) {
	s := newTestSigner(t, "")
	cred, _ := s.SignHybrid(SignOptions{Intent: validIntent()})

	subject := cred["credentialSubject"].(map[string]any)
	intent := subject["intent"].(map[string]any)
	intent["resource"] = "https://evil.example.com/x"

	ok, _ := VerifyDualProof(
		cred, s.PublicKeyEd25519(), s.PublicKeyMLDSA44(),
	)
	if ok {
		t.Fatal("expected tampered credential to fail")
	}
}

func TestVerifyHybridRejectsWrongEd25519Key(t *testing.T) {
	s := newTestSigner(t, "")
	other := newTestSigner(t, "did:web:other.example.com")
	cred, _ := s.SignHybrid(SignOptions{Intent: validIntent()})

	ok, _ := VerifyDualProof(
		cred, other.PublicKeyEd25519(), s.PublicKeyMLDSA44(),
	)
	if ok {
		t.Fatal("expected verification with foreign Ed25519 key to fail")
	}
}

func TestVerifyHybridRejectsWrongMLDSAKey(t *testing.T) {
	s := newTestSigner(t, "")
	other := newTestSigner(t, "did:web:other.example.com")
	cred, _ := s.SignHybrid(SignOptions{Intent: validIntent()})

	ok, _ := VerifyDualProof(
		cred, s.PublicKeyEd25519(), other.PublicKeyMLDSA44(),
	)
	if ok {
		t.Fatal("expected verification with foreign ML-DSA-44 key to fail")
	}
}

// A proof set missing its post-quantum half must not pass the dual verify.
func TestVerifyDualRejectsMissingMLDSAProof(t *testing.T) {
	s := newTestSigner(t, "")
	cred, _ := s.SignHybrid(SignOptions{Intent: validIntent()})
	ed, _ := hybridProofs(t, cred)
	cred["proof"] = []any{ed}

	ok, _ := VerifyDualProof(cred, s.PublicKeyEd25519(), s.PublicKeyMLDSA44())
	if ok {
		t.Fatal("expected a proof set without an ML-DSA-44 proof to fail")
	}
}

// The pre-alignment base58btc ("z") ML-DSA-44 proofValue encoding stays
// verifiable alongside the specified base64url-nopad ("u") form.
func TestVerifyDualAcceptsLegacyMLDSAEncoding(t *testing.T) {
	s := newTestSigner(t, "")
	cred, _ := s.SignHybrid(SignOptions{Intent: validIntent()})
	_, ml := hybridProofs(t, cred)

	pv, _ := ml["proofValue"].(string)
	sig, err := base64.RawURLEncoding.DecodeString(pv[1:])
	if err != nil {
		t.Fatal(err)
	}
	ml["proofValue"] = "z" + b58Encode(sig)

	ok, err := VerifyDualProof(cred, s.PublicKeyEd25519(), s.PublicKeyMLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected the base58btc ML-DSA-44 proofValue to still verify")
	}
}

// The pre-alignment mldsa44-jcs-2026 identifier stays verifiable.
func TestVerifyDualAcceptsLegacyMLDSACryptosuiteID(t *testing.T) {
	s := newTestSigner(t, "")
	cred, _ := s.SignHybrid(SignOptions{Intent: validIntent()})
	ed, _ := hybridProofs(t, cred)
	base := unsecuredDocument(cred)

	legacy := map[string]any{
		"type":               ProofTypeDataIntegrity,
		"cryptosuite":        CryptosuiteMLDSA44JcsLegacy,
		"created":            "2026-04-26T10:00:00Z",
		"verificationMethod": s.MLDSA44VerificationMethodID(),
		"proofPurpose":       "assertionMethod",
	}
	signingInput, err := HashData(base, legacy)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.mldsa44Private.Sign(rand.Reader, signingInput, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	legacy["proofValue"] = "u" + base64.RawURLEncoding.EncodeToString(sig)
	cred["proof"] = []any{ed, legacy}

	ok, err := VerifyDualProof(cred, s.PublicKeyEd25519(), s.PublicKeyMLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected the mldsa44-jcs-2026 identifier to still verify")
	}
}

// ---------------------------------------------------------------------------
// Independence from eddsa-jcs-2022 path
// ---------------------------------------------------------------------------

func TestHybridAndEddsaJcsCoexist(t *testing.T) {
	s := newTestSigner(t, "")

	// Modern eddsa-jcs-2022 path still works.
	credEd, err := s.Sign(SignOptions{Intent: validIntent()})
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyDataIntegrityProof(credEd, s.PublicKeyEd25519())
	if err != nil || !ok {
		t.Fatalf("eddsa-jcs-2022 path broken: ok=%v err=%v", ok, err)
	}

	// Hybrid path also works on the same signer.
	credHyb, err := s.SignHybrid(SignOptions{Intent: validIntent()})
	if err != nil {
		t.Fatal(err)
	}
	ok, err = VerifyDualProof(
		credHyb, s.PublicKeyEd25519(), s.PublicKeyMLDSA44(),
	)
	if err != nil || !ok {
		t.Fatalf("post-quantum path broken: ok=%v err=%v", ok, err)
	}

	// A proof set is an array, so the single-proof verifier rejects it
	// outright rather than checking only one half.
	_, err = VerifyDataIntegrityProof(credHyb, s.PublicKeyEd25519())
	if err == nil {
		t.Fatal("expected the single-proof verifier to reject a proof set")
	}
}

// ---------------------------------------------------------------------------
// Hybrid verificationMethod pair derivation
// ---------------------------------------------------------------------------

func TestHybridVerificationMethodPair(t *testing.T) {
	cases := []struct {
		input       string
		expectedEd  string
		expectedMLD string
	}{
		{
			input:       "did:web:agent.example.com#key-1",
			expectedEd:  "did:web:agent.example.com#key-1",
			expectedMLD: "did:web:agent.example.com#key-2",
		},
		{
			input:       "did:web:agent.example.com#abc",
			expectedEd:  "did:web:agent.example.com#abc",
			expectedMLD: "did:web:agent.example.com#key-2",
		},
		{
			input:       "did:web:agent.example.com",
			expectedEd:  "did:web:agent.example.com",
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

// The v1.6.x composite wire format is verify-only. Rebuilding it here is the
// regression check that credentials issued under it still verify.
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
		"@context":   []any{VCContextV2, VouchContextV1},
		"id":         "urn:uuid:test",
		"type":       []any{VCType, VouchCredentialType},
		"issuer":     "did:web:test.example.com",
		"validFrom":  "2026-04-26T00:00:00Z",
		"validUntil": "2026-04-26T00:05:00Z",
		"credentialSubject": map[string]any{
			"id":           "did:web:test.example.com",
			"vouchVersion": "1.0",
			"intent":       validIntent(),
		},
	}

	proof, err := BuildHybridDataIntegrityProof(cred, BuildHybridProofOptions{
		Ed25519PrivateKey:  edPriv,
		MLDSA44PrivateKey:  mlPriv,
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
		t.Fatal("direct composite proof verification failed")
	}
}

// The direct proof-set primitive, independent of Signer.
func TestBuildAndVerifyDualProofDirect(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mlPub, mlPriv, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cred := map[string]any{
		"@context":   []any{VCContextV2, VouchContextV1},
		"id":         "urn:uuid:test",
		"type":       []any{VCType, VouchCredentialType},
		"issuer":     "did:web:test.example.com",
		"validFrom":  "2026-04-26T00:00:00Z",
		"validUntil": "2026-04-26T00:05:00Z",
		"credentialSubject": map[string]any{
			"id":           "did:web:test.example.com",
			"vouchVersion": "1.0",
			"intent":       validIntent(),
		},
	}

	signed, err := SignDual(cred, BuildDualProofOptions{
		Ed25519PrivateKey:         edPriv,
		MLDSA44PrivateKey:         mlPriv,
		Ed25519VerificationMethod: "did:web:test.example.com#key-1",
		Created:                   time.Date(2026, 4, 26, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}

	ok, err := VerifyDualProof(signed, edPub, mlPub)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("direct proof-set verification failed")
	}

	// SignDual must not mutate the caller's credential.
	if _, present := cred["proof"]; present {
		t.Fatal("SignDual should leave the input credential unsecured")
	}
}
