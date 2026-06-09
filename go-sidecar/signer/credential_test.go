// Tests for the VC + Data Integrity path in the Go sidecar
// (Specification §5, §7.1, §8). Mirrors tests/test_signer_vc.py and
// typescript/tests/credential.test.ts in the sibling implementations.

package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestSigner(t *testing.T, did string) *Signer {
	t.Helper()
	if did == "" {
		did = "did:web:agent.example.com"
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("seed generation: %v", err)
	}
	s, err := New(Config{
		DID:         did,
		Ed25519Seed:     seed,
		DefaultExpirySeconds: 300,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func validIntent() map[string]any {
	return map[string]any{
		"action":  "read_database",
		"target":  "users_table",
		"resource": "https://api.example.com/v1/users",
	}
}

// ---------------------------------------------------------------------------
// JCS canonicalization
// ---------------------------------------------------------------------------

func TestJCSEmptyObject(t *testing.T) {
	out, err := CanonicalizeString(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if out != "{}" {
		t.Fatalf("expected {}, got %q", out)
	}
}

func TestJCSKeySorting(t *testing.T) {
	in := map[string]any{"b": 1, "a": 2, "c": 3}
	out, err := CanonicalizeString(in)
	if err != nil {
		t.Fatal(err)
	}
	if out != `{"a":2,"b":1,"c":3}` {
		t.Fatalf("expected sorted, got %q", out)
	}
}

func TestJCSArrayPreservesOrder(t *testing.T) {
	in := []any{3, 1, 2}
	out, err := CanonicalizeString(in)
	if err != nil {
		t.Fatal(err)
	}
	if out != "[3,1,2]" {
		t.Fatalf("expected [3,1,2], got %q", out)
	}
}

// ---------------------------------------------------------------------------
// Multikey
// ---------------------------------------------------------------------------

func TestMultikeyRoundtrip(t *testing.T) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	mk, err := EncodeEd25519Public(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(mk, "z6Mk") {
		t.Fatalf("expected z6Mk prefix, got %q", mk[:6])
	}
	alg, decoded, err := MultikeyDecode(mk)
	if err != nil {
		t.Fatal(err)
	}
	if alg != "Ed25519" {
		t.Fatalf("expected Ed25519, got %q", alg)
	}
	if len(decoded) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(decoded))
	}
	for i := range raw {
		if decoded[i] != raw[i] {
			t.Fatalf("byte %d mismatch", i)
		}
	}
}

func TestMultikeyRejectsWrongLength(t *testing.T) {
	if _, err := EncodeEd25519Public(make([]byte, 31)); err == nil {
		t.Fatal("expected error on 31-byte key")
	}
}

func TestMultikeyAlgorithmHelper(t *testing.T) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	mk, err := EncodeEd25519Public(raw)
	if err != nil {
		t.Fatal(err)
	}
	alg, err := MultikeyAlgorithm(mk)
	if err != nil {
		t.Fatal(err)
	}
	if alg != "Ed25519" {
		t.Fatalf("expected Ed25519, got %q", alg)
	}
}

// ---------------------------------------------------------------------------
// Credential issuance
// ---------------------------------------------------------------------------

func TestSignCredentialReturnsW3CVC(t *testing.T) {
	s := newTestSigner(t, "")
	cred, err := s.SignCredential(SignCredentialOptions{Intent: validIntent()})
	if err != nil {
		t.Fatal(err)
	}

	ctx, _ := cred["@context"].([]any)
	if len(ctx) != 2 || ctx[0] != VCContextV2 || ctx[1] != VouchContextV1 {
		t.Fatalf("unexpected @context: %v", ctx)
	}

	types, _ := cred["type"].([]any)
	hasVC, hasVouch := false, false
	for _, t0 := range types {
		if t0 == VCType {
			hasVC = true
		}
		if t0 == VouchCredentialType {
			hasVouch = true
		}
	}
	if !hasVC || !hasVouch {
		t.Fatalf("missing required types: %v", types)
	}

	if cred["issuer"] != s.DID() {
		t.Fatalf("wrong issuer: %v", cred["issuer"])
	}
	if id, _ := cred["id"].(string); !strings.HasPrefix(id, "urn:uuid:") {
		t.Fatalf("expected urn:uuid: id, got %v", cred["id"])
	}

	subject, _ := cred["credentialSubject"].(map[string]any)
	if subject["vouchVersion"] != ProtocolVersion {
		t.Fatalf("wrong protocol version: %v", subject["vouchVersion"])
	}

	proof, _ := cred["proof"].(map[string]any)
	if proof["type"] != ProofTypeDataIntegrity {
		t.Fatalf("wrong proof type: %v", proof["type"])
	}
	if proof["cryptosuite"] != CryptosuiteEddsaJcs2022 {
		t.Fatalf("wrong cryptosuite: %v", proof["cryptosuite"])
	}
	if proof["proofPurpose"] != "assertionMethod" {
		t.Fatalf("wrong proofPurpose: %v", proof["proofPurpose"])
	}
	pv, _ := proof["proofValue"].(string)
	if !strings.HasPrefix(pv, "z") {
		t.Fatalf("proofValue not z-prefixed: %v", pv)
	}
}

func TestSignCredentialClampsReputation(t *testing.T) {
	s := newTestSigner(t, "")
	high, low := 200, -10
	credHigh, _ := s.SignCredential(SignCredentialOptions{
		Intent: validIntent(), ReputationScore: &high,
	})
	credLow, _ := s.SignCredential(SignCredentialOptions{
		Intent: validIntent(), ReputationScore: &low,
	})
	if v := credHigh["credentialSubject"].(map[string]any)["reputationScore"]; v != 100 {
		t.Fatalf("expected clamp to 100, got %v", v)
	}
	if v := credLow["credentialSubject"].(map[string]any)["reputationScore"]; v != 0 {
		t.Fatalf("expected clamp to 0, got %v", v)
	}
}

func TestSignCredentialRejectsMissingResource(t *testing.T) {
	s := newTestSigner(t, "")
	bad := map[string]any{"action": "x", "target": "y"}
	if _, err := s.SignCredential(SignCredentialOptions{Intent: bad}); err == nil {
		t.Fatal("expected error on missing resource")
	}
}

func TestSignCredentialJSON(t *testing.T) {
	s := newTestSigner(t, "")
	jsonBytes, err := s.SignCredentialJSON(SignCredentialOptions{
		Intent: validIntent(),
	})
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	proof := parsed["proof"].(map[string]any)
	if proof["cryptosuite"] != CryptosuiteEddsaJcs2022 {
		t.Fatal("wrong cryptosuite after JSON roundtrip")
	}
}

func TestSignCredentialPublicKeyMultikey(t *testing.T) {
	s := newTestSigner(t, "")
	mk, err := s.PublicKeyMultikey()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(mk, "z6Mk") {
		t.Fatalf("expected z6Mk prefix, got %q", mk[:6])
	}
	alg, raw, err := MultikeyDecode(mk)
	if err != nil {
		t.Fatal(err)
	}
	if alg != "Ed25519" || len(raw) != 32 {
		t.Fatalf("unexpected: alg=%q len=%d", alg, len(raw))
	}
}

func TestVerificationMethodID(t *testing.T) {
	s := newTestSigner(t, "did:web:demo.example.com")
	if got := s.VerificationMethodID(); got != "did:web:demo.example.com#key-1" {
		t.Fatalf("unexpected verification method id: %q", got)
	}
}

// ---------------------------------------------------------------------------
// Verification roundtrip
// ---------------------------------------------------------------------------

func TestVerifyValidCredential(t *testing.T) {
	s := newTestSigner(t, "")
	cred, err := s.SignCredential(SignCredentialOptions{Intent: validIntent()})
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyDataIntegrityProof(cred, s.PublicKeyEd25519())
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !ok {
		t.Fatal("expected verification to succeed")
	}
}

func TestVerifyRejectsTamperedIntent(t *testing.T) {
	s := newTestSigner(t, "")
	cred, _ := s.SignCredential(SignCredentialOptions{Intent: validIntent()})

	subject := cred["credentialSubject"].(map[string]any)
	intent := subject["intent"].(map[string]any)
	intent["resource"] = "https://evil.example.com/x"

	ok, _ := VerifyDataIntegrityProof(cred, s.PublicKeyEd25519())
	if ok {
		t.Fatal("expected tampered credential to fail verification")
	}
}

func TestVerifyRejectsTamperedIssuer(t *testing.T) {
	s := newTestSigner(t, "")
	cred, _ := s.SignCredential(SignCredentialOptions{Intent: validIntent()})
	cred["issuer"] = "did:web:attacker.example.com"

	ok, _ := VerifyDataIntegrityProof(cred, s.PublicKeyEd25519())
	if ok {
		t.Fatal("expected issuer tamper to fail verification")
	}
}

func TestVerifyRejectsTamperedProofValue(t *testing.T) {
	s := newTestSigner(t, "")
	cred, _ := s.SignCredential(SignCredentialOptions{Intent: validIntent()})

	proof := cred["proof"].(map[string]any)
	pv := proof["proofValue"].(string)
	// Flip a couple of base58 chars.
	last := pv[len(pv)-2:]
	var flipped string
	if last[0] != 'a' {
		flipped = pv[:len(pv)-2] + "aA"
	} else {
		flipped = pv[:len(pv)-2] + "bB"
	}
	proof["proofValue"] = flipped

	ok, _ := VerifyDataIntegrityProof(cred, s.PublicKeyEd25519())
	if ok {
		t.Fatal("expected proof tamper to fail verification")
	}
}

func TestVerifyWithWrongPublicKey(t *testing.T) {
	s := newTestSigner(t, "did:web:a.example.com")
	other := newTestSigner(t, "did:web:b.example.com")
	cred, _ := s.SignCredential(SignCredentialOptions{Intent: validIntent()})

	ok, _ := VerifyDataIntegrityProof(cred, other.PublicKeyEd25519())
	if ok {
		t.Fatal("expected verification with foreign key to fail")
	}
}

// ---------------------------------------------------------------------------
// Delegation chains
// ---------------------------------------------------------------------------

func TestDelegationAppendsLinkFromParent(t *testing.T) {
	parent := newTestSigner(t, "did:web:alice.example.com")
	child := newTestSigner(t, "did:web:assistant.example.com")

	parentCred, _ := parent.SignCredential(SignCredentialOptions{
		Intent: map[string]any{
			"action":  "manage_bookings",
			"target":  "destination:Paris",
			"resource": "https://travel-api.example.com/v1/bookings",
		},
	})
	// v1.7 attenuation: action and target are held equal (no broadening), and
	// the resource is narrowed to a sub-path.
	childCred, err := child.SignCredential(SignCredentialOptions{
		Intent: map[string]any{
			"action":  "manage_bookings",
			"target":  "destination:Paris",
			"resource": "https://travel-api.example.com/v1/bookings/flight-AF123",
		},
		ParentCredential: parentCred,
	})
	if err != nil {
		t.Fatal(err)
	}

	subject := childCred["credentialSubject"].(map[string]any)
	chain := subject["delegationChain"].([]any)
	if len(chain) != 1 {
		t.Fatalf("expected 1 link, got %d", len(chain))
	}
	link := chain[0].(map[string]any)
	if link["issuer"] != parent.DID() {
		t.Fatalf("wrong issuer: %v", link["issuer"])
	}
	if link["subject"] != child.DID() {
		t.Fatalf("wrong subject: %v", link["subject"])
	}

	ok, _ := VerifyDataIntegrityProof(childCred, child.PublicKeyEd25519())
	if !ok {
		t.Fatal("expected child credential to verify")
	}
}

func TestDelegationResourceNarrowingViolation(t *testing.T) {
	parent := newTestSigner(t, "did:web:alice.example.com")
	child := newTestSigner(t, "did:web:rogue.example.com")

	parentCred, _ := parent.SignCredential(SignCredentialOptions{
		Intent: map[string]any{
			"action":  "read",
			"target":  "users",
			"resource": "https://api.example.com/v1/users",
		},
	})

	// Action and target are held equal; only the resource points at a sibling
	// path that is not a sub-resource. Resource broadens, so it is rejected.
	_, err := child.SignCredential(SignCredentialOptions{
		Intent: map[string]any{
			"action":  "read",
			"target":  "users",
			"resource": "https://api.example.com/v1/admin",
		},
		ParentCredential: parentCred,
	})
	if err == nil {
		t.Fatal("expected resource-narrowing violation")
	}
	if !strings.Contains(err.Error(), "resource-narrowing") {
		t.Fatalf("expected resource-narrowing error, got %v", err)
	}
}

func TestDeepChainNoDepthCap(t *testing.T) {
	// v1.7 (CH-001): the fixed depth cap is removed. A chain that keeps its
	// capability equal or narrower at each hop builds past the old cap of five
	// links. Depth is a verifier-side cost budget, not a build-time limit.
	intent := map[string]any{
		"action":  "read",
		"target":  "data",
		"resource": "https://api.example.com/v1/data",
	}

	signers := make([]*Signer, 8)
	for i := range signers {
		signers[i] = newTestSigner(t, fmt.Sprintf("did:web:agent%d.example.com", i))
	}

	cred, err := signers[0].SignCredential(SignCredentialOptions{Intent: intent})
	if err != nil {
		t.Fatal(err)
	}
	// Build seven hops: the sixth was rejected in v1.6.2, now it is allowed.
	for i := 1; i <= 7; i++ {
		cred, err = signers[i].SignCredential(SignCredentialOptions{
			Intent:      intent,
			ParentCredential: cred,
		})
		if err != nil {
			t.Fatalf("hop %d: %v", i, err)
		}
	}
	subject := cred["credentialSubject"].(map[string]any)
	chain := subject["delegationChain"].([]any)
	if len(chain) != 7 {
		t.Fatalf("expected 7 links, got %d", len(chain))
	}
}

// ---------------------------------------------------------------------------
// Coexistence with legacy composite-JWS path
// ---------------------------------------------------------------------------

func TestLegacyAndModernCoexist(t *testing.T) {
	s := newTestSigner(t, "")

	// Legacy composite JWS still works.
	jws, err := s.Sign(SignRequest{Payload: map[string]any{"action": "ping"}})
	if err != nil {
		t.Fatalf("legacy Sign: %v", err)
	}
	var parsed VouchToken
	if err := json.Unmarshal(jws, &parsed); err != nil {
		t.Fatalf("legacy output not valid JSON: %v", err)
	}
	if parsed.Mode != "standard" {
		t.Fatalf("expected mode=standard, got %q", parsed.Mode)
	}

	// Modern credential path also works on the same signer.
	cred, err := s.SignCredential(SignCredentialOptions{Intent: validIntent()})
	if err != nil {
		t.Fatalf("SignCredential: %v", err)
	}
	if cred["issuer"] != s.DID() {
		t.Fatal("modern path issuer mismatch")
	}
	ok, err := VerifyDataIntegrityProof(cred, s.PublicKeyEd25519())
	if err != nil || !ok {
		t.Fatalf("modern verification failed: ok=%v err=%v", ok, err)
	}
}

// ---------------------------------------------------------------------------
// Cross-implementation JCS interop
// ---------------------------------------------------------------------------

type jcsVector struct {
	Name   string `json:"name"`
	Input   any  `json:"input"`
	Canonical string `json:"canonical"`
}

type jcsVectorFile struct {
	Vectors []jcsVector `json:"vectors"`
}

func loadJCSVectors(t *testing.T) []jcsVector {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// signer/ -> go-sidecar/ -> repo root
	repoRoot := filepath.Clean(filepath.Join(wd, "..", ".."))
	vecPath := filepath.Join(repoRoot, "test-vectors", "jcs", "vectors.json")
	raw, err := os.ReadFile(vecPath)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var f jcsVectorFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	return f.Vectors
}

func TestJCSInteropVectors(t *testing.T) {
	for _, v := range loadJCSVectors(t) {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			out, err := CanonicalizeString(v.Input)
			if err != nil {
				t.Fatalf("canonicalize: %v", err)
			}
			if out != v.Canonical {
				t.Fatalf(
					"canonical mismatch\n expected: %s\n got:   %s",
					v.Canonical, out,
				)
			}
		})
	}
}

// Ensure we're using time correctly for reference.
var _ = time.Now
