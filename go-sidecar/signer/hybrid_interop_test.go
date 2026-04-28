// Cross-implementation interop test for the hybrid Ed25519 + ML-DSA-44
// cryptosuite (W3C CG Report §13.2). Loads the shared vector generated
// by the Python implementation and asserts that:
//
//  1. JCS canonicalization of the signed credential (with proofValue
//     stripped) produces the documented SHA-256 digest, confirming
//     Python, TypeScript, and Go canonicalize identically for this payload.
//
//  2. The Go verifier accepts the Python-generated hybrid signature,
//     confirming wire-format interop across all three implementations.
//
// The Python and TypeScript suites have parallel tests against the same
// vector.

package signer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

type hybridVector struct {
	Description                 string `json:"description"`
	Version                     string `json:"version"`
	Ed25519                     struct {
		SeedB64       string `json:"seed_b64"`
		PublicKeyB64  string `json:"public_key_b64"`
	} `json:"ed25519"`
	Mldsa44 struct {
		PublicKeyB64 string `json:"public_key_b64"`
		SecretKeyB64 string `json:"secret_key_b64"`
	} `json:"mldsa44"`
	ExpectedCanonicalSHA256B64 string         `json:"expected_canonical_sha256_b64"`
	SignedCredential           map[string]any `json:"signed_credential"`
}

func loadHybridInteropVector(t *testing.T) hybridVector {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	repoRoot := filepath.Clean(filepath.Join(wd, "..", ".."))
	vecPath := filepath.Join(
		repoRoot, "test-vectors", "hybrid-eddsa-mldsa44", "vector.json",
	)
	raw, err := os.ReadFile(vecPath)
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v hybridVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode vector: %v", err)
	}
	return v
}

func TestHybridInteropCanonicalDigest(t *testing.T) {
	vec := loadHybridInteropVector(t)

	// Strip proofValue from the proof and canonicalize the rest.
	credCopy := copyMap(vec.SignedCredential)
	proof, _ := credCopy["proof"].(map[string]any)
	if proof == nil {
		t.Fatal("vector has no proof object")
	}
	proofWithoutValue := copyMap(proof)
	delete(proofWithoutValue, "proofValue")
	credCopy["proof"] = proofWithoutValue

	canonical, err := Canonicalize(credCopy)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	digest := sha256.Sum256(canonical)
	got := base64.StdEncoding.EncodeToString(digest[:])
	if got != vec.ExpectedCanonicalSHA256B64 {
		t.Fatalf(
			"canonical digest mismatch\n  expected: %s\n  got:      %s",
			vec.ExpectedCanonicalSHA256B64, got,
		)
	}
}

func TestHybridInteropVerifyPythonSignature(t *testing.T) {
	vec := loadHybridInteropVector(t)

	edPubBytes, err := base64.StdEncoding.DecodeString(vec.Ed25519.PublicKeyB64)
	if err != nil {
		t.Fatalf("decode Ed25519 pub: %v", err)
	}
	if len(edPubBytes) != ed25519.PublicKeySize {
		t.Fatalf("unexpected Ed25519 pub size: %d", len(edPubBytes))
	}
	edPub := ed25519.PublicKey(edPubBytes)

	mlPubBytes, err := base64.StdEncoding.DecodeString(vec.Mldsa44.PublicKeyB64)
	if err != nil {
		t.Fatalf("decode ML-DSA-44 pub: %v", err)
	}
	mlPub := new(mldsa44.PublicKey)
	if err := mlPub.UnmarshalBinary(mlPubBytes); err != nil {
		t.Fatalf("unmarshal ML-DSA-44 pub: %v", err)
	}

	ok, err := VerifyHybridDataIntegrityProof(vec.SignedCredential, edPub, mlPub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("Go verifier rejected a Python-generated hybrid signature")
	}
}
