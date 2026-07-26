// Go side of the shared Authority Freshness interop vector.
//
// Loads test-vectors/authority-state/vector.json and asserts that Go reproduces
// proofValue byte-for-byte, verifies the shared credential, rejects a
// stale-epoch tamper, and reaches the same allow/reason on every freshness case
// as the Rust core, the TypeScript SDK, and Python.

package signer

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type authorityVector struct {
	Ed25519 struct {
		SeedB64      string `json:"seed_b64"`
		PublicKeyB64 string `json:"public_key_b64"`
	} `json:"ed25519"`
	VerificationMethod string         `json:"verificationMethod"`
	Created            string         `json:"created"`
	UnsignedCredential map[string]any `json:"unsigned_credential"`
	SignedCredential   map[string]any `json:"signed_credential"`
	ProofValue         string         `json:"proofValue"`
	Freshness          struct {
		Cases []struct {
			Name           string  `json:"name"`
			Tier           string  `json:"tier"`
			VoucherEpoch   *int64  `json:"voucher_epoch"`
			LastSeenEpoch  *int64  `json:"last_seen_epoch"`
			CurrentStatus  *string `json:"current_status"`
			LiveCosignOK   *bool   `json:"live_cosign_ok"`
			ExpectedAllow  bool    `json:"expected_allow"`
			ExpectedReason string  `json:"expected_reason"`
		} `json:"cases"`
	} `json:"freshness"`
}

func loadAuthorityVector(t *testing.T) authorityVector {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	repoRoot := filepath.Clean(filepath.Join(wd, "..", ".."))
	vecPath := filepath.Join(repoRoot, "test-vectors", "authority-state", "vector.json")
	raw, err := os.ReadFile(vecPath)
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v authorityVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	return v
}

func TestAuthorityStateReproducesProofValue(t *testing.T) {
	v := loadAuthorityVector(t)
	seed, err := base64.StdEncoding.DecodeString(v.Ed25519.SeedB64)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	created, err := time.Parse("2006-01-02T15:04:05Z", v.Created)
	if err != nil {
		t.Fatalf("parse created: %v", err)
	}
	proof, err := BuildDataIntegrityProof(v.UnsignedCredential, BuildProofOptions{
		PrivateKey:         ed25519.NewKeyFromSeed(seed),
		VerificationMethod: v.VerificationMethod,
		Created:            created,
	})
	if err != nil {
		t.Fatalf("build proof: %v", err)
	}
	if proof.ProofValue != v.ProofValue {
		t.Fatalf("proofValue mismatch:\n got %s\nwant %s", proof.ProofValue, v.ProofValue)
	}
}

func TestAuthorityStateVerifiesAndRejectsTamper(t *testing.T) {
	v := loadAuthorityVector(t)
	pubRaw, err := base64.StdEncoding.DecodeString(v.Ed25519.PublicKeyB64)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	pub := ed25519.PublicKey(pubRaw)

	res, err := VerifyAuthorityState(v.SignedCredential, pub, "2026-07-26T10:02:00Z", 30)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.IsValid() {
		t.Fatalf("expected valid credential, got %+v", res)
	}

	// Tamper the epoch after signing; the proof must no longer verify.
	tampered := map[string]any{}
	raw, _ := json.Marshal(v.SignedCredential)
	_ = json.Unmarshal(raw, &tampered)
	tampered["credentialSubject"].(map[string]any)["authorityEpoch"] = float64(999)
	res2, err := VerifyAuthorityState(tampered, pub, "2026-07-26T10:02:00Z", 30)
	if err != nil {
		t.Fatalf("verify tampered: %v", err)
	}
	if res2.ProofValid {
		t.Fatal("expected tampered credential to fail proof verification")
	}
}

func TestAuthorityStateFreshnessCasesMatch(t *testing.T) {
	v := loadAuthorityVector(t)
	for _, c := range v.Freshness.Cases {
		status := ""
		if c.CurrentStatus != nil {
			status = *c.CurrentStatus
		}
		verdict := EvaluateAuthorityFreshness(c.Tier, c.VoucherEpoch, c.LastSeenEpoch, status, c.LiveCosignOK)
		if verdict.Allow != c.ExpectedAllow {
			t.Fatalf("%s: allow mismatch got %v want %v", c.Name, verdict.Allow, c.ExpectedAllow)
		}
		if c.ExpectedReason != "" && verdict.Reason != c.ExpectedReason {
			t.Fatalf("%s: reason mismatch got %q want %q", c.Name, verdict.Reason, c.ExpectedReason)
		}
	}
}

func TestAuthorityStateBuildShape(t *testing.T) {
	cred, err := BuildAuthorityState(BuildAuthorityStateOptions{
		IssuerDID:      "did:web:treasury.example.com",
		AuthorityEpoch: 7,
		Status:         StatusActive,
		CredentialID:   "urn:uuid:00000000-0000-4000-8000-000000000000",
		ValidFrom:      time.Date(2026, 7, 26, 10, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	subject := cred["credentialSubject"].(map[string]any)
	if subject["authorityEpoch"].(int64) != 7 {
		t.Fatalf("epoch mismatch: %v", subject["authorityEpoch"])
	}
	if subject["status"].(string) != "active" {
		t.Fatalf("status mismatch: %v", subject["status"])
	}
}
