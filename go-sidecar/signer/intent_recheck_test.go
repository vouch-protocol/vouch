package signer

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func epochToISO(sec int64) string {
	return time.Unix(sec, 0).UTC().Format("2006-01-02T15:04:05Z")
}

// --- Shared cross-language interop vector -----------------------------------

type intentVector struct {
	PublicKeyHex                string         `json:"public_key_hex"`
	ReferenceJustification      map[string]any `json:"reference_justification"`
	ExpectedJustificationDigest string         `json:"expected_justification_digest"`
	ExpectedArtifactDigest      string         `json:"expected_artifact_digest"`
	Cases                       []intentCase   `json:"cases"`
}

type intentCase struct {
	Name           string         `json:"name"`
	Tier           int            `json:"tier"`
	LastPulse      string         `json:"last_pulse"`
	Credential     map[string]any `json:"credential"`
	ExpectedReason *string        `json:"expected_reason"`
}

func loadIntentVector(t *testing.T) intentVector {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	repoRoot := filepath.Clean(filepath.Join(wd, "..", ".."))
	raw, err := os.ReadFile(filepath.Join(repoRoot, "test-vectors", "intent-recheck", "vector.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v intentVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode vector: %v", err)
	}
	return v
}

// The Go port must agree with the Python-generated vector on the SAME bytes: a
// Python-signed seal verifies here, justification_digest recomputes byte for byte,
// and VerifyIntentFreshness returns the SAME reason for every case.
func TestIntentRecheckSharedVector(t *testing.T) {
	v := loadIntentVector(t)
	pubBytes, err := hex.DecodeString(v.PublicKeyHex)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	pub := ed25519.PublicKey(pubBytes)

	digest, err := JustificationDigest(v.ReferenceJustification)
	if err != nil {
		t.Fatalf("justification digest: %v", err)
	}
	if digest != v.ExpectedJustificationDigest {
		t.Fatalf("justification digest mismatch: got %s want %s", digest, v.ExpectedJustificationDigest)
	}

	art, err := ArtifactDigest(map[string]any{"text": "please move $500 to savings"})
	if err != nil {
		t.Fatalf("artifact digest: %v", err)
	}
	if art != v.ExpectedArtifactDigest {
		t.Fatalf("artifact digest mismatch: got %s want %s", art, v.ExpectedArtifactDigest)
	}

	for _, c := range v.Cases {
		ok, err := VerifyDataIntegrityProof(c.Credential, pub)
		if err != nil || !ok {
			t.Fatalf("case %s: Python-signed credential must verify in Go (ok=%v err=%v)", c.Name, ok, err)
		}
		if reason := CheckReasonedAction(c.Credential, pub, nil, false); reason != "" {
			t.Fatalf("case %s: CheckReasonedAction should pass, got %q", c.Name, reason)
		}
		got, err := VerifyIntentFreshness(c.Credential, c.Tier, c.LastPulse, DefaultRequirement(c.Tier))
		if err != nil {
			t.Fatalf("case %s: verify intent freshness: %v", c.Name, err)
		}
		want := ""
		if c.ExpectedReason != nil {
			want = *c.ExpectedReason
		}
		if got != want {
			t.Fatalf("case %s: verdict mismatch: got %q want %q", c.Name, got, want)
		}
	}
}

// --- Accept / reject matrix (built in Go) -----------------------------------

const (
	testPulse = "2026-08-02T10:00:00Z"
)

func testKey(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 7
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, priv.Public().(ed25519.PublicKey)
}

func testIntent() map[string]any {
	return map[string]any{"action": "transfer_funds", "target": "account:9911", "resource": "/v1/xfer"}
}

func testAnchors(t *testing.T) []map[string]any {
	t.Helper()
	a, err := EvidenceAnchor("user asked", "urn:msg:42", map[string]any{"text": "go"}, "", "user_message")
	if err != nil {
		t.Fatal(err)
	}
	return []map[string]any{a}
}

func sealedAction(t *testing.T, sealedAt, execAt string, tier int) (map[string]any, ed25519.PublicKey) {
	t.Helper()
	priv, pub := testKey(t)
	level := tier
	just, err := BuildJustification(testIntent(), testAnchors(t), &level)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := SignReasonedAction(priv, "did:web:agent.example", "did:web:agent.example#key-1",
		testIntent(), just, execAt, "urn:uuid:test", SignReasonedActionOptions{IncludeReasoning: true, SealedAt: sealedAt})
	if err != nil {
		t.Fatal(err)
	}
	return cred, pub
}

func TestFreshSealInWindowAccepts(t *testing.T) {
	cred, pub := sealedAction(t, "2026-08-02T10:00:10Z", "2026-08-02T10:00:20Z", TierHigh)
	if reason, _ := VerifyIntentFreshness(cred, TierHigh, testPulse, DefaultRequirement(TierHigh)); reason != "" {
		t.Fatalf("expected accept, got %q", reason)
	}
	if r := CheckReasonedAction(cred, pub, nil, false); r != "" {
		t.Fatalf("signature/commitment should verify, got %q", r)
	}
}

func TestStaleSealInGapRejects(t *testing.T) {
	// attacker times the action: sealed before the pulse, executed after it
	cred, _ := sealedAction(t, "2026-08-02T09:59:50Z", "2026-08-02T10:00:20Z", TierHigh)
	reason, _ := VerifyIntentFreshness(cred, TierHigh, testPulse, DefaultRequirement(TierHigh))
	want := "intent_seal_stale:sealed_at=2026-08-02T09:59:50Z,last_pulse=2026-08-02T10:00:00Z"
	if reason != want {
		t.Fatalf("expected %q, got %q", want, reason)
	}
}

func TestFreshResealInGapAccepts(t *testing.T) {
	priv, pub := testKey(t)
	level := TierHigh
	now := "2026-08-02T10:05:00Z"
	cred, err := ResealIntent(priv, "did:web:agent.example", "did:web:agent.example#key-1",
		testIntent(), testAnchors(t), &level, now, "urn:uuid:reseal", true)
	if err != nil {
		t.Fatal(err)
	}
	if reason, _ := VerifyIntentFreshness(cred, TierHigh, now, DefaultRequirement(TierHigh)); reason != "" {
		t.Fatalf("expected accept after reseal, got %q", reason)
	}
	if r := CheckReasonedAction(cred, pub, nil, false); r != "" {
		t.Fatalf("resealed credential should verify, got %q", r)
	}
	if got := SealTimestamp(cred); got != now {
		t.Fatalf("seal timestamp: got %q want %q", got, now)
	}
}

func TestNonSensitiveTierIgnoresStaleSeal(t *testing.T) {
	cred, _ := sealedAction(t, "2026-08-02T09:59:50Z", "2026-08-02T10:00:20Z", TierRoutine)
	if reason, _ := VerifyIntentFreshness(cred, TierRoutine, testPulse, DefaultRequirement(TierRoutine)); reason != "" {
		t.Fatalf("routine tier should accept a stale seal, got %q", reason)
	}
}

func TestSensitiveTierWithoutSealIsMissing(t *testing.T) {
	priv, _ := testKey(t)
	level := TierHigh
	just, _ := BuildJustification(testIntent(), testAnchors(t), &level)
	cred, err := SignReasonedAction(priv, "did:web:agent.example", "did:web:agent.example#key-1",
		testIntent(), just, "2026-08-02T10:00:20Z", "urn:uuid:noseal", SignReasonedActionOptions{IncludeReasoning: true})
	if err != nil {
		t.Fatal(err)
	}
	reason, _ := VerifyIntentFreshness(cred, TierHigh, testPulse, DefaultRequirement(TierHigh))
	if reason != "intent_seal_missing:tier=3" {
		t.Fatalf("expected intent_seal_missing:tier=3, got %q", reason)
	}
}

// An attacker timing an action mid-interval still hits the seal, across a sweep of
// gap positions.
func TestAdversarialTimingStillHitsSeal(t *testing.T) {
	for offset := int64(65); offset < 600; offset += 45 {
		sealed := "2026-08-02T09:59:55Z" // just before the 10:00:00 pulse
		execEpoch, _ := isoEpoch(testPulse)
		execAt := epochToISO(execEpoch + offset)
		crossed := epochToISO(execEpoch + (offset/60)*60)
		cred, _ := sealedAction(t, sealed, execAt, TierHigh)
		reason, err := VerifyIntentFreshness(cred, TierHigh, crossed, DefaultRequirement(TierHigh))
		if err != nil {
			t.Fatal(err)
		}
		if reason == "" || reason[:len(ReasonIntentSealStale)] != ReasonIntentSealStale {
			t.Fatalf("offset %d: expected stale rejection, got %q", offset, reason)
		}
	}
}

func TestDefaultPolicyBands(t *testing.T) {
	if DefaultRequirement(TierRoutine).RequireFreshSeal {
		t.Fatal("routine must not require a fresh seal")
	}
	if !DefaultRequirement(TierHigh).RequireFreshSeal || DefaultRequirement(TierHigh).MaxAgeSeconds != 300 {
		t.Fatal("high tier policy wrong")
	}
	if DefaultRequirement(TierCritical).MaxAgeSeconds != 60 {
		t.Fatal("critical tier policy wrong")
	}
}
