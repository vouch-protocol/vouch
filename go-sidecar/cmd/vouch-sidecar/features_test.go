package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

const intentFields = `"intent":{"action":"read.file","target":"report","resource":"https://api.example.com/reports/1"}`

func window(t *testing.T, cred map[string]any) time.Duration {
	t.Helper()
	from, err1 := time.Parse(time.RFC3339, cred["validFrom"].(string))
	until, err2 := time.Parse(time.RFC3339, cred["validUntil"].(string))
	if err1 != nil || err2 != nil {
		t.Fatalf("bad window %v to %v", cred["validFrom"], cred["validUntil"])
	}
	return until.Sub(from)
}

// ---------------------------------------------------------------------------
// Validity: the caller chooses, the operator sets the default and the ceiling
// ---------------------------------------------------------------------------

func TestCallerChoosesValidityAndGetsTheDefaultOtherwise(t *testing.T) {
	h := localHandler(t, newTestSigner(t), serverConfig{defaultValidSeconds: 900, maxValidSeconds: 7200})

	cases := map[string]time.Duration{
		`{` + intentFields + `}`:                      15 * time.Minute, // nothing asked: the default
		`{` + intentFields + `,"validSeconds":0}`:     15 * time.Minute,
		`{` + intentFields + `,"validSeconds":60}`:    time.Minute,
		`{` + intentFields + `,"validSeconds":7200}`:  2 * time.Hour, // exactly the ceiling
		`{` + intentFields + `,"valid_seconds":1800}`: 30 * time.Minute,
	}
	for body, want := range cases {
		rec := do(t, h, http.MethodPost, "/sign", body)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", body, rec.Code, rec.Body.String())
		}
		if got := window(t, decode(t, rec)); got != want {
			t.Fatalf("%s: valid for %s, want %s", body, got, want)
		}
	}

	rec := do(t, h, http.MethodPost, "/sign", `{`+intentFields+`,"validSeconds":7201}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("past the ceiling: status %d, want 400", rec.Code)
	}
	if msg := rec.Body.String(); !strings.Contains(msg, "7200") || !strings.Contains(msg, "900") {
		t.Fatalf("the refusal should state the ceiling and the default: %s", msg)
	}
}

func TestChangingTheDefaultChangesWhatCallersGet(t *testing.T) {
	s := newTestSigner(t)
	for _, seconds := range []int{30, 300, 3600} {
		h := localHandler(t, s, serverConfig{defaultValidSeconds: seconds, maxValidSeconds: 3600})
		rec := do(t, h, http.MethodPost, "/sign", `{`+intentFields+`}`)
		if got := window(t, decode(t, rec)); got != time.Duration(seconds)*time.Second {
			t.Fatalf("default %ds: valid for %s", seconds, got)
		}
	}
}

func TestValidityWindow(t *testing.T) {
	def, max, err := validityWindow(10*time.Minute, 2*time.Hour)
	if err != nil || def != 600 || max != 7200 {
		t.Fatalf("got %d, %d, %v", def, max, err)
	}
	if def, max, err := validityWindow(time.Hour, time.Hour); err != nil || def != max {
		t.Fatalf("default equal to the ceiling should be fine: %v", err)
	}
	bad := map[string][2]time.Duration{
		"default past the ceiling": {2 * time.Hour, time.Hour},
		"zero default":             {0, time.Hour},
		"negative default":         {-time.Minute, time.Hour},
		"sub-second default":       {500 * time.Millisecond, time.Hour},
	}
	for name, pair := range bad {
		if _, _, err := validityWindow(pair[0], pair[1]); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Post-quantum proof set
// ---------------------------------------------------------------------------

func proofs(cred map[string]any) []string {
	var suites []string
	switch p := cred["proof"].(type) {
	case map[string]any:
		suites = append(suites, p["cryptosuite"].(string))
	case []any:
		for _, each := range p {
			suites = append(suites, each.(map[string]any)["cryptosuite"].(string))
		}
	}
	return suites
}

func TestHybridModeSignsWithBothProofs(t *testing.T) {
	s := newTestSigner(t)
	plain := localHandler(t, s, serverConfig{})
	hybrid := localHandler(t, s, serverConfig{hybrid: true})

	if got := proofs(decode(t, do(t, plain, http.MethodPost, "/sign", goodIntent))); len(got) != 1 || got[0] != "eddsa-jcs-2022" {
		t.Fatalf("default /sign proofs = %v", got)
	}
	for name, rec := range map[string]map[string]any{
		"--hybrid /sign":         decode(t, do(t, hybrid, http.MethodPost, "/sign", goodIntent)),
		"/sign/hybrid, any mode": decode(t, do(t, plain, http.MethodPost, "/sign/hybrid", goodIntent)),
	} {
		got := proofs(rec)
		if len(got) != 2 || got[0] == got[1] {
			t.Fatalf("%s: proofs = %v, want an eddsa-jcs-2022 and an mldsa44-jcs-2024 proof", name, got)
		}
		joined := strings.Join(got, " ")
		if !strings.Contains(joined, "eddsa-jcs-2022") || !strings.Contains(joined, "mldsa44-jcs-2024") {
			t.Fatalf("%s: proofs = %v", name, got)
		}
	}
}

func TestHybridCredentialNeedsBothKeysToVerify(t *testing.T) {
	s := newTestSigner(t)
	h := localHandler(t, s, serverConfig{hybrid: true})
	cred := decode(t, do(t, h, http.MethodPost, "/sign", goodIntent))

	if ok, _, err := signer.Verify(cred, s.PublicKeyEd25519(), 30, s.PublicKeyMLDSA44()); err != nil || !ok {
		t.Fatalf("did not verify with both keys: ok=%v err=%v", ok, err)
	}
	// Only the Ed25519 key at hand: the second proof is unchecked, so no pass.
	if ok, _, _ := signer.Verify(cred, s.PublicKeyEd25519(), 30); ok {
		t.Fatal("verified on the Ed25519 proof alone")
	}
	other := newTestSigner(t)
	if ok, _, _ := signer.Verify(cred, s.PublicKeyEd25519(), 30, other.PublicKeyMLDSA44()); ok {
		t.Fatal("verified under another signer's ML-DSA-44 key")
	}
	if ok, _, _ := signer.Verify(cred, other.PublicKeyEd25519(), 30, s.PublicKeyMLDSA44()); ok {
		t.Fatal("verified under another signer's Ed25519 key")
	}
	subject := cred["credentialSubject"].(map[string]any)
	subject["intent"].(map[string]any)["action"] = "ledger.transfer"
	if ok, _, _ := signer.Verify(cred, s.PublicKeyEd25519(), 30, s.PublicKeyMLDSA44()); ok {
		t.Fatal("an altered credential still verified")
	}
}

func TestHybridEndpointKeepsEveryGuard(t *testing.T) {
	s := newTestSigner(t)
	guarded := localHandler(t, s, serverConfig{token: "t0ken", allowedActions: map[string]bool{"read.file": true}, maxValidSeconds: 600})
	auth := func(r *http.Request) { r.Header.Set("Authorization", "Bearer t0ken") }

	cases := []struct {
		name string
		body string
		edit func(*http.Request)
		want int
	}{
		{"allowed", goodIntent, auth, http.StatusOK},
		{"no token", goodIntent, func(*http.Request) {}, http.StatusUnauthorized},
		{"off the allow-list", `{"intent":{"action":"ledger.transfer","target":"t","resource":"r"}}`, auth, http.StatusForbidden},
		{"past the ceiling", `{` + intentFields + `,"validSeconds":601}`, auth, http.StatusBadRequest},
		{"payload form", `{"payload":{"action":"read.file"}}`, auth, http.StatusBadRequest},
		{"no intent", `{}`, auth, http.StatusBadRequest},
	}
	for _, c := range cases {
		if rec := do(t, guarded, http.MethodPost, "/sign/hybrid", c.body, c.edit); rec.Code != c.want {
			t.Fatalf("%s: status %d, want %d (%s)", c.name, rec.Code, c.want, rec.Body.String())
		}
	}
	if rec := do(t, guarded, http.MethodGet, "/sign/hybrid", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: status %d", rec.Code)
	}
	sensitive := localHandler(t, s, serverConfig{sensitive: true})
	if rec := do(t, sensitive, http.MethodPost, "/sign/hybrid", goodIntent); rec.Code != http.StatusBadRequest {
		t.Fatalf("sensitive mode: status %d, want 400", rec.Code)
	}
}

func TestPostQuantumKeyIsPublished(t *testing.T) {
	s := newTestSigner(t)
	wantPQ, err := s.PublicKeyMLDSA44Multikey()
	if err != nil {
		t.Fatal(err)
	}

	pub := decode(t, do(t, localHandler(t, s, serverConfig{}), http.MethodGet, "/pubkey", ""))
	pq, _ := pub["mldsa44"].(map[string]any)
	if pq["publicKeyMultibase"] != wantPQ || pq["verificationMethod"] != testDID+"#key-2" {
		t.Fatalf("/pubkey mldsa44 = %v", pq)
	}
	if algorithm, _, err := signer.MultikeyDecode(wantPQ); err != nil || algorithm != "ML-DSA-44" {
		t.Fatalf("published key is %q (%v)", algorithm, err)
	}

	methodsOf := func(hybrid bool) []any {
		doc := decode(t, do(t, localHandler(t, s, serverConfig{hybrid: hybrid}), http.MethodGet, "/.well-known/did.json", ""))
		methods, _ := doc["verificationMethod"].([]any)
		return methods
	}
	if got := methodsOf(false); len(got) != 1 {
		t.Fatalf("classical DID document lists %d keys, want 1", len(got))
	}
	got := methodsOf(true)
	if len(got) != 2 {
		t.Fatalf("hybrid DID document lists %d keys, want 2", len(got))
	}
	second := got[1].(map[string]any)
	if second["id"] != testDID+"#key-2" || second["type"] != "Multikey" || second["publicKeyMultibase"] != wantPQ {
		t.Fatalf("second key = %v", second)
	}
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

func TestHealthReportsTheLastSignature(t *testing.T) {
	h := localHandler(t, newTestSigner(t), serverConfig{keySource: keyFromKeystore, defaultValidSeconds: 120, maxValidSeconds: 600})
	health := func() map[string]any { return decode(t, do(t, h, http.MethodGet, "/health", "")) }

	before := health()
	if before["ready"] != true || before["lastSignedAt"] != nil || before["key"] != keyFromKeystore {
		t.Fatalf("health before signing = %v", before)
	}
	if before["defaultValiditySeconds"] != float64(120) || before["maxValiditySeconds"] != float64(600) {
		t.Fatalf("health does not show the validity settings: %v", before)
	}

	// A refused request is not a signature.
	do(t, h, http.MethodPost, "/sign", `{}`)
	if health()["lastSignedAt"] != nil {
		t.Fatal("a refused request moved lastSignedAt")
	}

	started := time.Now().Add(-2 * time.Second)
	do(t, h, http.MethodPost, "/sign", goodIntent)
	at, err := time.Parse(time.RFC3339, health()["lastSignedAt"].(string))
	if err != nil || at.Before(started) || at.After(time.Now().Add(2*time.Second)) {
		t.Fatalf("lastSignedAt = %v (%v)", health()["lastSignedAt"], err)
	}
}

// ---------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------

func logLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var lines []map[string]any
	for _, raw := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if raw == "" {
			continue
		}
		var line map[string]any
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			t.Fatalf("log line is not JSON: %q", raw)
		}
		lines = append(lines, line)
	}
	return lines
}

func TestLogsAreJSONAndCarryNoSecrets(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := localHandler(t, newTestSigner(t), serverConfig{token: "s3cret-token-value", logger: logger})

	body := `{"intent":{"action":"read.file","target":"report","resource":"https://api.example.com/private/customer-8842"}}`
	do(t, h, http.MethodPost, "/sign", body, func(r *http.Request) { r.Header.Set("Authorization", "Bearer s3cret-token-value") })
	do(t, h, http.MethodPost, "/sign", body, func(r *http.Request) { r.Header.Set("Authorization", "Bearer wrong-guess") })

	var signed, refused map[string]any
	for _, line := range logLines(t, &buf) {
		switch line["msg"] {
		case "signed":
			signed = line
		case "refused":
			refused = line
		}
	}
	if signed == nil || signed["action"] != "read.file" || signed["did"] != testDID ||
		!strings.HasPrefix(signed["credential_id"].(string), "urn:uuid:") || signed["proof"] != "eddsa-jcs-2022" {
		t.Fatalf("signed line = %v", signed)
	}
	if refused == nil || refused["status"] != float64(http.StatusUnauthorized) || refused["reason"] == "" {
		t.Fatalf("refused line = %v", refused)
	}
	for _, secret := range []string{"s3cret-token-value", "wrong-guess", "customer-8842", `"d"`, "proofValue"} {
		if strings.Contains(buf.String(), secret) {
			t.Fatalf("log output contains %q:\n%s", secret, buf.String())
		}
	}
}

func TestVerboseLogsEveryRequestAndQuietDoesNot(t *testing.T) {
	count := func(level slog.Level) int {
		var buf bytes.Buffer
		h := localHandler(t, newTestSigner(t), serverConfig{logger: slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: level}))})
		do(t, h, http.MethodGet, "/health", "")
		do(t, h, http.MethodGet, "/pubkey", "")
		n := 0
		for _, line := range logLines(t, &buf) {
			if line["msg"] == "request" {
				n++
			}
		}
		return n
	}
	if got := count(slog.LevelDebug); got != 2 {
		t.Fatalf("verbose logged %d request lines, want 2", got)
	}
	if got := count(slog.LevelInfo); got != 0 {
		t.Fatalf("default level logged %d request lines, want 0", got)
	}
}

func TestOversizedActionIsClippedInLogs(t *testing.T) {
	var buf bytes.Buffer
	h := localHandler(t, newTestSigner(t), serverConfig{logger: slog.New(slog.NewJSONHandler(&buf, nil))})
	long := strings.Repeat("a", 5000)
	do(t, h, http.MethodPost, "/sign", `{"intent":{"action":"`+long+`","target":"t","resource":"r"}}`)

	for _, line := range logLines(t, &buf) {
		if action, _ := line["action"].(string); len(action) > maxLoggedText {
			t.Fatalf("logged action is %d characters long", len(action))
		}
	}
}
