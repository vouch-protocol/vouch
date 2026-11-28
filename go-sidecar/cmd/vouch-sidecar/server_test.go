package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

const testDID = "did:web:agent.example.com"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestSigner(t *testing.T) *signer.Signer {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	s, err := signer.New(signer.Config{DID: testDID, Ed25519Seed: seed})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// do sends a request the way a local client would: loopback Host, JSON body.
func do(t *testing.T, h http.Handler, method, path, body string, edit ...func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "127.0.0.1:8877"
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, e := range edit {
		e(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func localHandler(t *testing.T, s *signer.Signer, cfg serverConfig) http.Handler {
	t.Helper()
	cfg.did = testDID
	cfg.loopbackOnly = true
	return newHandler(s, cfg)
}

const goodIntent = `{"intent":{"action":"read.file","target":"report","resource":"https://api.example.com/reports/1"}}`

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not JSON: %v (%s)", err, rec.Body.String())
	}
	return out
}

func privateJWK(t *testing.T, seed []byte) map[string]string {
	t.Helper()
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	return map[string]string{
		"kty": "OKP",
		"crv": "Ed25519",
		"d":   base64.RawURLEncoding.EncodeToString(seed),
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ---------------------------------------------------------------------------
// Listening address and allow-list
// ---------------------------------------------------------------------------

func TestCheckExposure(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "localhost", "LOCALHOST", "::1", "[::1]", "127.0.0.53"} {
		if err := checkExposure(host, ""); err != nil {
			t.Fatalf("%q should be allowed without a token: %v", host, err)
		}
	}
	for _, host := range []string{"0.0.0.0", "", "::", "192.168.1.20", "sidecar.internal", "127.0.0.1.example.com"} {
		if err := checkExposure(host, ""); err == nil {
			t.Fatalf("%q must need a token", host)
		}
		if err := checkExposure(host, "s3cret"); err != nil {
			t.Fatalf("%q with a token should be allowed: %v", host, err)
		}
	}
}

func TestLoadAllowlist(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	good := write("good.json", `{"version":1,"issuer":"`+testDID+`","actions":[{"name":"read.file"},{"name":"http.post"},{"name":""}]}`)
	allowed, err := loadAllowlist(good, testDID)
	if err != nil {
		t.Fatal(err)
	}
	if len(allowed) != 2 || !allowed["read.file"] || !allowed["http.post"] {
		t.Fatalf("allowed = %v", allowed)
	}

	if _, err := loadAllowlist(good, "did:web:someone-else.example"); err == nil {
		t.Fatal("an allow-list written for another issuer must be refused")
	}
	if _, err := loadAllowlist(write("empty.json", `{"actions":[]}`), testDID); err == nil {
		t.Fatal("an allow-list with no actions must be refused")
	}
	if _, err := loadAllowlist(write("bad.json", `{"actions":`), testDID); err == nil {
		t.Fatal("invalid JSON must be refused")
	}
	if _, err := loadAllowlist(filepath.Join(dir, "missing.json"), testDID); err == nil {
		t.Fatal("a missing allow-list must be an error")
	}
}

// ---------------------------------------------------------------------------
// POST /sign, credential form
// ---------------------------------------------------------------------------

func TestSignReturnsAVerifiableCredential(t *testing.T) {
	s := newTestSigner(t)
	h := localHandler(t, s, serverConfig{})

	rec := do(t, h, http.MethodPost, "/sign", goodIntent)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	cred := decode(t, rec)
	if cred["issuer"] != testDID {
		t.Fatalf("issuer = %v", cred["issuer"])
	}

	ok, passport, err := signer.Verify(cred, s.PublicKeyEd25519(), 30)
	if err != nil || !ok {
		t.Fatalf("credential did not verify: ok=%v err=%v", ok, err)
	}
	if passport.Action() != "read.file" {
		t.Fatalf("action = %q", passport.Action())
	}

	// The same credential must fail under any other key, and once altered.
	if ok, _, _ := signer.Verify(cred, newTestSigner(t).PublicKeyEd25519(), 30); ok {
		t.Fatal("credential verified under a different key")
	}
	subject := cred["credentialSubject"].(map[string]any)
	subject["intent"].(map[string]any)["action"] = "ledger.transfer"
	if ok, _, _ := signer.Verify(cred, s.PublicKeyEd25519(), 30); ok {
		t.Fatal("an altered credential still verified")
	}
}

func TestSignRejectsMalformedRequests(t *testing.T) {
	h := localHandler(t, newTestSigner(t), serverConfig{})
	cases := map[string]string{
		"no intent":          `{}`,
		"flat fields":        `{"issuer":"did:web:x","action":"read.file","args":{}}`,
		"missing resource":   `{"intent":{"action":"a","target":"t"}}`,
		"empty action":       `{"intent":{"action":"","target":"t","resource":"r"}}`,
		"non-string action":  `{"intent":{"action":["a"],"target":"t","resource":"r"}}`,
		"intent and payload": `{"intent":{"action":"a","target":"t","resource":"r"},"payload":{"x":1}}`,
		"not json":           `{"intent":`,
		"negative validity":  `{"intent":{"action":"a","target":"t","resource":"r"},"validSeconds":-5}`,
	}
	for name, body := range cases {
		if rec := do(t, h, http.MethodPost, "/sign", body); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status %d, want 400 (%s)", name, rec.Code, rec.Body.String())
		}
	}
}

func TestSignRequiresPostAndJSON(t *testing.T) {
	h := localHandler(t, newTestSigner(t), serverConfig{})

	if rec := do(t, h, http.MethodGet, "/sign", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /sign: status %d", rec.Code)
	}
	for _, contentType := range []string{"", "text/plain", "application/x-www-form-urlencoded"} {
		rec := do(t, h, http.MethodPost, "/sign", goodIntent, func(r *http.Request) {
			r.Header.Del("Content-Type")
			if contentType != "" {
				r.Header.Set("Content-Type", contentType)
			}
		})
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("Content-Type %q: status %d, want 415", contentType, rec.Code)
		}
	}
	rec := do(t, h, http.MethodPost, "/sign", goodIntent, func(r *http.Request) {
		r.Header.Set("Content-Type", "application/json; charset=utf-8")
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("JSON with a charset: status %d", rec.Code)
	}
}

func TestSignRejectsOversizedBody(t *testing.T) {
	h := localHandler(t, newTestSigner(t), serverConfig{})
	huge := `{"intent":{"action":"a","target":"t","resource":"` + strings.Repeat("x", maxBodyBytes) + `"}}`
	if rec := do(t, h, http.MethodPost, "/sign", huge); rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
}

func TestSignEnforcesTheToken(t *testing.T) {
	h := localHandler(t, newTestSigner(t), serverConfig{token: "correct-horse"})

	attempts := map[string]string{
		"none":         "",
		"wrong":        "Bearer wrong-horse",
		"prefix only":  "Bearer ",
		"no scheme":    "correct-horse",
		"basic scheme": "Basic correct-horse",
		"longer":       "Bearer correct-horse-and-more",
		"shorter":      "Bearer correct",
	}
	for name, header := range attempts {
		rec := do(t, h, http.MethodPost, "/sign", goodIntent, func(r *http.Request) {
			if header != "" {
				r.Header.Set("Authorization", header)
			}
		})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status %d, want 401", name, rec.Code)
		}
	}

	rec := do(t, h, http.MethodPost, "/sign", goodIntent, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer correct-horse")
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("right token: status %d: %s", rec.Code, rec.Body.String())
	}

	// Public endpoints stay open so health checks keep working.
	if rec := do(t, h, http.MethodGet, "/health", ""); rec.Code != http.StatusOK {
		t.Fatalf("/health with a token configured: status %d", rec.Code)
	}
}

func TestSignEnforcesTheAllowlist(t *testing.T) {
	h := localHandler(t, newTestSigner(t), serverConfig{allowedActions: map[string]bool{"read.file": true}})

	if rec := do(t, h, http.MethodPost, "/sign", goodIntent); rec.Code != http.StatusOK {
		t.Fatalf("allowed action: status %d: %s", rec.Code, rec.Body.String())
	}

	denied := map[string]string{
		"other action":           `{"intent":{"action":"ledger.transfer","target":"t","resource":"r"}}`,
		"case variant":           `{"intent":{"action":"READ.FILE","target":"t","resource":"r"}}`,
		"padded":                 `{"intent":{"action":"read.file ","target":"t","resource":"r"}}`,
		"payload, other action":  `{"payload":{"action":"ledger.transfer"}}`,
		"payload, no action":     `{"payload":{"note":"hi"}}`,
		"payload, action object": `{"payload":{"action":{"name":"read.file"}}}`,
	}
	for name, body := range denied {
		if rec := do(t, h, http.MethodPost, "/sign", body); rec.Code != http.StatusForbidden {
			t.Fatalf("%s: status %d, want 403 (%s)", name, rec.Code, rec.Body.String())
		}
	}
}

func TestSignCapsValidity(t *testing.T) {
	h := localHandler(t, newTestSigner(t), serverConfig{maxValidSeconds: 600})
	intent := `"intent":{"action":"a","target":"t","resource":"r"}`

	for name, body := range map[string]string{
		"over the cap":          `{` + intent + `,"validSeconds":601}`,
		"over the cap, alias":   `{` + intent + `,"valid_seconds":86400}`,
		"payload, over the cap": `{"payload":{"action":"a"},"expiry_seconds":601}`,
	} {
		if rec := do(t, h, http.MethodPost, "/sign", body); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status %d, want 400", name, rec.Code)
		}
	}

	for field, want := range map[string]time.Duration{
		`"validSeconds":120`:  120 * time.Second,
		`"valid_seconds":600`: 600 * time.Second,
	} {
		rec := do(t, h, http.MethodPost, "/sign", `{`+intent+`,`+field+`}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", field, rec.Code, rec.Body.String())
		}
		cred := decode(t, rec)
		from, err1 := time.Parse(time.RFC3339, cred["validFrom"].(string))
		until, err2 := time.Parse(time.RFC3339, cred["validUntil"].(string))
		if err1 != nil || err2 != nil || until.Sub(from) != want {
			t.Fatalf("%s: window %v to %v", field, cred["validFrom"], cred["validUntil"])
		}
	}
}

func TestSensitiveModeRefusesThePlainCredentialForm(t *testing.T) {
	h := localHandler(t, newTestSigner(t), serverConfig{sensitive: true})
	if rec := do(t, h, http.MethodPost, "/sign", goodIntent); rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// POST /sign, token form
// ---------------------------------------------------------------------------

func TestSignPayloadReturnsAToken(t *testing.T) {
	h := localHandler(t, newTestSigner(t), serverConfig{})
	rec := do(t, h, http.MethodPost, "/sign", `{"payload":{"action":"read.file","note":"hello"}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	out := decode(t, rec)
	if token, _ := out["token"].(string); token == "" {
		t.Fatalf("no token in %v", out)
	}
	if out["mode"] != "standard" {
		t.Fatalf("mode = %v", out["mode"])
	}
}

// ---------------------------------------------------------------------------
// Host check and the read-only endpoints
// ---------------------------------------------------------------------------

func TestLocalSidecarIgnoresForeignHostNames(t *testing.T) {
	s := newTestSigner(t)
	local := localHandler(t, s, serverConfig{})

	for _, host := range []string{"evil.example:8877", "evil.example", "127.0.0.1.evil.example:8877", "10.0.0.5:8877", ""} {
		for _, path := range []string{"/sign", "/pubkey", "/health"} {
			method, body := http.MethodGet, ""
			if path == "/sign" {
				method, body = http.MethodPost, goodIntent
			}
			rec := do(t, local, method, path, body, func(r *http.Request) { r.Host = host })
			if rec.Code != http.StatusForbidden {
				t.Fatalf("Host %q %s: status %d, want 403", host, path, rec.Code)
			}
		}
	}
	for _, host := range []string{"localhost:8877", "127.0.0.1:8877", "[::1]:8877", "localhost"} {
		rec := do(t, local, http.MethodPost, "/sign", goodIntent, func(r *http.Request) { r.Host = host })
		if rec.Code != http.StatusOK {
			t.Fatalf("Host %q: status %d, want 200", host, rec.Code)
		}
	}

	// A sidecar that listens beyond loopback is reached by name, and relies
	// on the token instead.
	shared := newHandler(s, serverConfig{did: testDID, token: "t0ken"})
	rec := do(t, shared, http.MethodPost, "/sign", goodIntent, func(r *http.Request) {
		r.Host = "vouch-sidecar:8877"
		r.Header.Set("Authorization", "Bearer t0ken")
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("named host with a token: status %d", rec.Code)
	}
}

func TestReadOnlyEndpoints(t *testing.T) {
	s := newTestSigner(t)
	h := localHandler(t, s, serverConfig{keySource: keyEphemeral})

	health := decode(t, do(t, h, http.MethodGet, "/health", ""))
	if health["status"] != "operational" || health["did"] != testDID || health["key"] != keyEphemeral {
		t.Fatalf("health = %v", health)
	}

	did := decode(t, do(t, h, http.MethodGet, "/did", ""))
	if did["did"] != testDID || did["verificationMethod"] != testDID+"#key-1" {
		t.Fatalf("did = %v", did)
	}

	pub := decode(t, do(t, h, http.MethodGet, "/pubkey", ""))
	multikey, _ := pub["publicKeyMultibase"].(string)
	algorithm, raw, err := signer.MultikeyDecode(multikey)
	if err != nil {
		t.Fatalf("pubkey %q does not decode: %v", multikey, err)
	}
	if !bytes.Equal(raw, s.PublicKeyEd25519()) {
		t.Fatalf("pubkey (%s) is not the signer's key", algorithm)
	}

	// The DID document names the same key, as a Multikey.
	doc := decode(t, do(t, h, http.MethodGet, "/.well-known/did.json", ""))
	methods, _ := doc["verificationMethod"].([]any)
	if doc["id"] != testDID || len(methods) != 1 {
		t.Fatalf("did document = %v", doc)
	}
	method := methods[0].(map[string]any)
	if method["id"] != testDID+"#key-1" || method["type"] != "Multikey" ||
		method["controller"] != testDID || method["publicKeyMultibase"] != multikey {
		t.Fatalf("verification method = %v", method)
	}
	if assertion, _ := doc["assertionMethod"].([]any); len(assertion) != 1 || assertion[0] != testDID+"#key-1" {
		t.Fatalf("assertionMethod = %v", doc["assertionMethod"])
	}

	// Nothing the server returns may carry private key material.
	for _, path := range []string{"/health", "/did", "/pubkey", "/.well-known/did.json"} {
		body := do(t, h, http.MethodGet, path, "").Body.String()
		if strings.Contains(body, `"d"`) || strings.Contains(strings.ToLower(body), "seed") {
			t.Fatalf("%s leaks key material: %s", path, body)
		}
	}
}
