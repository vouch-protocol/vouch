package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// identityFile is what `vouch init` writes for an unencrypted identity.
func identityFile(t *testing.T, did string, seed []byte) []byte {
	t.Helper()
	jwk := privateJWK(t, seed)
	return mustJSON(t, map[string]any{
		"v": 1, "id": did, "algo": "Ed25519", "encrypted": false,
		"public_key":  string(mustJSON(t, map[string]string{"kty": "OKP", "crv": "Ed25519", "x": jwk["x"]})),
		"private_key": string(mustJSON(t, jwk)),
	})
}

// saveIdentity writes an identity into a keystore folder under the file name
// `vouch init` would use.
func saveIdentity(t *testing.T, dir, did string, seed []byte) {
	t.Helper()
	path, err := keystorePath(dir, did)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, identityFile(t, did, seed), 0o600); err != nil {
		t.Fatal(err)
	}
}

func seedOf(b byte) []byte { return bytes.Repeat([]byte{b}, ed25519.SeedSize) }

// ---------------------------------------------------------------------------
// Keystore: the default, with nothing to pass
// ---------------------------------------------------------------------------

func TestKeystoreIdentityIsFoundByDID(t *testing.T) {
	dir := t.TempDir()
	saveIdentity(t, dir, testDID, seedOf(1))
	saveIdentity(t, dir, "did:web:other.example.com", seedOf(2))

	id, err := resolveIdentity(keyOptions{did: testDID, keystoreDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if id.did != testDID || id.source != keyFromKeystore || !bytes.Equal(id.seed, seedOf(1)) {
		t.Fatalf("got %s from %q", id.did, id.source)
	}
}

func TestKeystoreWithOneIdentityNeedsNoFlags(t *testing.T) {
	dir := t.TempDir()
	saveIdentity(t, dir, testDID, seedOf(7))

	id, err := resolveIdentity(keyOptions{keystoreDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if id.did != testDID || !bytes.Equal(id.seed, seedOf(7)) {
		t.Fatalf("got %s", id.did)
	}
}

func TestKeystoreWithSeveralIdentitiesAsksWhichOne(t *testing.T) {
	dir := t.TempDir()
	saveIdentity(t, dir, "did:web:b.example.com", seedOf(1))
	saveIdentity(t, dir, "did:web:a.example.com", seedOf(2))

	_, err := resolveIdentity(keyOptions{keystoreDir: dir})
	if err == nil {
		t.Fatal("two identities and no --did must not pick one silently")
	}
	for _, want := range []string{"did:web:a.example.com", "did:web:b.example.com", "--did"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error should mention %q: %v", want, err)
		}
	}
}

func TestNoKeyAnywhereFails(t *testing.T) {
	cases := map[string]keyOptions{
		"empty keystore":           {keystoreDir: t.TempDir()},
		"empty keystore, with did": {did: testDID, keystoreDir: t.TempDir()},
		"missing keystore folder":  {did: testDID, keystoreDir: filepath.Join(t.TempDir(), "absent")},
		"no home folder":           {did: testDID},
	}
	for name, opts := range cases {
		id, err := resolveIdentity(opts)
		if err == nil || id.seed != nil {
			t.Fatalf("%s: a signing key appeared from nowhere", name)
		}
		if !strings.Contains(err.Error(), "no signing key") || !strings.Contains(err.Error(), "--dev") {
			t.Fatalf("%s: error should say how to get a key: %v", name, err)
		}
	}
}

func TestKeystoreFileMustNameTheRequestedDID(t *testing.T) {
	dir := t.TempDir()
	// These DIDs map to the same file name as testDID.
	lookalikes := []string{"did-web-agent.example.com", "did/web/agent.example.com", "did:web:agent.example.com/"}
	saveIdentity(t, dir, testDID, seedOf(3))
	for _, did := range lookalikes {
		if _, err := resolveIdentity(keyOptions{did: did, keystoreDir: dir}); err == nil {
			t.Fatalf("%q was served the key that belongs to %s", did, testDID)
		}
	}
}

func TestKeystorePathCannotLeaveTheFolder(t *testing.T) {
	dir := t.TempDir()
	for _, did := range []string{"../../etc/passwd", `..\..\secret`, "a/../../b", "/abs/path", "did:web:x/../../y"} {
		path, err := keystorePath(dir, did)
		if err != nil {
			continue
		}
		if filepath.Dir(path) != filepath.Clean(dir) {
			t.Fatalf("%q resolves outside the keystore: %s", did, path)
		}
	}
	for _, did := range []string{"", "..", "...", "."} {
		if _, err := keystorePath(dir, did); err == nil {
			t.Fatalf("%q should not yield a file name", did)
		}
	}
}

func TestKeystorePathMatchesVouchInit(t *testing.T) {
	// `vouch init` turns every character outside [A-Za-z0-9._-] into a hyphen.
	cases := map[string]string{
		"did:web:agent.example.com":     "did-web-agent.example.com.json",
		"did:web:localhost%3A8080":      "did-web-localhost-3A8080.json",
		"did:key:z6MkhaXgBZDvotDkL5257": "did-key-z6MkhaXgBZDvotDkL5257.json",
		"did:web:münchen.example":       "did-web-m-nchen.example.json",
	}
	for did, want := range cases {
		path, err := keystorePath("keys", did)
		if err != nil || filepath.Base(path) != want {
			t.Fatalf("%s -> %s (%v), want %s", did, filepath.Base(path), err, want)
		}
	}
}

func TestLockedIdentityIsRefusedWithAWayForward(t *testing.T) {
	dir := t.TempDir()
	path, _ := keystorePath(dir, testDID)
	locked := mustJSON(t, map[string]any{
		"v": 1, "id": testDID, "encrypted": true,
		"cipher": map[string]string{"algo": "chacha20-poly1305", "ciphertext": "AAAA"},
	})
	if err := os.WriteFile(path, locked, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := resolveIdentity(keyOptions{did: testDID, keystoreDir: dir})
	if err == nil || !strings.Contains(err.Error(), "passphrase") || !strings.Contains(err.Error(), "vouch sidecar") {
		t.Fatalf("a locked identity should explain what to do: %v", err)
	}
}

func TestUnreadableKeystoreEntriesAreSkipped(t *testing.T) {
	dir := t.TempDir()
	saveIdentity(t, dir, testDID, seedOf(4))
	for name, content := range map[string]string{"broken.json": "{not json", "list.json": "[]", "noid.json": "{}", "notes.txt": "hello"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got := listKeystore(dir); len(got) != 1 || got[0] != testDID {
		t.Fatalf("listKeystore = %v", got)
	}
}

// ---------------------------------------------------------------------------
// Explicit key sources
// ---------------------------------------------------------------------------

func TestKeyFileNamesItsOwnDID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(path, identityFile(t, testDID, seedOf(5)), 0o600); err != nil {
		t.Fatal(err)
	}

	id, err := resolveIdentity(keyOptions{keyPath: path})
	if err != nil || id.did != testDID || id.source != keyFromFile || !bytes.Equal(id.seed, seedOf(5)) {
		t.Fatalf("got %+v, err %v", id.did, err)
	}
	if _, err := resolveIdentity(keyOptions{keyPath: path, did: "did:web:someone-else.example"}); err == nil {
		t.Fatal("a key file for one DID must not be used to sign as another")
	}
}

func TestBareJWKNeedsADID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.jwk")
	if err := os.WriteFile(path, mustJSON(t, privateJWK(t, seedOf(6))), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveIdentity(keyOptions{keyPath: path}); err == nil {
		t.Fatal("a bare JWK does not say who it is; --did is needed")
	}
	id, err := resolveIdentity(keyOptions{keyPath: path, did: testDID})
	if err != nil || id.did != testDID || !bytes.Equal(id.seed, seedOf(6)) {
		t.Fatalf("got %s, err %v", id.did, err)
	}
	if _, err := resolveIdentity(keyOptions{keyPath: filepath.Join(t.TempDir(), "missing.jwk"), did: testDID}); err == nil {
		t.Fatal("a missing key file must be an error, not a fallback key")
	}
}

func TestExplicitKeyFileWinsOverTheKeystore(t *testing.T) {
	dir := t.TempDir()
	saveIdentity(t, dir, testDID, seedOf(1))
	path := filepath.Join(t.TempDir(), "agent.jwk")
	if err := os.WriteFile(path, mustJSON(t, privateJWK(t, seedOf(9))), 0o600); err != nil {
		t.Fatal(err)
	}
	id, err := resolveIdentity(keyOptions{keyPath: path, did: testDID, keystoreDir: dir})
	if err != nil || id.source != keyFromFile || !bytes.Equal(id.seed, seedOf(9)) {
		t.Fatalf("source %q, err %v", id.source, err)
	}
}

func TestSeedFromEnvironment(t *testing.T) {
	want := seedOf(0xAB)
	id, err := resolveIdentity(keyOptions{did: testDID, seedHex: "  " + strings.ToUpper(hex.EncodeToString(want)) + "\n"})
	if err != nil || id.source != keyFromEnv || !bytes.Equal(id.seed, want) {
		t.Fatalf("got %x from %q, err %v", id.seed, id.source, err)
	}
	if _, err := resolveIdentity(keyOptions{seedHex: hex.EncodeToString(want)}); err == nil {
		t.Fatal("a raw seed does not say who it is; --did is needed")
	}
}

func TestBadEnvironmentSeedsAreRefusedWithoutEchoingThem(t *testing.T) {
	secret := strings.Repeat("zz", ed25519.SeedSize)
	cases := map[string]string{
		"not hex":   secret,
		"too short": "abcd",
		"too long":  strings.Repeat("ab", ed25519.SeedSize+1),
		"odd":       strings.Repeat("a", 63),
	}
	for name, value := range cases {
		_, err := resolveIdentity(keyOptions{did: testDID, seedHex: value, dev: true, random: rand.Reader, keystoreDir: t.TempDir()})
		if err == nil {
			t.Fatalf("%s: accepted", name)
		}
		if strings.Contains(err.Error(), value) || strings.Contains(err.Error(), "'z'") {
			t.Fatalf("%s: error echoes the secret: %v", name, err)
		}
	}
}

func TestTwoExplicitKeySourcesAreRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.jwk")
	if err := os.WriteFile(path, mustJSON(t, privateJWK(t, seedOf(1))), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveIdentity(keyOptions{did: testDID, keyPath: path, seedHex: hex.EncodeToString(seedOf(1))}); err == nil {
		t.Fatal("a key file and an environment seed together must be refused")
	}
}

// ---------------------------------------------------------------------------
// --dev
// ---------------------------------------------------------------------------

func TestDevModeUsesAFreshRandomKey(t *testing.T) {
	dir := t.TempDir()
	saveIdentity(t, dir, testDID, seedOf(1))

	first, err := resolveIdentity(keyOptions{did: testDID, dev: true, random: rand.Reader, keystoreDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	second, err := resolveIdentity(keyOptions{did: testDID, dev: true, random: rand.Reader, keystoreDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if first.source != keyEphemeral || bytes.Equal(first.seed, second.seed) {
		t.Fatal("--dev should give a different key on every run")
	}

	counting := make([]byte, ed25519.SeedSize)
	for i := range counting {
		counting[i] = byte(i)
	}
	for _, seed := range [][]byte{first.seed, second.seed} {
		if len(seed) != ed25519.SeedSize || bytes.Equal(seed, counting) ||
			bytes.Equal(seed, make([]byte, ed25519.SeedSize)) || bytes.Equal(seed, seedOf(1)) {
			t.Fatal("--dev key is fixed, guessable, or the saved identity's key")
		}
	}
}

func TestDevModeNeedsADIDAndRealRandomness(t *testing.T) {
	if _, err := resolveIdentity(keyOptions{dev: true, random: rand.Reader}); err == nil {
		t.Fatal("--dev without --did should be refused")
	}
	if _, err := resolveIdentity(keyOptions{did: testDID, dev: true, random: strings.NewReader("too short")}); err == nil {
		t.Fatal("a short random source must not yield a key")
	}
}

func TestAConfiguredKeyWinsOverDevMode(t *testing.T) {
	want := seedOf(0x5A)
	id, err := resolveIdentity(keyOptions{did: testDID, seedHex: hex.EncodeToString(want), dev: true, random: rand.Reader})
	if err != nil || id.source != keyFromEnv || !bytes.Equal(id.seed, want) {
		t.Fatalf("got %x from %q, err %v", id.seed, id.source, err)
	}
}

// ---------------------------------------------------------------------------
// Key file parsing
// ---------------------------------------------------------------------------

func TestIdentityFileLayouts(t *testing.T) {
	seed := seedOf(9)
	jwk := privateJWK(t, seed)
	asObject := mustJSON(t, map[string]any{"id": testDID, "encrypted": false, "private_key": jwk})

	for name, raw := range map[string][]byte{"string": identityFile(t, testDID, seed), "object": asObject} {
		got, did, _, err := identityFromKeyFile(raw)
		if err != nil || did != testDID || !bytes.Equal(got, seed) {
			t.Fatalf("%s: did %q, err %v", name, did, err)
		}
	}
	got, did, _, err := identityFromKeyFile(mustJSON(t, jwk))
	if err != nil || did != "" || !bytes.Equal(got, seed) {
		t.Fatalf("bare JWK: did %q, err %v", did, err)
	}
}

func TestBadKeyFilesAreRefused(t *testing.T) {
	seed, other := seedOf(3), seedOf(4)

	wrongCurve := privateJWK(t, seed)
	wrongCurve["crv"] = "X25519"
	wrongType := privateJWK(t, seed)
	wrongType["kty"] = "EC"
	publicOnly := privateJWK(t, seed)
	delete(publicOnly, "d")
	shortKey := privateJWK(t, seed)
	shortKey["d"] = base64.RawURLEncoding.EncodeToString(seed[:16])
	mismatched := privateJWK(t, seed)
	mismatched["x"] = privateJWK(t, other)["x"]

	cases := map[string][]byte{
		"not json":          []byte("not json"),
		"wrong curve":       mustJSON(t, wrongCurve),
		"wrong key type":    mustJSON(t, wrongType),
		"public key only":   mustJSON(t, publicOnly),
		"short private key": mustJSON(t, shortKey),
		"mismatched public": mustJSON(t, mismatched),
		"locked":            mustJSON(t, map[string]any{"encrypted": true, "cipher": map[string]string{"ciphertext": "AAAA"}}),
		"empty object":      []byte("{}"),
	}
	for name, raw := range cases {
		if _, _, _, err := identityFromKeyFile(raw); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// ---------------------------------------------------------------------------
// The real binary
// ---------------------------------------------------------------------------

// runMain runs the real main() in a child process with a private home folder
// and stdin closed, the way a container starts it.
func runMain(t *testing.T, home string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMainProcess$")
	// Start from this process's environment, so the child finds the same
	// libraries, and take out every setting the sidecar itself reads.
	own := []string{"HOME=", "USERPROFILE=", seedEnv + "=", tokenEnv + "=", hostEnv + "=",
		defaultValidityEnv + "=", maxValidityEnv + "=", otelEndpointEnv + "="}
	for _, entry := range os.Environ() {
		keep := true
		for _, prefix := range own {
			if strings.HasPrefix(entry, prefix) {
				keep = false
			}
		}
		if keep {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env,
		"VOUCH_SIDECAR_TEST_MAIN=1",
		"VOUCH_SIDECAR_TEST_ARGS="+strings.Join(args, "\x1f"),
		"HOME="+home, "USERPROFILE="+home,
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestMainProcess is the child half of runMain. It does nothing on its own.
func TestMainProcess(t *testing.T) {
	if os.Getenv("VOUCH_SIDECAR_TEST_MAIN") != "1" {
		t.Skip("helper process for the startup tests")
	}
	os.Args = []string{"vouch-sidecar"}
	if raw := os.Getenv("VOUCH_SIDECAR_TEST_ARGS"); raw != "" {
		os.Args = append(os.Args, strings.Split(raw, "\x1f")...)
	}
	main()
}

func TestStartupWithoutAKeyExitsNonZero(t *testing.T) {
	out, err := runMain(t, t.TempDir(), "--did", testDID, "--port", "0")

	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() <= 0 {
		t.Fatalf("startup without a key should exit non-zero; err=%v output=%s", err, out)
	}
	if strings.Contains(out, "listening") {
		t.Fatalf("the sidecar started serving without a key: %s", out)
	}
	if !strings.Contains(out, "no signing key") {
		t.Fatalf("output should explain the missing key: %s", out)
	}
}

func TestStartupRefusesBadSettings(t *testing.T) {
	home := t.TempDir()
	cases := map[string][]string{
		"exposed without a token":   {"--did", testDID, "--dev", "--host", "0.0.0.0", "--port", "0"},
		"default longer than max":   {"--did", testDID, "--dev", "--default-validity", "2h", "--max-validity", "1h", "--port", "0"},
		"zero default validity":     {"--did", testDID, "--dev", "--default-validity", "0s", "--port", "0"},
		"bad tracing address":       {"--did", testDID, "--dev", "--otel-endpoint", "collector:4318", "--port", "0"},
		"allow-list does not exist": {"--did", testDID, "--dev", "--allowlist", filepath.Join(home, "missing.json"), "--port", "0"},
	}
	for name, args := range cases {
		out, err := runMain(t, home, args...)
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() <= 0 {
			t.Fatalf("%s: should exit non-zero; err=%v output=%s", name, err, out)
		}
		if strings.Contains(out, "listening") {
			t.Fatalf("%s: the sidecar started anyway: %s", name, out)
		}
	}
}
