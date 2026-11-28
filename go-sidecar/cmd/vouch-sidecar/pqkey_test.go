package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// pqRow is the "#key-2" row `vouch init` saves for an ML-DSA-44 key.
func pqRow(t *testing.T) (map[string]any, *mldsa44.PrivateKey) {
	t.Helper()
	public, private, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rawPublic, _ := public.MarshalBinary()
	rawPrivate, _ := private.MarshalBinary()
	multikey, err := signer.EncodeMLDSA44Public(rawPublic)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(rawPrivate)
	return map[string]any{
		"id": "#key-2", "alg": "ML-DSA-44", "public_key": multikey,
		"private_key":        base64.StdEncoding.EncodeToString(rawPrivate),
		"private_key_sha256": hex.EncodeToString(sum[:]),
	}, private
}

// identityFileWith is an unlocked identity file carrying the given key rows.
func identityFileWith(t *testing.T, did string, seed []byte, rows ...map[string]any) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(identityFile(t, did, seed), &doc); err != nil {
		t.Fatal(err)
	}
	doc["v"] = 2
	if rows == nil {
		rows = []map[string]any{}
	}
	doc["keys"] = rows
	return mustJSON(t, doc)
}

func privateBytes(t *testing.T, key *mldsa44.PrivateKey) []byte {
	t.Helper()
	raw, err := key.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// ---------------------------------------------------------------------------
// Reading the saved key
// ---------------------------------------------------------------------------

func TestSavedPostQuantumKeyIsReadAndStable(t *testing.T) {
	dir := t.TempDir()
	row, private := pqRow(t)
	path, _ := keystorePath(dir, testDID)
	if err := os.WriteFile(path, identityFileWith(t, testDID, seedOf(1), row), 0o600); err != nil {
		t.Fatal(err)
	}

	first, err := resolveIdentity(keyOptions{keystoreDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	second, err := resolveIdentity(keyOptions{did: testDID, keystoreDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if first.mldsa44 == nil || second.mldsa44 == nil {
		t.Fatal("the saved post-quantum key was not read")
	}
	want := privateBytes(t, private)
	if !bytes.Equal(privateBytes(t, first.mldsa44), want) || !bytes.Equal(privateBytes(t, second.mldsa44), want) {
		t.Fatal("two starts did not load the same post-quantum key")
	}
	if !bytes.Equal(first.seed, seedOf(1)) {
		t.Fatal("the Ed25519 key was not read alongside it")
	}

	// The same file passed with --key carries both keys too.
	fromFile, err := resolveIdentity(keyOptions{keyPath: path})
	if err != nil || fromFile.mldsa44 == nil || fromFile.did != testDID {
		t.Fatalf("--key identity file: %v", err)
	}
}

func TestIdentityWithoutASavedPostQuantumKey(t *testing.T) {
	for name, raw := range map[string][]byte{
		"one-key file":          identityFile(t, testDID, seedOf(2)),
		"empty key list":        identityFileWith(t, testDID, seedOf(2)),
		"bare jwk":              mustJSON(t, privateJWK(t, seedOf(2))),
		"only a later key type": identityFileWith(t, testDID, seedOf(2), map[string]any{"id": "#key-3", "alg": "SLH-DSA-128s", "public_key": "z", "private_key": "AA=="}),
	} {
		seed, _, pq, err := identityFromKeyFile(raw)
		if err != nil || pq != nil || !bytes.Equal(seed, seedOf(2)) {
			t.Fatalf("%s: pq=%v err=%v", name, pq != nil, err)
		}
	}
}

func TestDamagedPostQuantumRowsAreErrorsNotNewKeys(t *testing.T) {
	good, _ := pqRow(t)
	other, _ := pqRow(t)
	with := func(change func(map[string]any)) map[string]any {
		row := map[string]any{}
		for k, v := range good {
			row[k] = v
		}
		change(row)
		return row
	}

	cases := map[string][]map[string]any{
		"public key of another pair":  {with(func(r map[string]any) { r["public_key"] = other["public_key"] })},
		"private key of another pair": {with(func(r map[string]any) { r["private_key"] = other["private_key"] })},
		"truncated private key":       {with(func(r map[string]any) { r["private_key"] = r["private_key"].(string)[:100] })},
		"private key not base64":      {with(func(r map[string]any) { r["private_key"] = "!!!" })},
		"no private key":              {with(func(r map[string]any) { delete(r, "private_key") })},
		"wrong slot":                  {with(func(r map[string]any) { r["id"] = "#key-9" })},
		"public key not a multikey":   {with(func(r map[string]any) { r["public_key"] = "not-a-key" })},
		"locked row in an open file": {with(func(r map[string]any) {
			delete(r, "private_key")
			r["cipher"] = map[string]string{"ciphertext": "AAAA"}
		})},
		"two post-quantum rows": {good, other},
	}
	for name, rows := range cases {
		if _, _, pq, err := identityFromKeyFile(identityFileWith(t, testDID, seedOf(3), rows...)); err == nil {
			t.Fatalf("%s: accepted (pq=%v)", name, pq != nil)
		}
	}

	// An Ed25519 public key in the post-quantum slot is refused.
	edAsPQ, _ := signer.EncodeEd25519Public(bytes.Repeat([]byte{7}, 32))
	if _, _, _, err := identityFromKeyFile(identityFileWith(t, testDID, seedOf(3), with(func(r map[string]any) { r["public_key"] = edAsPQ }))); err == nil {
		t.Fatal("an Ed25519 key was accepted as the ML-DSA-44 key")
	}
}

// ---------------------------------------------------------------------------
// Serving with and without a saved key
// ---------------------------------------------------------------------------

func TestPostQuantumSigningNeedsASavedKey(t *testing.T) {
	s := newTestSigner(t)
	without := localHandler(t, s, serverConfig{postQuantum: pqNone})

	rec := do(t, without, http.MethodPost, "/sign/hybrid", goodIntent)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "post-quantum key") {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if rec := do(t, without, http.MethodPost, "/sign", goodIntent); rec.Code != http.StatusOK {
		t.Fatalf("ordinary signing should still work: %d", rec.Code)
	}
	if _, has := decode(t, do(t, without, http.MethodGet, "/pubkey", ""))["mldsa44"]; has {
		t.Fatal("/pubkey advertises a post-quantum key the sidecar will not sign with")
	}
	if got := decode(t, do(t, without, http.MethodGet, "/health", ""))["postQuantumKey"]; got != pqNone {
		t.Fatalf("health postQuantumKey = %v", got)
	}

	saved := localHandler(t, s, serverConfig{postQuantum: pqSaved})
	if rec := do(t, saved, http.MethodPost, "/sign/hybrid", goodIntent); rec.Code != http.StatusOK {
		t.Fatalf("with a saved key: status %d", rec.Code)
	}
}

func TestTwoStartsSignWithTheSamePostQuantumKey(t *testing.T) {
	row, _ := pqRow(t)
	raw := identityFileWith(t, testDID, seedOf(5), row)

	start := func() (*signer.Signer, http.Handler) {
		seed, did, pq, err := identityFromKeyFile(raw)
		if err != nil {
			t.Fatal(err)
		}
		s, err := signer.New(signer.Config{DID: did, Ed25519Seed: seed, MLDSA44PrivateKey: pq})
		if err != nil {
			t.Fatal(err)
		}
		return s, localHandler(t, s, serverConfig{hybrid: true, postQuantum: pqSaved})
	}
	_, runOne := start()
	later, runTwo := start()

	cred := decode(t, do(t, runOne, http.MethodPost, "/sign", goodIntent))
	published := decode(t, do(t, runTwo, http.MethodGet, "/pubkey", ""))["mldsa44"].(map[string]any)["publicKeyMultibase"]
	if published != row["public_key"] {
		t.Fatal("the published key is not the saved one")
	}
	if ok, _, err := signer.Verify(cred, later.PublicKeyEd25519(), 30, later.PublicKeyMLDSA44()); err != nil || !ok {
		t.Fatalf("a credential from the first start does not verify under the second start's keys: %v", err)
	}
	docOne := do(t, runOne, http.MethodGet, "/.well-known/did.json", "").Body.String()
	docTwo := do(t, runTwo, http.MethodGet, "/.well-known/did.json", "").Body.String()
	if docOne != docTwo {
		t.Fatal("the DID document changed between starts")
	}
}

func TestHybridStartupNeedsASavedKeyUnlessDev(t *testing.T) {
	home := t.TempDir()
	keys := filepath.Join(home, ".vouch", "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	saveIdentity(t, keys, testDID, seedOf(6)) // an identity with one key

	out, err := runMain(t, home, "--hybrid", "--port", "0")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() <= 0 {
		t.Fatalf("--hybrid without a saved key should exit non-zero; err=%v output=%s", err, out)
	}
	if strings.Contains(out, "listening") || !strings.Contains(out, "vouch init") {
		t.Fatalf("output should say how to add the key: %s", out)
	}
}

// ---------------------------------------------------------------------------
// Second review round
// ---------------------------------------------------------------------------

func withRow(row map[string]any, change func(map[string]any)) map[string]any {
	copied := map[string]any{}
	for k, v := range row {
		copied[k] = v
	}
	change(copied)
	return copied
}

func TestTamperedPostQuantumRowsAreRefused(t *testing.T) {
	good, _ := pqRow(t)
	cases := map[string]func(map[string]any){
		"alg ML-DSA-65":    func(r map[string]any) { r["alg"] = "ML-DSA-65" },
		"alg lower case":   func(r map[string]any) { r["alg"] = "ml-dsa-44" },
		"alg removed":      func(r map[string]any) { delete(r, "alg") },
		"alg a number":     func(r map[string]any) { r["alg"] = 44 },
		"alg one byte off": func(r map[string]any) { r["alg"] = "ML-DSA-44x" },
		"no check value":   func(r map[string]any) { delete(r, "private_key_sha256") },
		"cipher and key":   func(r map[string]any) { r["cipher"] = map[string]string{"nonce": "AA"} },
		"line breaks":      func(r map[string]any) { k := r["private_key"].(string); r["private_key"] = k[:64] + "\n" + k[64:] },
	}
	for name, change := range cases {
		raw := identityFileWith(t, testDID, seedOf(3), withRow(good, change))
		if _, _, pq, err := identityFromKeyFile(raw); err == nil {
			t.Fatalf("%s: accepted (pq=%v)", name, pq != nil)
		}
	}
}

func TestDamageAnywhereInThePrivateKeyIsNoticed(t *testing.T) {
	good, _ := pqRow(t)
	for _, position := range []int{0, 1000, 1664, 2550, 2559} {
		raw, _ := base64.StdEncoding.DecodeString(good["private_key"].(string))
		raw[position] ^= 0x01
		bad := withRow(good, func(r map[string]any) { r["private_key"] = base64.StdEncoding.EncodeToString(raw) })
		if _, _, _, err := identityFromKeyFile(identityFileWith(t, testDID, seedOf(3), bad)); err == nil {
			t.Fatalf("byte %d flipped: accepted", position)
		}
	}
}

func TestKeyListShapes(t *testing.T) {
	good, _ := pqRow(t)
	base := func() map[string]any {
		var doc map[string]any
		if err := json.Unmarshal(identityFileWith(t, testDID, seedOf(4), good), &doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}

	refused := map[string]func(map[string]any){
		"keys null":         func(d map[string]any) { d["keys"] = nil },
		"keys removed, v 2": func(d map[string]any) { delete(d, "keys") },
		"keys not a list":   func(d map[string]any) { d["keys"] = "rows" },
		"null row":          func(d map[string]any) { d["keys"] = []any{nil, good} },
	}
	for name, change := range refused {
		doc := base()
		change(doc)
		if _, _, _, err := identityFromKeyFile(mustJSON(t, doc)); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}

	// Rows of a key type this release does not know are left alone, whatever
	// their shape.
	doc := base()
	doc["keys"] = []any{
		map[string]any{"id": 9, "alg": "SLH-DSA-128s", "private_key": map[string]any{"x": 1}},
		good,
	}
	if _, _, pq, err := identityFromKeyFile(mustJSON(t, doc)); err != nil || pq == nil {
		t.Fatalf("an unknown row stopped the file from loading: %v", err)
	}

	// Member names match exactly: a "Keys" member is not the key list.
	other, otherKey := pqRow(t)
	doc = base()
	doc["Keys"] = []any{other}
	_, _, pq, err := identityFromKeyFile(mustJSON(t, doc))
	if err != nil || pq == nil || bytes.Equal(privateBytes(t, pq), privateBytes(t, otherKey)) {
		t.Fatalf("the wrong member was read as the key list: %v", err)
	}
}

func TestStartupUsesTheSavedPostQuantumKey(t *testing.T) {
	row, private := pqRow(t)
	seed, did, pq, err := identityFromKeyFile(identityFileWith(t, testDID, seedOf(5), row))
	if err != nil {
		t.Fatal(err)
	}
	s, postQuantum, err := newSigner(identity{did: did, seed: seed, source: keyFromKeystore, mldsa44: pq}, 300, true)
	if err != nil || postQuantum != pqSaved {
		t.Fatalf("postQuantum=%q err=%v", postQuantum, err)
	}
	got, _ := s.PublicKeyMLDSA44().MarshalBinary()
	want, _ := private.Public().(*mldsa44.PublicKey).MarshalBinary()
	if !bytes.Equal(got, want) {
		t.Fatal("the signer does not use the saved post-quantum key")
	}
}

func TestStartupMessagesNameTheKeySource(t *testing.T) {
	cases := map[string]string{keyFromEnv: seedEnv, keyFromFile: "--did " + testDID, keyFromKeystore: "--did " + testDID + " --add-post-quantum-key"}
	for source, want := range cases {
		_, _, err := newSigner(identity{did: testDID, seed: seedOf(6), source: source}, 300, true)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: %v", source, err)
		}
	}
	if _, postQuantum, err := newSigner(identity{did: testDID, seed: seedOf(6), source: keyEphemeral}, 300, true); err != nil || postQuantum != pqPerRun {
		t.Fatalf("--dev: %q %v", postQuantum, err)
	}
	if _, postQuantum, err := newSigner(identity{did: testDID, seed: seedOf(6), source: keyFromKeystore}, 300, false); err != nil || postQuantum != pqNone {
		t.Fatalf("no --hybrid: %q %v", postQuantum, err)
	}
}

func TestVersionMustBeExactlyOne(t *testing.T) {
	for _, version := range []string{"2", "1.0", "true", `"1"`, "null"} {
		raw := []byte(`{"v": ` + version + `, "id": "` + testDID + `", "private_key": ` + string(mustJSON(t, string(mustJSON(t, privateJWK(t, seedOf(8)))))) + `}`)
		if _, _, _, err := identityFromKeyFile(raw); err == nil {
			t.Fatalf("v=%s with no key list: accepted", version)
		}
	}
	raw := []byte(`{"v": 1, "id": "` + testDID + `", "private_key": ` + string(mustJSON(t, string(mustJSON(t, privateJWK(t, seedOf(8)))))) + `}`)
	if _, _, pq, err := identityFromKeyFile(raw); err != nil || pq != nil {
		t.Fatalf("v=1 one-key file: %v", err)
	}
}
