package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// Where the signing key came from. Reported on /health and in the startup log.
const (
	keyFromFile     = "key file"
	keyFromEnv      = "environment"
	keyFromKeystore = "keystore"
	keyEphemeral    = "ephemeral"
)

// identity is the agent this sidecar signs as, and the key it signs with.
type identity struct {
	did    string
	seed   []byte
	source string

	// mldsa44 is the identity's saved post-quantum key, from the "#key-2" row
	// of its identity file. nil when the key source carries none.
	mldsa44 *mldsa44.PrivateKey

	// fileNamesIdentity is true when a --key file names its own DID (an
	// identity file from the keystore), false for a bare JWK.
	fileNamesIdentity bool
}

// keyOptions is everything that can say which identity to use.
type keyOptions struct {
	did         string    // --did; may be empty when the key source names the DID
	keyPath     string    // --key
	seedHex     string    // VOUCH_ED25519_SEED
	dev         bool      // --dev
	keystoreDir string    // where `vouch init` saves identities; "" when unknown
	random      io.Reader // source of the --dev key
}

// resolveIdentity works out which agent to sign as and loads its key.
//
// With nothing configured it looks in the keystore, the folder where
// `vouch init` saves identities: the identity for --did, or the only identity
// there when --did is not given. An explicit --key file or VOUCH_ED25519_SEED
// takes its place, and --dev swaps in a random key for one run. When none of
// these yields a key, startup fails: the sidecar never invents a lasting key.
func resolveIdentity(o keyOptions) (identity, error) {
	switch {
	case o.keyPath != "" && o.seedHex != "":
		return identity{}, fmt.Errorf("set only one of --key and %s", seedEnv)

	case o.keyPath != "":
		raw, err := os.ReadFile(o.keyPath)
		if err != nil {
			return identity{}, fmt.Errorf("read key file: %w", err)
		}
		seed, fileDID, pq, err := identityFromKeyFile(raw)
		if err != nil {
			return identity{}, err
		}
		did, err := reconcileDID(o.did, fileDID)
		if err != nil {
			return identity{}, err
		}
		return identity{did: did, seed: seed, source: keyFromFile, mldsa44: pq, fileNamesIdentity: fileDID != ""}, nil

	case o.seedHex != "":
		if o.did == "" {
			return identity{}, fmt.Errorf("--did is required with %s", seedEnv)
		}
		// The decode error is not wrapped: it would echo part of the secret.
		seed, err := hex.DecodeString(strings.TrimSpace(o.seedHex))
		if err != nil || len(seed) != ed25519.SeedSize {
			return identity{}, fmt.Errorf("%s must be %d hex characters", seedEnv, ed25519.SeedSize*2)
		}
		return identity{did: o.did, seed: seed, source: keyFromEnv}, nil

	case o.dev:
		if o.did == "" {
			return identity{}, errors.New("--did is required with --dev, for example --did did:web:localhost")
		}
		seed := make([]byte, ed25519.SeedSize)
		if _, err := io.ReadFull(o.random, seed); err != nil {
			return identity{}, fmt.Errorf("generate a random key: %w", err)
		}
		return identity{did: o.did, seed: seed, source: keyEphemeral}, nil

	default:
		return identityFromKeystore(o.keystoreDir, o.did)
	}
}

// reconcileDID settles the DID when both the command line and the key file may
// name one. They have to agree.
func reconcileDID(flagDID, fileDID string) (string, error) {
	switch {
	case flagDID == "" && fileDID == "":
		return "", errors.New("--did is required: this key file does not name an identity")
	case flagDID == "":
		return fileDID, nil
	case fileDID == "" || fileDID == flagDID:
		return flagDID, nil
	default:
		return "", fmt.Errorf("the key file is for %s, but --did is %s", fileDID, flagDID)
	}
}

// ---------------------------------------------------------------------------
// Keystore
// ---------------------------------------------------------------------------

// defaultKeystoreDir is where `vouch init` and `vouch onboard` save identities.
func defaultKeystoreDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".vouch", "keys")
}

// identityFromKeystore loads the identity for did, or the only identity in the
// keystore when did is empty.
func identityFromKeystore(dir, did string) (identity, error) {
	if dir == "" {
		return identity{}, noKeyError(did)
	}
	if did == "" {
		found := listKeystore(dir)
		switch len(found) {
		case 0:
			return identity{}, noKeyError("")
		case 1:
			did = found[0]
		default:
			return identity{}, fmt.Errorf(
				"several identities found (%s): choose one with --did", strings.Join(found, ", "),
			)
		}
	}

	path, err := keystorePath(dir, did)
	if err != nil {
		return identity{}, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return identity{}, noKeyError(did)
	}
	if err != nil {
		return identity{}, fmt.Errorf("read the identity for %s: %w", did, err)
	}
	seed, fileDID, pq, err := identityFromKeyFile(raw)
	if err != nil {
		return identity{}, fmt.Errorf("identity for %s: %w", did, err)
	}
	// Different DIDs can share a file name, so the file has to name this exact
	// DID before its key is used for it.
	if fileDID != did {
		return identity{}, fmt.Errorf("the keystore file for %s names a different identity", did)
	}
	return identity{did: did, seed: seed, source: keyFromKeystore, mldsa44: pq}, nil
}

func noKeyError(did string) error {
	if did == "" {
		return errors.New(
			"no signing key found: create an identity with `vouch init --domain <your domain>`, " +
				"or pass --key <file>. For local testing, --did did:web:localhost --dev uses a throwaway key",
		)
	}
	return fmt.Errorf(
		"no signing key for %s: create it with `vouch init`, or pass --key <file>. "+
			"For local testing, --dev uses a throwaway key", did,
	)
}

// keystorePath is the file `vouch init` uses for a DID: every character outside
// letters, digits, dot, underscore and hyphen becomes a hyphen. The name can
// therefore never contain a path separator.
func keystorePath(dir, did string) (string, error) {
	var b strings.Builder
	for _, r := range did {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	name := strings.Trim(b.String(), ".")
	if name == "" {
		return "", fmt.Errorf("%q is not a usable identity name", did)
	}
	return filepath.Join(dir, name+".json"), nil
}

// listKeystore returns the DIDs of the identities saved in dir, sorted.
func listKeystore(dir string) []string {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var dids []string
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		var entry map[string]json.RawMessage
		if json.Unmarshal(raw, &entry) != nil {
			continue
		}
		id, ok := stringField(entry, "id")
		if !ok || id == "" || seen[id] {
			continue
		}
		seen[id] = true
		dids = append(dids, id)
	}
	sort.Strings(dids)
	return dids
}

// ---------------------------------------------------------------------------
// Key files
// ---------------------------------------------------------------------------

// keyFile covers both accepted layouts: a bare private JWK, and the identity
// file `vouch init` writes, which carries the DID under "id" and the JWK under
// "private_key".
// keyRow is one further key of an identity, such as its ML-DSA-44 key, with
// every member kept as raw JSON so nothing is read under a different name.
type keyRow map[string]json.RawMessage

const (
	algMLDSA44     = "ML-DSA-44"
	mldsa44KeySlot = "#key-2"
)

// field decodes one member of a JSON object, matching its name exactly.
// ok is false when the member is absent.
func field(object map[string]json.RawMessage, name string) (value any, ok bool) {
	raw, ok := object[name]
	if !ok {
		return nil, false
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, true
	}
	return value, true
}

// stringField returns a member that must be a string, and whether it is one.
func stringField(object map[string]json.RawMessage, name string) (string, bool) {
	value, _ := field(object, name)
	text, ok := value.(string)
	return text, ok
}

// truthy follows the reference reader: false, null, zero, "" and empty
// lists or objects count as false.
func truthy(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case bool:
		return v
	case float64:
		return v != 0
	case string:
		return v != ""
	case []any:
		return len(v) > 0
	case map[string]any:
		return len(v) > 0
	}
	return true
}

// strictBase64 decodes standard base64 and refuses anything the reference
// reader refuses, such as embedded line breaks.
func strictBase64(text string) ([]byte, error) {
	if strings.ContainsAny(text, "\r\n\t ") {
		return nil, errors.New("not strict base64")
	}
	return base64.StdEncoding.Strict().DecodeString(text)
}

func damaged(what string) error {
	return errors.New("identity file is damaged: " + what)
}

// postQuantumKey reads the saved ML-DSA-44 key from an unlocked identity
// file, following the same rules as the reference reader: a row that names
// the post-quantum slot or algorithm must be exactly that key, rows of other
// key types are left alone, and a damaged key is an error. The key is never
// quietly replaced with a new one.
func postQuantumKey(top map[string]json.RawMessage) (*mldsa44.PrivateKey, error) {
	rawRows, present := top["keys"]
	if !present {
		if version, ok := top["v"]; ok && strings.TrimSpace(string(version)) != "1" {
			return nil, damaged("its key list is missing")
		}
		return nil, nil
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(rawRows, &rows); err != nil || rows == nil {
		return nil, damaged("its key list is not a list")
	}

	var found *mldsa44.PrivateKey
	for _, rawRow := range rows {
		var row keyRow
		if err := json.Unmarshal(rawRow, &row); err != nil || row == nil {
			return nil, damaged("a key entry is not an object")
		}
		alg, _ := field(row, "alg")
		id, _ := field(row, "id")
		if alg != algMLDSA44 && id != mldsa44KeySlot {
			// A key type this release does not know. Leave it alone.
			continue
		}
		public, publicOK := stringField(row, "public_key")
		if alg != algMLDSA44 || id != mldsa44KeySlot || !publicOK {
			return nil, damaged("its ML-DSA-44 entry is malformed")
		}
		if found != nil {
			return nil, damaged("it holds two ML-DSA-44 keys")
		}
		if _, locked := row["cipher"]; locked {
			return nil, damaged("its ML-DSA-44 key cannot be read")
		}
		encoded, ok := stringField(row, "private_key")
		digest, digestOK := stringField(row, "private_key_sha256")
		if !ok || !digestOK {
			return nil, damaged("its ML-DSA-44 key cannot be read")
		}
		raw, err := strictBase64(encoded)
		if err != nil {
			return nil, damaged("its ML-DSA-44 key cannot be read")
		}
		sum := sha256.Sum256(raw)
		if !strings.EqualFold(digest, hex.EncodeToString(sum[:])) {
			return nil, damaged("its ML-DSA-44 key cannot be read")
		}
		if len(raw) != mldsa44.PrivateKeySize {
			return nil, damaged("its ML-DSA-44 private key is the wrong size")
		}
		var private mldsa44.PrivateKey
		if err := private.UnmarshalBinary(raw); err != nil {
			return nil, damaged("its ML-DSA-44 private key cannot be read")
		}
		algorithm, stated, err := signer.MultikeyDecode(public)
		if err != nil || algorithm != algMLDSA44 {
			return nil, damaged("its ML-DSA-44 public key is not an ML-DSA-44 Multikey")
		}
		derived, err := private.Public().(*mldsa44.PublicKey).MarshalBinary()
		if err != nil || !bytes.Equal(stated, derived) {
			return nil, damaged("its ML-DSA-44 public key does not match its private key")
		}
		found = &private
	}
	return found, nil
}

// identityFromKeyFile extracts the Ed25519 seed from a key file, checks it
// against the public key the file states, and returns the DID the file names
// (empty for a bare JWK) and the saved post-quantum key, if the file has one.
func identityFromKeyFile(raw []byte) (seed []byte, did string, pq *mldsa44.PrivateKey, err error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil || top == nil {
		return nil, "", nil, errors.New("key file is not valid JSON")
	}
	did, _ = stringField(top, "id")
	if encrypted, _ := field(top, "encrypted"); truthy(encrypted) {
		return nil, "", nil, errors.New(
			"the identity file is locked with a passphrase, which this sidecar cannot open. " +
				"Start `vouch sidecar` instead (it asks for the passphrase), or use an identity saved without one",
		)
	}
	seed, err = ed25519FromKeyFile(top)
	if err != nil {
		return nil, "", nil, err
	}
	pq, err = postQuantumKey(top)
	if err != nil {
		return nil, "", nil, err
	}
	return seed, did, pq, nil
}

// ed25519FromKeyFile reads the Ed25519 seed from a bare private JWK, or from
// the "private_key" member of an identity file (a JWK, as a JSON string or an
// object).
func ed25519FromKeyFile(top map[string]json.RawMessage) ([]byte, error) {
	jwk := top
	if inner, ok := top["private_key"]; ok {
		var asString string
		if err := json.Unmarshal(inner, &asString); err == nil {
			inner = []byte(asString)
		}
		jwk = nil
		if err := json.Unmarshal(inner, &jwk); err != nil || jwk == nil {
			return nil, errors.New("key file holds a private key that is not a JWK")
		}
	}
	kty, _ := stringField(jwk, "kty")
	crv, _ := stringField(jwk, "crv")
	if kty != "OKP" || crv != "Ed25519" {
		return nil, errors.New("key file must hold an Ed25519 JWK (kty OKP, crv Ed25519)")
	}
	d, _ := stringField(jwk, "d")
	if d == "" {
		return nil, errors.New("key file has no private key (the JWK \"d\" member is missing)")
	}
	seed, err := decodeBase64URL(d)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("key file private key must be %d bytes, base64url-encoded", ed25519.SeedSize)
	}
	if x, _ := stringField(jwk, "x"); x != "" {
		stated, err := decodeBase64URL(x)
		derived := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		if err != nil || !bytes.Equal(stated, derived) {
			return nil, errors.New("key file public key does not match its private key")
		}
	}
	return seed, nil
}

func decodeBase64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}
