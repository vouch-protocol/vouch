package main

import (
	"bytes"
	"crypto/ed25519"
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
		return identity{did: did, seed: seed, source: keyFromFile, mldsa44: pq}, nil

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
		var entry struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(raw, &entry) != nil || entry.ID == "" || seen[entry.ID] {
			continue
		}
		seen[entry.ID] = true
		dids = append(dids, entry.ID)
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
type keyFile struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	D   string `json:"d"`
	X   string `json:"x"`

	ID         string          `json:"id"`
	Encrypted  bool            `json:"encrypted"`
	PrivateKey json.RawMessage `json:"private_key"`

	// Keys lists the identity's further keys, one row per key.
	Keys []keyRow `json:"keys"`
}

// keyRow is one further key of an identity, such as its ML-DSA-44 key.
type keyRow struct {
	ID         string          `json:"id"`
	Alg        string          `json:"alg"`
	PublicKey  string          `json:"public_key"`
	PrivateKey string          `json:"private_key"`
	Cipher     json.RawMessage `json:"cipher"`
}

const (
	algMLDSA44     = "ML-DSA-44"
	mldsa44KeySlot = "#key-2"
)

// postQuantumKey reads the saved ML-DSA-44 key from an identity file's rows.
// It returns nil when the file has none. A row that is present but damaged is
// an error: the key is never quietly replaced with a new one.
func postQuantumKey(rows []keyRow) (*mldsa44.PrivateKey, error) {
	var found *mldsa44.PrivateKey
	for _, row := range rows {
		if row.Alg != algMLDSA44 {
			// A key type this release does not know. Leave it alone.
			continue
		}
		if found != nil {
			return nil, errors.New("identity file holds two ML-DSA-44 keys")
		}
		if row.ID != mldsa44KeySlot {
			return nil, errors.New("identity file has its ML-DSA-44 key in the wrong slot")
		}
		if len(row.Cipher) > 0 || row.PrivateKey == "" {
			return nil, errors.New("identity file has a locked ML-DSA-44 key that this sidecar cannot open")
		}
		raw, err := base64.StdEncoding.DecodeString(row.PrivateKey)
		if err != nil || len(raw) != mldsa44.PrivateKeySize {
			return nil, errors.New("identity file has a damaged ML-DSA-44 private key")
		}
		var private mldsa44.PrivateKey
		if err := private.UnmarshalBinary(raw); err != nil {
			return nil, errors.New("identity file has a damaged ML-DSA-44 private key")
		}
		algorithm, stated, err := signer.MultikeyDecode(row.PublicKey)
		if err != nil || algorithm != algMLDSA44 {
			return nil, errors.New("identity file has a damaged ML-DSA-44 public key")
		}
		derived, err := private.Public().(*mldsa44.PublicKey).MarshalBinary()
		if err != nil || !bytes.Equal(stated, derived) {
			return nil, errors.New("identity file ML-DSA-44 public key does not match its private key")
		}
		found = &private
	}
	return found, nil
}

// identityFromKeyFile extracts the Ed25519 seed from a key file, checks it
// against the public key the file states, and returns the DID the file names
// (empty for a bare JWK) and the saved post-quantum key, if the file has one.
func identityFromKeyFile(raw []byte) (seed []byte, did string, pq *mldsa44.PrivateKey, err error) {
	seed, did, rows, err := ed25519FromKeyFile(raw)
	if err != nil {
		return nil, "", nil, err
	}
	pq, err = postQuantumKey(rows)
	if err != nil {
		return nil, "", nil, err
	}
	return seed, did, pq, nil
}

func ed25519FromKeyFile(raw []byte) (seed []byte, did string, rows []keyRow, err error) {
	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		return nil, "", nil, errors.New("key file is not valid JSON")
	}
	did = kf.ID
	rows = kf.Keys
	if kf.Encrypted {
		return nil, "", nil, errors.New(
			"the identity file is locked with a passphrase, which this sidecar cannot open. " +
				"Start `vouch sidecar` instead (it asks for the passphrase), or use an identity saved without one",
		)
	}
	if len(kf.PrivateKey) > 0 {
		// `vouch init` stores the JWK as a JSON string; accept an object too.
		inner := []byte(kf.PrivateKey)
		var asString string
		if err := json.Unmarshal(inner, &asString); err == nil {
			inner = []byte(asString)
		}
		kf = keyFile{}
		if err := json.Unmarshal(inner, &kf); err != nil {
			return nil, "", nil, errors.New("key file holds a private key that is not a JWK")
		}
	}
	if kf.Kty != "OKP" || kf.Crv != "Ed25519" {
		return nil, "", nil, errors.New("key file must hold an Ed25519 JWK (kty OKP, crv Ed25519)")
	}
	if kf.D == "" {
		return nil, "", nil, errors.New("key file has no private key (the JWK \"d\" member is missing)")
	}
	seed, err = decodeBase64URL(kf.D)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, "", nil, fmt.Errorf("key file private key must be %d bytes, base64url-encoded", ed25519.SeedSize)
	}
	if kf.X != "" {
		stated, err := decodeBase64URL(kf.X)
		derived := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		if err != nil || !bytes.Equal(stated, derived) {
			return nil, "", nil, errors.New("key file public key does not match its private key")
		}
	}
	return seed, did, rows, nil
}

func decodeBase64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}
