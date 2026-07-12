// Ed25519 identity generation and did:key encoding/decoding.
//
// Mirrors vouch/keys.py's generate_identity and the did:key helpers already
// used by the Python and TypeScript SDKs.

package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
)

// Identity is a freshly generated Ed25519 key pair. Seed is the 32-byte
// private seed (RFC 8032); PublicKey is the 32-byte public key.
type Identity struct {
	DID       string
	Seed      []byte
	PublicKey ed25519.PublicKey
}

// GenerateIdentity generates a new Ed25519 identity. With a non-empty domain
// the DID is did:web:<domain>; with an empty domain it is a self-certifying
// did:key (verifiable offline, no DID document to host).
func GenerateIdentity(domain string) (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate identity: %w", err)
	}
	seed := priv.Seed()

	var did string
	if domain != "" {
		did = "did:web:" + domain
	} else {
		did, err = DIDKeyFromEd25519(pub)
		if err != nil {
			return nil, err
		}
	}

	return &Identity{DID: did, Seed: seed, PublicKey: pub}, nil
}

// DIDKeyFromEd25519 encodes an Ed25519 public key as a did:key identifier.
func DIDKeyFromEd25519(pub ed25519.PublicKey) (string, error) {
	multikey, err := EncodeEd25519Public(pub)
	if err != nil {
		return "", err
	}
	return "did:key:" + multikey, nil
}

// Ed25519FromDIDKey decodes the Ed25519 public key embedded in a did:key
// identifier. Returns an error if did is not an Ed25519 did:key.
func Ed25519FromDIDKey(did string) (ed25519.PublicKey, error) {
	const prefix = "did:key:"
	if !strings.HasPrefix(did, prefix) {
		return nil, fmt.Errorf("not a did:key: %s", did)
	}
	algorithm, raw, err := MultikeyDecode(strings.TrimPrefix(did, prefix))
	if err != nil {
		return nil, fmt.Errorf("decode did:key: %w", err)
	}
	if algorithm != "Ed25519" {
		return nil, fmt.Errorf("did:key is not Ed25519: %s", algorithm)
	}
	return ed25519.PublicKey(raw), nil
}

// IsDIDKey reports whether did is a did:key identifier.
func IsDIDKey(did string) bool {
	return strings.HasPrefix(did, "did:key:")
}
