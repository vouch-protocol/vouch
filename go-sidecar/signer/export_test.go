package signer

import (
	"crypto/ed25519"
	"crypto/mlkem"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// TestSigner wraps a Signer and exposes public keys for test verification.
type TestSigner struct {
	*Signer
}

// NewTestSigner creates a Signer and returns it wrapped for testing.
func NewTestSigner(cfg Config) (*TestSigner, error) {
	s, err := New(cfg)
	if err != nil {
		return nil, err
	}
	return &TestSigner{Signer: s}, nil
}

// Ed25519Public returns the classical public key for test verification.
func (ts *TestSigner) Ed25519Public() ed25519.PublicKey {
	return ts.Signer.ed25519Public
}

// MLDSAPublic returns the post-quantum public key for test verification.
func (ts *TestSigner) MLDSAPublic() *mldsa65.PublicKey {
	return ts.Signer.mldsaPublic
}

// GenerateTestKEMKeyPair is a test-accessible wrapper for GenerateKEMKeyPair.
func GenerateTestKEMKeyPair() (*mlkem.DecapsulationKey768, string, error) {
	return GenerateKEMKeyPair()
}
