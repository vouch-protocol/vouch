package signer

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSplitAndCombineRoundtrip(t *testing.T) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("rand: %v", err)
	}
	shares, err := SplitSecret(secret, 3, 5)
	if err != nil {
		t.Fatalf("SplitSecret: %v", err)
	}
	if len(shares) != 5 {
		t.Fatalf("expected 5 shares, got %d", len(shares))
	}

	combined, err := CombineShares(shares[:3])
	if err != nil {
		t.Fatalf("CombineShares: %v", err)
	}
	if !bytes.Equal(combined, secret) {
		t.Fatal("combined secret does not match original")
	}

	combined2, err := CombineShares([]([]byte){shares[0], shares[2], shares[4]})
	if err != nil {
		t.Fatalf("CombineShares (alt subset): %v", err)
	}
	if !bytes.Equal(combined2, secret) {
		t.Fatal("alt subset combined secret does not match original")
	}
}

func TestBelowThresholdDoesNotRevealSecret(t *testing.T) {
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("rand: %v", err)
	}
	shares, err := SplitSecret(secret, 3, 5)
	if err != nil {
		t.Fatalf("SplitSecret: %v", err)
	}
	combined, err := CombineShares(shares[:2])
	if err != nil {
		t.Fatalf("CombineShares: %v", err)
	}
	if bytes.Equal(combined, secret) {
		t.Fatal("below-threshold shares must not reveal the secret")
	}
}

func TestSplitSecretInvalidParameters(t *testing.T) {
	if _, err := SplitSecret(nil, 2, 3); err == nil {
		t.Fatal("expected error for empty secret")
	}
	if _, err := SplitSecret([]byte{1}, 1, 3); err == nil {
		t.Fatal("expected error for threshold < 2")
	}
	if _, err := SplitSecret([]byte{1}, 4, 3); err == nil {
		t.Fatal("expected error for threshold > shares")
	}
}

func TestCombineSharesRejectsInconsistentInput(t *testing.T) {
	secret := make([]byte, 16)
	shares, err := SplitSecret(secret, 2, 3)
	if err != nil {
		t.Fatalf("SplitSecret: %v", err)
	}
	if _, err := CombineShares([][]byte{shares[0], shares[0]}); err == nil {
		t.Fatal("expected error for duplicate share index")
	}
	if _, err := CombineShares([][]byte{shares[0], shares[1][:5]}); err == nil {
		t.Fatal("expected error for inconsistent share length")
	}
}

func TestSplitAndRecoverIdentitySignsIdentically(t *testing.T) {
	identity, err := GenerateIdentity("root.example")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	shares, err := SplitIdentity(identity.Seed, 2, 3)
	if err != nil {
		t.Fatalf("SplitIdentity: %v", err)
	}
	if len(shares) != 3 {
		t.Fatalf("expected 3 shares, got %d", len(shares))
	}

	recovered, err := RecoverIdentity(shares[:2], identity.DID)
	if err != nil {
		t.Fatalf("RecoverIdentity: %v", err)
	}
	if recovered.DID != identity.DID {
		t.Fatalf("recovered DID mismatch: %s != %s", recovered.DID, identity.DID)
	}
	if !bytes.Equal(recovered.PublicKey, identity.PublicKey) {
		t.Fatal("recovered public key does not match the original")
	}

	// The recovered key is the original key: sign with it and verify against
	// the ORIGINAL public key.
	recoveredSigner, err := New(Config{DID: recovered.DID, Ed25519Seed: recovered.Seed, DefaultExpirySeconds: 300})
	if err != nil {
		t.Fatalf("New (recovered signer): %v", err)
	}
	cred, err := recoveredSigner.SignCredential(SignCredentialOptions{
		Action: "read", Target: "t", Resource: "https://x/y",
	})
	if err != nil {
		t.Fatalf("SignCredential: %v", err)
	}
	ok, err := VerifyDataIntegrityProof(cred, identity.PublicKey)
	if err != nil {
		t.Fatalf("VerifyDataIntegrityProof: %v", err)
	}
	if !ok {
		t.Fatal("credential signed by the recovered key did not verify against the original public key")
	}
}

func TestRecoverIdentityWithoutExplicitDID(t *testing.T) {
	identity, err := GenerateIdentity("")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	shares, err := SplitIdentity(identity.Seed, 2, 3)
	if err != nil {
		t.Fatalf("SplitIdentity: %v", err)
	}
	recovered, err := RecoverIdentity(shares[1:3], "")
	if err != nil {
		t.Fatalf("RecoverIdentity: %v", err)
	}
	if recovered.DID != identity.DID {
		t.Fatalf("derived did:key mismatch: %s != %s", recovered.DID, identity.DID)
	}
}

func TestTooFewSharesRejectedByLength(t *testing.T) {
	identity, err := GenerateIdentity("root.example")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	shares, err := SplitIdentity(identity.Seed, 3, 5)
	if err != nil {
		t.Fatalf("SplitIdentity: %v", err)
	}
	// Two shares when three are required: CombineShares still returns 32
	// bytes (it does not know the threshold), so RecoverIdentity succeeds
	// structurally but the seed (and therefore the DID) will not match the
	// original, since interpolation with too few points gives the wrong value.
	recovered, err := RecoverIdentity(shares[:2], "")
	if err != nil {
		t.Fatalf("RecoverIdentity: %v", err)
	}
	if recovered.DID == identity.DID {
		t.Fatal("expected a wrong DID when recovering with fewer than the threshold")
	}
}
