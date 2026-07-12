//go:build frost

// Tests for FROST(Ed25519) threshold signing. Requires CGO_ENABLED=1 and the
// native library built via ../build-native.sh (run: go test -tags frost ./...
// with LD_LIBRARY_PATH pointing at ../lib).
package signer

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func generateCommitSignAggregate(t *testing.T, minSigners, maxSigners uint16, indices []int, message []byte) (*GenerateKeyResult, []byte) {
	t.Helper()
	generated, err := ThresholdGenerateKey(minSigners, maxSigners)
	if err != nil {
		t.Fatalf("ThresholdGenerateKey: %v", err)
	}
	if len(generated.Shares) != int(maxSigners) {
		t.Fatalf("expected %d shares, got %d", maxSigners, len(generated.Shares))
	}

	noncesByID := make(map[string]string)
	commitments := make(map[string]string)
	for _, i := range indices {
		share := generated.Shares[i]
		round1, err := ThresholdCommit(share)
		if err != nil {
			t.Fatalf("ThresholdCommit: %v", err)
		}
		commitments[share.Identifier] = round1.Commitments
		noncesByID[share.Identifier] = round1.Nonces
	}

	sharesOut := make(map[string]string)
	for _, i := range indices {
		share := generated.Shares[i]
		sigShare, err := ThresholdSignShare(message, share, noncesByID[share.Identifier], commitments)
		if err != nil {
			t.Fatalf("ThresholdSignShare: %v", err)
		}
		sharesOut[share.Identifier] = sigShare
	}

	signature, err := ThresholdAggregate(message, commitments, sharesOut, generated.GroupPublicKey)
	if err != nil {
		t.Fatalf("ThresholdAggregate: %v", err)
	}
	return generated, signature
}

func TestTwoOfThreeSignsAndVerifiesAsPlainEd25519(t *testing.T) {
	message := []byte("charge api.bank invoices/42")
	generated, signature := generateCommitSignAggregate(t, 2, 3, []int{0, 2}, message)

	verifyingKey, err := base64.StdEncoding.DecodeString(generated.GroupPublicKey.VerifyingKey)
	if err != nil {
		t.Fatalf("decode verifying key: %v", err)
	}
	if !ed25519.Verify(verifyingKey, message, signature) {
		t.Fatal("FROST aggregate signature must verify as a plain Ed25519 signature")
	}
}

func TestDifferentSubsetOfSameGroupAlsoVerifies(t *testing.T) {
	message := []byte("same message, different signer subset")
	generated, err := ThresholdGenerateKey(3, 5)
	if err != nil {
		t.Fatalf("ThresholdGenerateKey: %v", err)
	}

	signWith := func(indices []int) []byte {
		noncesByID := make(map[string]string)
		commitments := make(map[string]string)
		for _, i := range indices {
			share := generated.Shares[i]
			round1, err := ThresholdCommit(share)
			if err != nil {
				t.Fatalf("ThresholdCommit: %v", err)
			}
			commitments[share.Identifier] = round1.Commitments
			noncesByID[share.Identifier] = round1.Nonces
		}
		sharesOut := make(map[string]string)
		for _, i := range indices {
			share := generated.Shares[i]
			sigShare, err := ThresholdSignShare(message, share, noncesByID[share.Identifier], commitments)
			if err != nil {
				t.Fatalf("ThresholdSignShare: %v", err)
			}
			sharesOut[share.Identifier] = sigShare
		}
		sig, err := ThresholdAggregate(message, commitments, sharesOut, generated.GroupPublicKey)
		if err != nil {
			t.Fatalf("ThresholdAggregate: %v", err)
		}
		return sig
	}

	sigA := signWith([]int{0, 1, 2})
	sigB := signWith([]int{2, 3, 4})

	verifyingKey, err := base64.StdEncoding.DecodeString(generated.GroupPublicKey.VerifyingKey)
	if err != nil {
		t.Fatalf("decode verifying key: %v", err)
	}
	if !ed25519.Verify(verifyingKey, message, sigA) {
		t.Fatal("subset A signature must verify")
	}
	if !ed25519.Verify(verifyingKey, message, sigB) {
		t.Fatal("subset B signature must verify")
	}
}

func TestWrongMessageFailsVerification(t *testing.T) {
	message := []byte("original message")
	generated, signature := generateCommitSignAggregate(t, 2, 3, []int{0, 1}, message)

	verifyingKey, err := base64.StdEncoding.DecodeString(generated.GroupPublicKey.VerifyingKey)
	if err != nil {
		t.Fatalf("decode verifying key: %v", err)
	}
	if ed25519.Verify(verifyingKey, []byte("tampered message"), signature) {
		t.Fatal("a signature over one message must not verify a different message")
	}
}

func TestThresholdGenerateKeyRejectsBadThreshold(t *testing.T) {
	if _, err := ThresholdGenerateKey(1, 3); err == nil {
		t.Fatal("expected error: min_signers must be >= 2")
	}
	if _, err := ThresholdGenerateKey(4, 3); err == nil {
		t.Fatal("expected error: min_signers must be <= max_signers")
	}
}

func TestThresholdSignerNeedsAtLeastTwoShares(t *testing.T) {
	generated, err := ThresholdGenerateKey(2, 3)
	if err != nil {
		t.Fatalf("ThresholdGenerateKey: %v", err)
	}
	if _, err := NewThresholdSigner(generated.Shares[:1], generated.GroupPublicKey); err == nil {
		t.Fatal("expected error: ThresholdSigner needs at least 2 key shares")
	}
}

func TestThresholdSignerPlugsIntoBackendSigner(t *testing.T) {
	generated, err := ThresholdGenerateKey(2, 3)
	if err != nil {
		t.Fatalf("ThresholdGenerateKey: %v", err)
	}
	thresholdSigner, err := NewThresholdSigner(generated.Shares[:2], generated.GroupPublicKey)
	if err != nil {
		t.Fatalf("NewThresholdSigner: %v", err)
	}

	verifyingKey, err := base64.StdEncoding.DecodeString(generated.GroupPublicKey.VerifyingKey)
	if err != nil {
		t.Fatalf("decode verifying key: %v", err)
	}

	s, err := NewBackend("did:web:agent.example.com", ed25519.PublicKey(verifyingKey), thresholdSigner.Sign, 300)
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}

	cred, err := s.Sign(SignOptions{Action: "read", Target: "t", Resource: "https://x/y"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	ok, err := VerifyDataIntegrityProof(cred, verifyingKey)
	if err != nil {
		t.Fatalf("VerifyDataIntegrityProof: %v", err)
	}
	if !ok {
		t.Fatal("credential signed by the threshold signer failed verification")
	}
}
