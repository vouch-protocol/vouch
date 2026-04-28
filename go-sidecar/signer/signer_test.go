package signer_test

import (
	"encoding/json"
	"testing"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// TestStandardSign verifies that a non-sensitive sign request produces
// a valid composite JWS token.
func TestStandardSign(t *testing.T) {
	s := newTestSigner(t)

	req := signer.SignRequest{
		Payload:   map[string]any{"action": "read_email", "scope": "inbox"},
		Sensitive: false,
	}

	out, err := s.Sign(req)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	var token signer.VouchToken
	if err := json.Unmarshal(out, &token); err != nil {
		t.Fatalf("output is not a VouchToken: %v", err)
	}

	if token.Mode != "standard" {
		t.Errorf("expected mode 'standard', got %q", token.Mode)
	}
	if token.Token == "" {
		t.Error("token is empty")
	}
}

// TestSensitiveSign_RoundTrip verifies the full sensitive flow:
// Sign -> JWE Vault -> Decrypt -> Verify composite JWS -> Extract claims.
func TestSensitiveSign_RoundTrip(t *testing.T) {
	s := newTestSigner(t)

	// Generate recipient KEM keypair
	recipientDK, recipientPubB64, err := signer.GenerateTestKEMKeyPair()
	if err != nil {
		t.Fatalf("GenerateKEMKeyPair() failed: %v", err)
	}

	req := signer.SignRequest{
		Payload:               map[string]any{"action": "transfer_funds", "amount": 50000},
		Sensitive:             true,
		RecipientKEMPublicKey: recipientPubB64,
		ExpirySeconds:         60,
	}

	out, err := s.Sign(req)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	// Parse as SensitiveVault
	var vault signer.SensitiveVault
	if err := json.Unmarshal(out, &vault); err != nil {
		t.Fatalf("output is not a SensitiveVault: %v", err)
	}

	if vault.Mode != "sensitive" {
		t.Errorf("expected mode 'sensitive', got %q", vault.Mode)
	}
	if vault.Algorithm != "ML-KEM-768" {
		t.Errorf("expected alg 'ML-KEM-768', got %q", vault.Algorithm)
	}
	if vault.Encryption != "A256GCM" {
		t.Errorf("expected enc 'A256GCM', got %q", vault.Encryption)
	}

	// Decrypt the vault
	jwsData, err := signer.DecryptVault(&vault, recipientDK)
	if err != nil {
		t.Fatalf("DecryptVault() failed: %v", err)
	}

	// Verify the composite JWS
	claims, err := signer.VerifyCompositeJWS(jwsData, s.Ed25519Public(), s.MLDSAPublic())
	if err != nil {
		t.Fatalf("VerifyCompositeJWS() failed: %v", err)
	}

	// Validate claims
	if claims.ISS != "did:web:test-agent.example.com" {
		t.Errorf("expected iss 'did:web:test-agent.example.com', got %q", claims.ISS)
	}

	vouch, ok := claims.Vouch["payload"].(map[string]any)
	if !ok {
		t.Fatal("missing vouch.payload")
	}
	if vouch["action"] != "transfer_funds" {
		t.Errorf("expected action 'transfer_funds', got %v", vouch["action"])
	}
}

// TestSensitiveSign_MissingRecipientKey ensures an error when no
// recipient key is provided with sensitive=true.
func TestSensitiveSign_MissingRecipientKey(t *testing.T) {
	s := newTestSigner(t)

	req := signer.SignRequest{
		Payload:   map[string]any{"action": "delete_all"},
		Sensitive: true,
		// RecipientKEMPublicKey intentionally omitted
	}

	_, err := s.Sign(req)
	if err == nil {
		t.Fatal("expected error for missing recipient key, got nil")
	}
}

// TestDecryptVault_WrongKey verifies decryption fails with wrong key.
func TestDecryptVault_WrongKey(t *testing.T) {
	s := newTestSigner(t)

	// Intended recipient
	_, recipientPubB64, err := signer.GenerateTestKEMKeyPair()
	if err != nil {
		t.Fatalf("GenerateKEMKeyPair() failed: %v", err)
	}

	// Attacker's key
	attackerDK, _, err := signer.GenerateTestKEMKeyPair()
	if err != nil {
		t.Fatalf("GenerateKEMKeyPair() failed: %v", err)
	}

	req := signer.SignRequest{
		Payload:               map[string]any{"action": "confidential_briefing"},
		Sensitive:             true,
		RecipientKEMPublicKey: recipientPubB64,
	}

	out, err := s.Sign(req)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	var vault signer.SensitiveVault
	if err := json.Unmarshal(out, &vault); err != nil {
		t.Fatalf("output is not a SensitiveVault: %v", err)
	}

	// Attempt decryption with attacker's key -- must fail
	_, err = signer.DecryptVault(&vault, attackerDK)
	if err == nil {
		t.Fatal("expected decryption to fail with wrong key, but it succeeded")
	}
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func newTestSigner(t *testing.T) *signer.TestSigner {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i) // deterministic test seed
	}

	s, err := signer.NewTestSigner(signer.Config{
		DID:                  "did:web:test-agent.example.com",
		Ed25519Seed:          seed,
		DefaultExpirySeconds: 300,
	})
	if err != nil {
		t.Fatalf("NewTestSigner() failed: %v", err)
	}
	return s
}
