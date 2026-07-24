// Tests for the W3C Data Integrity signing-input alignment: the 64-byte
// hashData construction, and the backward compatibility that keeps
// pre-alignment credentials verifying.

package signer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"testing"
)

// preAlignmentCredential is a credential issued before the alignment, whose
// signature covers the pre-alignment signing input (a single SHA-256 over the
// JCS form of the credential with the unsigned proof attached). It is the
// shared fixture used by the reference implementation.
const preAlignmentCredential = `{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://vouch-protocol.com/contexts/v1"
  ],
  "type": ["VerifiableCredential", "VouchCredential"],
  "issuer": "did:web:test.example.com",
  "validFrom": "2026-04-26T10:00:00Z",
  "validUntil": "2026-04-26T10:05:00Z",
  "credentialSubject": {
    "id": "did:web:test.example.com",
    "vouchVersion": "1.0",
    "intent": {
      "action": "read_database",
      "target": "users_table",
      "resource": "https://api.example.com/v1/users"
    }
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "created": "2026-04-26T10:00:00Z",
    "verificationMethod": "did:web:test.example.com#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z24FsZHuADF9uwHAfsjW3okmynrNCCN4QkQirEPfEy5MtcXzg4uhFqz4o3RVH57cFvVXg9oarC4m51YEmNu5UQRLQ"
  }
}`

var preAlignmentPublicKey = ed25519.PublicKey([]byte{
	0x4c, 0xb5, 0xab, 0xf6, 0xad, 0x79, 0xfb, 0xf5, 0xab, 0xbc, 0xca, 0xfc,
	0xc2, 0x69, 0xd8, 0x5c, 0xd2, 0x65, 0x1e, 0xd4, 0xb8, 0x85, 0xb5, 0x86,
	0x9f, 0x24, 0x1a, 0xed, 0xf0, 0xa5, 0xba, 0x29,
})

// A credential issued before the Data Integrity alignment MUST still verify.
func TestVerifiesPreAlignmentCredential(t *testing.T) {
	var cred map[string]any
	if err := json.Unmarshal([]byte(preAlignmentCredential), &cred); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	ok, err := VerifyDataIntegrityProof(cred, preAlignmentPublicKey)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("a pre-alignment credential must still verify")
	}
}

// Tampering with a pre-alignment credential must not be rescued by the
// backward-compatible fallback.
func TestPreAlignmentFallbackStillRejectsTampering(t *testing.T) {
	var cred map[string]any
	if err := json.Unmarshal([]byte(preAlignmentCredential), &cred); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	subject := cred["credentialSubject"].(map[string]any)
	intent := subject["intent"].(map[string]any)
	intent["action"] = "delete_database"

	ok, err := VerifyDataIntegrityProof(cred, preAlignmentPublicKey)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("a tampered pre-alignment credential must not verify")
	}
}

// hashData is SHA-256(canonical proof configuration) followed by
// SHA-256(canonical unsecured document), 64 bytes, configuration hash first.
func TestHashDataConstruction(t *testing.T) {
	credential := map[string]any{
		"@context":  []any{"https://www.w3.org/ns/credentials/v2"},
		"issuer":    "did:web:agent.example.com",
		"validFrom": "2026-04-26T10:00:00Z",
		"proof":     map[string]any{"proofValue": "zshould-be-ignored"},
	}
	unsigned := map[string]any{
		"type":               ProofTypeDataIntegrity,
		"cryptosuite":        CryptosuiteEddsaJcs2022,
		"created":            "2026-04-26T10:00:00Z",
		"verificationMethod": "did:web:agent.example.com#key-1",
		"proofPurpose":       "assertionMethod",
	}

	got, err := HashData(credential, unsigned)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 64 {
		t.Fatalf("hashData length %d, expected 64", len(got))
	}

	document := map[string]any{
		"@context":  credential["@context"],
		"issuer":    credential["issuer"],
		"validFrom": credential["validFrom"],
	}
	config := copyMap(unsigned)
	config["@context"] = credential["@context"]

	canonicalConfig, err := Canonicalize(config)
	if err != nil {
		t.Fatal(err)
	}
	canonicalDocument, err := Canonicalize(document)
	if err != nil {
		t.Fatal(err)
	}
	configHash := sha256.Sum256(canonicalConfig)
	documentHash := sha256.Sum256(canonicalDocument)

	if string(got[:32]) != string(configHash[:]) {
		t.Fatal("first 32 bytes are not the proof configuration hash")
	}
	if string(got[32:]) != string(documentHash[:]) {
		t.Fatal("last 32 bytes are not the document hash")
	}
}

// The proof configuration carries the document's @context, so a credential
// signed under one context does not verify under another.
func TestProofConfigurationBindsContext(t *testing.T) {
	s := newTestSigner(t, "")
	cred, err := s.Sign(SignOptions{Intent: validIntent()})
	if err != nil {
		t.Fatal(err)
	}
	cred["@context"] = []any{"https://example.com/attacker/v1"}

	ok, err := VerifyDataIntegrityProof(cred, s.PublicKeyEd25519())
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("swapping @context must invalidate the proof")
	}
}

// A freshly issued credential signs the aligned 64-byte input, not the
// pre-alignment digest.
func TestNewProofsSignTheAlignedInput(t *testing.T) {
	s := newTestSigner(t, "")
	cred, err := s.Sign(SignOptions{Intent: validIntent()})
	if err != nil {
		t.Fatal(err)
	}
	proof := cred["proof"].(map[string]any)
	pv := proof["proofValue"].(string)
	signature, err := b58Decode(pv[1:])
	if err != nil {
		t.Fatal(err)
	}
	unsigned := copyMap(proof)
	delete(unsigned, "proofValue")

	signingInput, err := HashData(cred, unsigned)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(s.PublicKeyEd25519(), signingInput, signature) {
		t.Fatal("a new proof must sign the aligned 64-byte signing input")
	}

	legacy, err := LegacyProofDigest(cred, unsigned)
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(s.PublicKeyEd25519(), legacy, signature) {
		t.Fatal("a new proof must not sign the pre-alignment digest")
	}
}
