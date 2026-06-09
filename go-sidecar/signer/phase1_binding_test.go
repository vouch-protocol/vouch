package signer

import "testing"

// Security regression tests for proofPurpose enforcement and
// verificationMethod-to-issuer binding in VerifyDataIntegrityProof. These run
// before signature verification, so tampering the bound fields is rejected on
// the binding check itself.

func TestVerifyRejectsWrongProofPurpose(t *testing.T) {
	s := newTestSigner(t, "")
	cred, _ := s.SignCredential(SignCredentialOptions{Intent: validIntent()})
	proof := cred["proof"].(map[string]any)
	proof["proofPurpose"] = "authentication"

	ok, err := VerifyDataIntegrityProof(cred, s.PublicKeyEd25519())
	if ok || err == nil {
		t.Fatalf("expected wrong proofPurpose to be rejected, got ok=%v err=%v", ok, err)
	}
}

func TestVerifyRejectsCrossIssuerVerificationMethod(t *testing.T) {
	s := newTestSigner(t, "")
	cred, _ := s.SignCredential(SignCredentialOptions{Intent: validIntent()})
	proof := cred["proof"].(map[string]any)
	proof["verificationMethod"] = "did:web:attacker.example.com#key-1"

	ok, err := VerifyDataIntegrityProof(cred, s.PublicKeyEd25519())
	if ok || err == nil {
		t.Fatalf("expected cross-issuer verificationMethod to be rejected, got ok=%v err=%v", ok, err)
	}
}

func TestVerifyAcceptsBoundCredential(t *testing.T) {
	s := newTestSigner(t, "")
	cred, _ := s.SignCredential(SignCredentialOptions{Intent: validIntent()})

	ok, err := VerifyDataIntegrityProof(cred, s.PublicKeyEd25519())
	if !ok || err != nil {
		t.Fatalf("expected a properly bound credential to verify, got ok=%v err=%v", ok, err)
	}
}

func TestDelegationLinkStoresFullParentProofValue(t *testing.T) {
	parent := newTestSigner(t, "did:web:alice.example.com")
	child := newTestSigner(t, "did:web:assistant.example.com")

	parentCred, _ := parent.SignCredential(SignCredentialOptions{
		Intent: map[string]any{
			"action":   "manage_bookings",
			"target":   "destination:Paris",
			"resource": "https://travel-api.example.com/v1/bookings",
		},
	})
	childCred, err := child.SignCredential(SignCredentialOptions{
		Intent: map[string]any{
			"action":   "manage_bookings",
			"target":   "destination:Paris",
			"resource": "https://travel-api.example.com/v1/bookings/flight-AF123",
		},
		ParentCredential: parentCred,
	})
	if err != nil {
		t.Fatal(err)
	}

	subject := childCred["credentialSubject"].(map[string]any)
	link := subject["delegationChain"].([]any)[0].(map[string]any)
	full := parentCred["proof"].(map[string]any)["proofValue"].(string)

	if link["parentProofValue"] != full {
		t.Fatal("parentProofValue must equal the full parent proofValue")
	}
	if len(link["parentProofValue"].(string)) <= 64 {
		t.Fatal("parentProofValue looks truncated (<= 64 chars)")
	}
}
