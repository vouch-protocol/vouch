package robotics

import (
	"testing"
)

// TestVerifyPqInteropVector is the cross-language PQ interop proof: Go verifies
// the hybrid-signed RobotIdentityCredential minted by the Python module and
// pinned in the shared interop vector.
func TestVerifyPqInteropVector(t *testing.T) {
	v := loadVector(t)
	pub := ed25519FromJWK(t, v["robot_public_key_jwk"].(map[string]any))
	cred := v["pq_robot_identity_credential"].(map[string]any)
	mlMultikey := v["robot_mldsa44_public_multikey"].(string)

	if !IsPq(cred) {
		t.Fatal("expected the pinned PQ credential to report IsPq true")
	}
	ok := VerifyRobotCredential(cred, pub, VerifyRobotCredentialOptions{Mldsa44PublicKey: mlMultikey})
	if !ok {
		t.Fatal("expected the Python-minted hybrid interop vector to verify in Go")
	}
}

func TestSignPqRoundTrip(t *testing.T) {
	s := newRobot(t, "did:web:robot.example.com")
	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", RobotIdentityType},
		"issuer":            s.DID(),
		"validFrom":         "2026-01-01T00:00:00Z",
		"credentialSubject": map[string]any{"id": s.DID(), "make": "Acme"},
	}
	signed, err := SignPq(cred, s)
	if err != nil {
		t.Fatal(err)
	}
	if !IsPq(signed) {
		t.Fatal("SignPq output should report IsPq true")
	}

	mlMultikey, err := s.PublicKeyMLDSA44Multikey()
	if err != nil {
		t.Fatal(err)
	}

	// Verify with a Multikey string.
	if !VerifyPq(signed, s.PublicKeyEd25519(), mlMultikey) {
		t.Fatal("round-trip VerifyPq (multikey) failed")
	}
	// Verify with the raw ML-DSA-44 public key too.
	if !VerifyRobotCredential(signed, s.PublicKeyEd25519(), VerifyRobotCredentialOptions{Mldsa44PublicKey: s.PublicKeyMLDSA44()}) {
		t.Fatal("round-trip VerifyRobotCredential (raw key) failed")
	}
}

func TestSignPqStripsExistingProof(t *testing.T) {
	s := newRobot(t, "did:web:robot.example.com")
	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", RobotIdentityType},
		"issuer":            s.DID(),
		"validFrom":         "2026-01-01T00:00:00Z",
		"credentialSubject": map[string]any{"id": s.DID()},
	}
	classical, err := s.AttachProof(cred)
	if err != nil {
		t.Fatal(err)
	}
	if IsPq(classical) {
		t.Fatal("classical credential should not report IsPq")
	}
	signed, err := SignPq(classical, s)
	if err != nil {
		t.Fatal(err)
	}
	if !IsPq(signed) {
		t.Fatal("re-signed credential should be hybrid")
	}
	if !VerifyPq(signed, s.PublicKeyEd25519(), s.PublicKeyMLDSA44()) {
		t.Fatal("re-signed credential should verify")
	}
}

func TestVerifyPqTamperedRejected(t *testing.T) {
	s := newRobot(t, "did:web:robot.example.com")
	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", RobotIdentityType},
		"issuer":            s.DID(),
		"validFrom":         "2026-01-01T00:00:00Z",
		"credentialSubject": map[string]any{"id": s.DID(), "make": "Acme"},
	}
	signed, err := SignPq(cred, s)
	if err != nil {
		t.Fatal(err)
	}
	// Tamper with the body after signing.
	signed["credentialSubject"].(map[string]any)["make"] = "Evil Corp"
	if VerifyPq(signed, s.PublicKeyEd25519(), s.PublicKeyMLDSA44()) {
		t.Fatal("expected a tampered hybrid credential to fail verification")
	}
}

func TestVerifyPqWrongKeyRejected(t *testing.T) {
	s := newRobot(t, "did:web:robot.example.com")
	other := newRobot(t, "did:web:other.example.com")
	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", RobotIdentityType},
		"issuer":            s.DID(),
		"validFrom":         "2026-01-01T00:00:00Z",
		"credentialSubject": map[string]any{"id": s.DID()},
	}
	signed, err := SignPq(cred, s)
	if err != nil {
		t.Fatal(err)
	}
	// Wrong Ed25519 key.
	if VerifyPq(signed, other.PublicKeyEd25519(), s.PublicKeyMLDSA44()) {
		t.Fatal("expected the wrong Ed25519 key to fail verification")
	}
	// Wrong ML-DSA-44 key.
	if VerifyPq(signed, s.PublicKeyEd25519(), other.PublicKeyMLDSA44()) {
		t.Fatal("expected the wrong ML-DSA-44 key to fail verification")
	}
}

func TestClassicalPassesDualVerify(t *testing.T) {
	s := newRobot(t, "did:web:robot.example.com")
	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", RobotIdentityType},
		"issuer":            s.DID(),
		"validFrom":         "2026-01-01T00:00:00Z",
		"credentialSubject": map[string]any{"id": s.DID()},
	}
	classical, err := s.AttachProof(cred)
	if err != nil {
		t.Fatal(err)
	}
	// A classical credential verifies through the dual-mode verify without any
	// ML-DSA-44 key.
	if !VerifyRobotCredential(classical, s.PublicKeyEd25519(), VerifyRobotCredentialOptions{}) {
		t.Fatal("expected a classical credential to pass the dual-mode verify")
	}
}

func TestHybridWithoutKeyRejected(t *testing.T) {
	s := newRobot(t, "did:web:robot.example.com")
	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", RobotIdentityType},
		"issuer":            s.DID(),
		"validFrom":         "2026-01-01T00:00:00Z",
		"credentialSubject": map[string]any{"id": s.DID()},
	}
	signed, err := SignPq(cred, s)
	if err != nil {
		t.Fatal(err)
	}
	// A hybrid credential without an ML-DSA-44 key must not verify.
	if VerifyRobotCredential(signed, s.PublicKeyEd25519(), VerifyRobotCredentialOptions{}) {
		t.Fatal("expected a hybrid credential without an ML-DSA-44 key to fail")
	}
}

func TestMigrateToPq(t *testing.T) {
	s := newRobot(t, "did:web:robot.example.com")
	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", RobotIdentityType},
		"issuer":            s.DID(),
		"validFrom":         "2026-01-01T00:00:00Z",
		"credentialSubject": map[string]any{"id": s.DID()},
	}
	classical, err := s.AttachProof(cred)
	if err != nil {
		t.Fatal(err)
	}
	migrated, err := MigrateToPq(classical, s)
	if err != nil {
		t.Fatal(err)
	}
	if !IsPq(migrated) {
		t.Fatal("migrated credential should be hybrid")
	}
	if !VerifyRobotCredential(migrated, s.PublicKeyEd25519(), VerifyRobotCredentialOptions{Mldsa44PublicKey: s.PublicKeyMLDSA44()}) {
		t.Fatal("migrated credential should verify hybrid")
	}
}
