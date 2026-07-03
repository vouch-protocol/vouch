package robotics

import (
	"bytes"
	"testing"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// vectorCredentials pulls the conformance_credentials array out of the interop
// vector as a slice of credential objects.
func vectorCredentials(t *testing.T, v map[string]any) []map[string]any {
	t.Helper()
	raw, ok := v["conformance_credentials"].([]any)
	if !ok {
		t.Fatal("vector missing conformance_credentials")
	}
	creds := make([]map[string]any, len(raw))
	for i, c := range raw {
		m, ok := c.(map[string]any)
		if !ok {
			t.Fatalf("conformance_credentials[%d] is not an object", i)
		}
		creds[i] = m
	}
	return creds
}

// canonEqual reports whether two JSON-decoded values are structurally equal by
// comparing their JCS-canonical bytes. This sidesteps int-versus-float
// differences between a computed report (Go ints) and the vector (JSON floats).
func canonEqual(t *testing.T, a, b any) bool {
	t.Helper()
	ca, err := signer.Canonicalize(a)
	if err != nil {
		t.Fatalf("canonicalize a: %v", err)
	}
	cb, err := signer.Canonicalize(b)
	if err != nil {
		t.Fatalf("canonicalize b: %v", err)
	}
	return bytes.Equal(ca, cb)
}

// TestConformanceVectorReport is the cross-language interop proof: Go's checker
// over the pinned credential set and profile reproduces the report the Python
// reference pinned in the shared interop vector.
func TestConformanceVectorReport(t *testing.T) {
	v := loadVector(t)
	profileID, _ := v["conformance_profile_id"].(string)
	if profileID == "" {
		t.Fatal("vector missing conformance_profile_id")
	}
	creds := vectorCredentials(t, v)

	report, err := CheckConformance(creds, profileID)
	if err != nil {
		t.Fatalf("CheckConformance: %v", err)
	}

	expected, ok := v["expected_conformance_report"].(map[string]any)
	if !ok {
		t.Fatal("vector missing expected_conformance_report")
	}
	if !canonEqual(t, report, expected) {
		ca, _ := signer.CanonicalizeString(report)
		ce, _ := signer.CanonicalizeString(expected)
		t.Fatalf("report mismatch\n got: %s\nwant: %s", ca, ce)
	}
}

// TestConformanceVectorDigest checks the report digest matches the pinned value.
func TestConformanceVectorDigest(t *testing.T) {
	v := loadVector(t)
	profileID, _ := v["conformance_profile_id"].(string)
	creds := vectorCredentials(t, v)

	report, err := CheckConformance(creds, profileID)
	if err != nil {
		t.Fatalf("CheckConformance: %v", err)
	}
	digest, err := ReportDigest(report)
	if err != nil {
		t.Fatalf("ReportDigest: %v", err)
	}
	want, _ := v["expected_conformance_report_digest"].(string)
	if digest != want {
		t.Fatalf("digest mismatch\n got: %s\nwant: %s", digest, want)
	}
}

// TestConformanceAttestationRoundTrip signs an attestation over a computed report
// and verifies it under the issuer's key.
func TestConformanceAttestationRoundTrip(t *testing.T) {
	v := loadVector(t)
	creds := vectorCredentials(t, v)
	report, err := CheckConformance(creds, "eu-ai-act-high-risk")
	if err != nil {
		t.Fatal(err)
	}

	s := newRobot(t, "did:web:robot.example.com")
	cred, err := BuildConformanceAttestation(s, BuildConformanceAttestationOptions{
		RobotDID:     "did:web:robot.example.com",
		Report:       report,
		ValidSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}

	ok, subject := VerifyConformanceAttestation(cred, s.PublicKeyEd25519())
	if !ok {
		t.Fatal("round-trip verify failed")
	}
	if subject["profileId"] != "eu-ai-act-high-risk" {
		t.Fatalf("unexpected profileId: %v", subject["profileId"])
	}
	if subject["conforms"] != true {
		t.Fatalf("unexpected conforms: %v", subject["conforms"])
	}
	if _, ok := cred["validUntil"]; !ok {
		t.Fatal("expected validUntil to be set")
	}
}

// TestConformanceAttestationWrongKeyRejected rejects an attestation verified
// under a different key.
func TestConformanceAttestationWrongKeyRejected(t *testing.T) {
	v := loadVector(t)
	creds := vectorCredentials(t, v)
	report, _ := CheckConformance(creds, "eu-ai-act-high-risk")

	s := newRobot(t, "did:web:robot.example.com")
	cred, err := BuildConformanceAttestation(s, BuildConformanceAttestationOptions{
		RobotDID: "did:web:robot.example.com",
		Report:   report,
	})
	if err != nil {
		t.Fatal(err)
	}

	attacker := newRobot(t, "did:web:attacker.example.com")
	if ok, _ := VerifyConformanceAttestation(cred, attacker.PublicKeyEd25519()); ok {
		t.Fatal("expected verification under the wrong key to fail")
	}
}

// TestConformanceAttestationTamperedReportRejected rejects an attestation whose
// embedded report no longer matches its bound digest.
func TestConformanceAttestationTamperedReportRejected(t *testing.T) {
	v := loadVector(t)
	creds := vectorCredentials(t, v)
	report, _ := CheckConformance(creds, "eu-ai-act-high-risk")

	s := newRobot(t, "did:web:robot.example.com")
	cred, err := BuildConformanceAttestation(s, BuildConformanceAttestationOptions{
		RobotDID: "did:web:robot.example.com",
		Report:   report,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the embedded report after signing. The proof still verifies
	// (the subject is unchanged by re-signing here) only if we re-sign; instead
	// we mutate the embedded report so its digest no longer matches, and re-sign
	// so the proof is valid but the digest binding is broken.
	subject := cred["credentialSubject"].(map[string]any)
	embedded := subject["report"].(map[string]any)
	embedded["conforms"] = false
	delete(cred, "proof")
	resigned, err := s.AttachProof(cred)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := VerifyConformanceAttestation(resigned, s.PublicKeyEd25519()); ok {
		t.Fatal("expected a tampered embedded report to fail verification")
	}
}

// TestConformanceMissingFieldFails checks that a requirement with a missing field
// is reported unsatisfied and the profile does not conform.
func TestConformanceMissingFieldFails(t *testing.T) {
	// A credential set missing the ModelProvenanceAttestation weightsHash and
	// configHash fails the transparency and accuracy requirements.
	creds := []map[string]any{
		{
			"type": []any{"VerifiableCredential", "RobotSafetyRecordCredential"},
			"credentialSubject": map[string]any{
				"id":       "did:web:robot.example.com",
				"logHead":  "uHEAD",
				"physical": nil,
			},
		},
		{
			"type": []any{"VerifiableCredential", "ModelProvenanceAttestation"},
			"credentialSubject": map[string]any{
				"id": "did:web:robot.example.com",
				"vla": map[string]any{
					"modelName": "OpenVLA-7B",
					// weightsHash and configHash intentionally absent
				},
			},
		},
		{
			"type": []any{"VerifiableCredential", "PhysicalCapabilityScope"},
			"credentialSubject": map[string]any{
				"id": "did:web:robot.example.com",
				"physicalScope": map[string]any{
					"maxSpeedNearHumansMps": 0.25,
				},
			},
		},
	}

	report, err := CheckConformance(creds, "eu-ai-act-high-risk")
	if err != nil {
		t.Fatal(err)
	}
	if report["conforms"] != false {
		t.Fatalf("expected conforms=false, got %v", report["conforms"])
	}
	if report["satisfiedCount"] != 2 {
		t.Fatalf("expected satisfiedCount=2, got %v", report["satisfiedCount"])
	}

	// Confirm the two provenance-backed requirements are the unsatisfied ones.
	reqs := report["requirements"].([]any)
	byID := map[string]bool{}
	for _, r := range reqs {
		m := r.(map[string]any)
		byID[m["id"].(string)] = m["satisfied"].(bool)
	}
	if byID["eu-aia-transparency"] {
		t.Fatal("expected eu-aia-transparency unsatisfied")
	}
	if byID["eu-aia-accuracy-robustness"] {
		t.Fatal("expected eu-aia-accuracy-robustness unsatisfied")
	}
	if !byID["eu-aia-record-keeping"] {
		t.Fatal("expected eu-aia-record-keeping satisfied")
	}
}

// TestConformanceEmptyArrayUnsatisfied checks that an empty array at a required
// path counts as unsatisfied.
func TestConformanceEmptyArrayUnsatisfied(t *testing.T) {
	creds := []map[string]any{
		{
			"type": []any{"VerifiableCredential", "PhysicalCapabilityScope"},
			"credentialSubject": map[string]any{
				"id": "did:web:robot.example.com",
				"physicalScope": map[string]any{
					"maxSpeedMps":  1.5,
					"allowedZones": []any{},
				},
			},
		},
	}
	report, err := CheckConformance(creds, "ul-3300")
	if err != nil {
		t.Fatal(err)
	}
	reqs := report["requirements"].([]any)
	for _, r := range reqs {
		m := r.(map[string]any)
		if m["id"] == "ul3300-operating-limits" && m["satisfied"].(bool) {
			t.Fatal("expected ul3300-operating-limits unsatisfied for an empty allowedZones")
		}
	}
}

// TestUnknownProfile checks an unknown profile id is an error.
func TestUnknownProfile(t *testing.T) {
	if _, err := CheckConformance(nil, "no-such-profile"); err == nil {
		t.Fatal("expected an error for an unknown profile")
	}
}
