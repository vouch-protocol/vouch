package robotics

import (
	"reflect"
	"testing"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

const (
	testFleetStatusURL = "https://fleet.example.com/status/1"
	testStatusIndex    = 42
)

// TestStatusEntryMatchesVector reconstructs the generator's credentialStatus
// entry and asserts it equals the pinned expected_credential_status_entry.
func TestStatusEntryMatchesVector(t *testing.T) {
	v := loadVector(t)
	entry, err := signer.BuildStatusListEntry(signer.BuildStatusListEntryOptions{
		StatusListCredential: testFleetStatusURL,
		StatusListIndex:      testStatusIndex,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := jsonRoundTrip(t, entry)
	want := v["expected_credential_status_entry"].(map[string]any)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("status entry mismatch:\n got=%v\nwant=%v", got, want)
	}
}

// buildSignedStatusList builds and signs a BitstringStatusListCredential whose
// id is testFleetStatusURL, with the given index revoked.
func buildSignedStatusList(t *testing.T, issuer *signer.Signer, revokeIndex int) map[string]any {
	t.Helper()
	sl, err := signer.NewStatusList(testFleetStatusURL, signer.StatusPurposeRevocation, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := sl.Revoke(revokeIndex); err != nil {
		t.Fatal(err)
	}
	listCred, err := signer.BuildStatusListCredential(signer.BuildStatusListCredentialOptions{
		IssuerDID:    issuer.DID(),
		StatusList:   sl,
		CredentialID: testFleetStatusURL,
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := issuer.AttachProof(listCred)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestAttachAndCheckCredentialStatus(t *testing.T) {
	robot := newRobot(t, "did:web:robot.example.com")
	fleet := newRobot(t, "did:web:fleet.example.com")

	// A minimal robot credential the fleet can pin a status bit on.
	cred, err := MintRobotIdentity(robot, mustRoot(t), MintOptions{
		Make: "Acme", Model: "AR-7", Serial: "SN-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	withStatus, err := AttachCredentialStatus(cred, robot, AttachStatusOptions{
		StatusListCredential: testFleetStatusURL,
		StatusListIndex:      testStatusIndex,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The proof must still verify after the status entry was added and re-signed.
	if ok, _ := VerifyRobotIdentity(withStatus, robot.PublicKeyEd25519()); !ok {
		t.Fatal("expected the re-signed credential to verify")
	}

	// Index 42 revoked: the status check reports revoked.
	revoked := buildSignedStatusList(t, fleet, testStatusIndex)
	set, err := CheckCredentialStatus(withStatus, revoked, "")
	if err != nil {
		t.Fatal(err)
	}
	if !set {
		t.Fatal("expected the revoked bit to be reported as set")
	}

	// A different index revoked: index 42 is clear, so not revoked.
	other := buildSignedStatusList(t, fleet, 7)
	set, err = CheckCredentialStatus(withStatus, other, "")
	if err != nil {
		t.Fatal(err)
	}
	if set {
		t.Fatal("expected an unrevoked bit to be reported as clear")
	}
}

func TestCheckCredentialStatusNoEntry(t *testing.T) {
	fleet := newRobot(t, "did:web:fleet.example.com")
	cred := map[string]any{"type": []any{"VerifiableCredential"}}
	list := buildSignedStatusList(t, fleet, testStatusIndex)
	set, err := CheckCredentialStatus(cred, list, "")
	if err != nil {
		t.Fatal(err)
	}
	if set {
		t.Fatal("expected a credential without a status entry to report clear")
	}
}

func TestAttachCredentialStatusAppends(t *testing.T) {
	robot := newRobot(t, "did:web:robot.example.com")
	cred, err := MintRobotIdentity(robot, mustRoot(t), MintOptions{Make: "A", Model: "B", Serial: "C"})
	if err != nil {
		t.Fatal(err)
	}
	cred, err = AttachCredentialStatus(cred, robot, AttachStatusOptions{
		StatusListCredential: testFleetStatusURL, StatusListIndex: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	cred, err = AttachCredentialStatus(cred, robot, AttachStatusOptions{
		StatusListCredential: testFleetStatusURL, StatusListIndex: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	list, ok := asAnyList(cred["credentialStatus"])
	if !ok || len(list) != 2 {
		t.Fatalf("expected credentialStatus to become a 2-element list, got %v", cred["credentialStatus"])
	}
}

func mustRoot(t *testing.T) *SoftwareRootOfTrust {
	t.Helper()
	root, err := NewSoftwareRoot(filled(7), "TPM")
	if err != nil {
		t.Fatal(err)
	}
	return root
}
