package robotics

import (
	"crypto/ed25519"
	"testing"
)

// TestLifecycleInteropVectors is the cross-language interop proof: Go verifies
// the ownership-transfer, key-rotation, and decommission credentials minted by
// the Python module and pinned in the shared interop vector.
func TestLifecycleInteropVectors(t *testing.T) {
	v := loadVector(t)

	// (a) ownership transfer verifies under its owner key.
	ownerPub := ed25519FromJWK(t, v["ownership_transfer_owner_key"].(map[string]any))
	transfer := v["ownership_transfer_credential"].(map[string]any)
	if ok, subject := VerifyOwnershipTransfer(transfer, ownerPub); !ok {
		t.Fatal("expected the Python-minted ownership transfer to verify in Go")
	} else if subject["toOwner"] != "did:web:owner-b.example.com" {
		t.Fatalf("unexpected toOwner: %v", subject["toOwner"])
	}

	// (b) key rotation verifies under the robot (old) key.
	robotPub := ed25519FromJWK(t, v["robot_public_key_jwk"].(map[string]any))
	rotation := v["key_rotation_credential"].(map[string]any)
	if ok, subject := VerifyKeyRotation(rotation, robotPub); !ok {
		t.Fatal("expected the Python-minted key rotation to verify in Go")
	} else if subject["newKey"] == "" {
		t.Fatal("key rotation subject missing newKey")
	}

	// (c) decommission verifies under the authority key.
	authPub := ed25519FromJWK(t, v["decommission_authority_key"].(map[string]any))
	decommission := v["decommission_credential"].(map[string]any)
	if ok, subject := VerifyDecommission(decommission, authPub, VerifyDecommissionOptions{}); !ok {
		t.Fatal("expected the Python-minted decommission to verify in Go")
	} else if subject["reason"] != "end of service life" {
		t.Fatalf("unexpected reason: %v", subject["reason"])
	}
}

func TestOwnershipTransferRoundTrip(t *testing.T) {
	owner := newRobot(t, "did:web:owner-a.example.com")
	cred, err := BuildOwnershipTransfer(owner, BuildOwnershipTransferOptions{
		RobotDID: "did:web:robot.example.com",
		ToOwner:  "did:web:owner-b.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(cred["type"], OwnershipTransferType) {
		t.Fatal("missing RobotOwnershipTransferCredential type")
	}
	ok, subject := VerifyOwnershipTransfer(cred, owner.PublicKeyEd25519())
	if !ok {
		t.Fatal("ownership-transfer round-trip verify failed")
	}
	if subject["fromOwner"] != "did:web:owner-a.example.com" {
		t.Fatalf("fromOwner did not default to the signer: %v", subject["fromOwner"])
	}
}

// TestOwnershipTransferRejectsIssuerNotFromOwner ensures that only the current
// owner (issuer == fromOwner) can transfer the robot.
func TestOwnershipTransferRejectsIssuerNotFromOwner(t *testing.T) {
	owner := newRobot(t, "did:web:owner-a.example.com")
	cred, err := BuildOwnershipTransfer(owner, BuildOwnershipTransferOptions{
		RobotDID:  "did:web:robot.example.com",
		ToOwner:   "did:web:owner-b.example.com",
		FromOwner: "did:web:someone-else.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Issuer is owner-a but fromOwner claims someone-else: must be rejected.
	if ok, _ := VerifyOwnershipTransfer(cred, owner.PublicKeyEd25519()); ok {
		t.Fatal("expected a transfer whose issuer is not the fromOwner to be rejected")
	}
}

func TestCustodyChainAcceptAndBrokenLink(t *testing.T) {
	a := newRobot(t, "did:web:owner-a.example.com")
	b := newRobot(t, "did:web:owner-b.example.com")
	robot := "did:web:robot.example.com"

	t1, err := BuildOwnershipTransfer(a, BuildOwnershipTransferOptions{RobotDID: robot, ToOwner: b.DID()})
	if err != nil {
		t.Fatal(err)
	}
	t2, err := BuildOwnershipTransfer(b, BuildOwnershipTransferOptions{
		RobotDID:       robot,
		ToOwner:        "did:web:owner-c.example.com",
		PrevTransferID: "transfer-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	keys := map[string]ed25519.PublicKey{
		a.DID(): a.PublicKeyEd25519(),
		b.DID(): b.PublicKeyEd25519(),
	}
	ok, current := VerifyCustodyChain([]map[string]any{t1, t2}, keys, VerifyCustodyChainOptions{OriginOwner: a.DID()})
	if !ok {
		t.Fatal("expected a well-formed custody chain to verify")
	}
	if current != "did:web:owner-c.example.com" {
		t.Fatalf("unexpected current owner: %v", current)
	}

	// Broken link: the second transfer's fromOwner (b) does not match the first
	// link's toOwner once we inject a mismatched origin start.
	if ok, _ := VerifyCustodyChain([]map[string]any{t2, t1}, keys, VerifyCustodyChainOptions{OriginOwner: a.DID()}); ok {
		t.Fatal("expected an out-of-order custody chain to be rejected")
	}
}

func TestKeyRotationRoundTrip(t *testing.T) {
	robot := newRobot(t, "did:web:robot.example.com")
	newKeyHolder := newRobot(t, "did:web:robot.example.com")
	newKey, err := newKeyHolder.PublicKeyMultikey()
	if err != nil {
		t.Fatal(err)
	}
	cred, err := BuildKeyRotation(robot, BuildKeyRotationOptions{
		RobotDID:        robot.DID(),
		NewKeyMultibase: newKey,
		Reason:          "scheduled rotation",
	})
	if err != nil {
		t.Fatal(err)
	}
	ok, subject := VerifyKeyRotation(cred, robot.PublicKeyEd25519())
	if !ok {
		t.Fatal("key-rotation round-trip verify failed")
	}
	if subject["newKey"] != newKey {
		t.Fatalf("unexpected newKey: %v", subject["newKey"])
	}
}

func TestKeyHistoryChain(t *testing.T) {
	k0 := newRobot(t, "did:web:robot.example.com")
	k1 := newRobot(t, "did:web:robot.example.com")
	k2 := newRobot(t, "did:web:robot.example.com")
	robot := "did:web:robot.example.com"

	mb0, _ := k0.PublicKeyMultikey()
	mb1, _ := k1.PublicKeyMultikey()
	mb2, _ := k2.PublicKeyMultikey()

	r1, err := BuildKeyRotation(k0, BuildKeyRotationOptions{RobotDID: robot, NewKeyMultibase: mb1})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := BuildKeyRotation(k1, BuildKeyRotationOptions{RobotDID: robot, NewKeyMultibase: mb2})
	if err != nil {
		t.Fatal(err)
	}

	keys := map[string]ed25519.PublicKey{
		mb0: k0.PublicKeyEd25519(),
		mb1: k1.PublicKeyEd25519(),
	}
	ok, current := VerifyKeyHistory([]map[string]any{r1, r2}, mb0, keys)
	if !ok {
		t.Fatal("expected a well-formed key history to verify")
	}
	if current != mb2 {
		t.Fatalf("unexpected current key: got %v want %v", current, mb2)
	}

	// Wrong origin breaks the first previousKey match.
	if ok, _ := VerifyKeyHistory([]map[string]any{r1, r2}, mb1, keys); ok {
		t.Fatal("expected a key history with the wrong origin key to be rejected")
	}
}

func TestDecommissionRoundTripAndAuthorityEnforcement(t *testing.T) {
	authority := newRobot(t, "did:web:authority.example.com")
	cred, err := BuildDecommission(authority, BuildDecommissionOptions{
		RobotDID:         "did:web:robot.example.com",
		Reason:           "end of service life",
		FinalDisposition: "recycled",
		ValidSeconds:     3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cred["validUntil"]; !ok {
		t.Fatal("expected validUntil to be set when ValidSeconds is positive")
	}

	// Trusted authority is in the set: accepted.
	trusted := VerifyDecommissionOptions{TrustedAuthorities: map[string]bool{authority.DID(): true}}
	if ok, _ := VerifyDecommission(cred, authority.PublicKeyEd25519(), trusted); !ok {
		t.Fatal("expected a decommission from a trusted authority to verify")
	}

	// Issuer not in the trusted set: rejected.
	untrusted := VerifyDecommissionOptions{TrustedAuthorities: map[string]bool{"did:web:other.example.com": true}}
	if ok, _ := VerifyDecommission(cred, authority.PublicKeyEd25519(), untrusted); ok {
		t.Fatal("expected a decommission from an untrusted issuer to be rejected")
	}
}
