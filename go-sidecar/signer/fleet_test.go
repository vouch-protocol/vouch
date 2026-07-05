package signer

import "testing"

func rootAndDeviceSigners(t *testing.T) (*Signer, *Signer, string, string) {
	t.Helper()
	root, err := GenerateIdentity("root.example")
	if err != nil {
		t.Fatalf("GenerateIdentity root: %v", err)
	}
	device, err := GenerateIdentity("") // did:key
	if err != nil {
		t.Fatalf("GenerateIdentity device: %v", err)
	}
	rootSigner, err := New(Config{DID: root.DID, Ed25519Seed: root.Seed, DefaultExpirySeconds: 300})
	if err != nil {
		t.Fatalf("New root: %v", err)
	}
	deviceSigner, err := New(Config{DID: device.DID, Ed25519Seed: device.Seed, DefaultExpirySeconds: 300})
	if err != nil {
		t.Fatalf("New device: %v", err)
	}
	return rootSigner, deviceSigner, root.DID, device.DID
}

func signedChain(t *testing.T, root, device *Signer, deviceDID string) (map[string]any, map[string]any) {
	t.Helper()
	grant, err := EnrollDevice(root, EnrollDeviceOptions{
		DeviceDID: deviceDID, Action: "charge", Target: "api.bank", Resource: "https://api.bank/invoices",
	})
	if err != nil {
		t.Fatalf("EnrollDevice: %v", err)
	}
	action, err := device.SignCredential(SignCredentialOptions{
		Action: "charge", Target: "api.bank", Resource: "https://api.bank/invoices/42",
		ParentCredential: grant,
	})
	if err != nil {
		t.Fatalf("SignCredential (device action): %v", err)
	}
	return grant, action
}

func TestEnrollAndVerifyChain(t *testing.T) {
	root, device, rootDID, deviceDID := rootAndDeviceSigners(t)
	grant, action := signedChain(t, root, device, deviceDID)

	result := VerifyDelegatedChain([]map[string]any{grant, action}, VerifyDelegatedChainOptions{
		TrustedRoots: map[string][]byte{rootDID: root.PublicKeyEd25519()},
	})
	if !result.OK {
		t.Fatalf("expected ok, got reason: %s", result.Reason)
	}
	if result.RootDID != rootDID {
		t.Fatalf("unexpected root did: %s", result.RootDID)
	}
	if result.Leaf.Issuer != deviceDID {
		t.Fatalf("unexpected leaf issuer: %s", result.Leaf.Issuer)
	}
	if result.Leaf.Resource() != "https://api.bank/invoices/42" {
		t.Fatalf("unexpected leaf resource: %s", result.Leaf.Resource())
	}
}

func TestUntrustedRootRejected(t *testing.T) {
	root, device, _, deviceDID := rootAndDeviceSigners(t)
	grant, action := signedChain(t, root, device, deviceDID)

	result := VerifyDelegatedChain([]map[string]any{grant, action}, VerifyDelegatedChainOptions{
		TrustedRoots: map[string][]byte{},
	})
	if result.OK {
		t.Fatal("expected untrusted root to be rejected")
	}
}

func TestWrongDeviceIssuerRejected(t *testing.T) {
	root, _, rootDID, deviceDID := rootAndDeviceSigners(t)
	grant, err := EnrollDevice(root, EnrollDeviceOptions{
		DeviceDID: deviceDID, Action: "charge", Target: "api.bank", Resource: "https://api.bank/invoices",
	})
	if err != nil {
		t.Fatalf("EnrollDevice: %v", err)
	}

	impostor, err := GenerateIdentity("")
	if err != nil {
		t.Fatalf("GenerateIdentity impostor: %v", err)
	}
	impostorSigner, err := New(Config{DID: impostor.DID, Ed25519Seed: impostor.Seed, DefaultExpirySeconds: 300})
	if err != nil {
		t.Fatalf("New impostor: %v", err)
	}
	action, err := impostorSigner.SignCredential(SignCredentialOptions{
		Action: "charge", Target: "api.bank", Resource: "https://api.bank/invoices/42",
		ParentCredential: grant,
	})
	if err != nil {
		t.Fatalf("SignCredential impostor: %v", err)
	}

	result := VerifyDelegatedChain([]map[string]any{grant, action}, VerifyDelegatedChainOptions{
		TrustedRoots: map[string][]byte{rootDID: root.PublicKeyEd25519()},
	})
	if result.OK {
		t.Fatal("expected wrong device issuer to be rejected")
	}
}

func TestTamperedActionRejected(t *testing.T) {
	root, device, rootDID, deviceDID := rootAndDeviceSigners(t)
	grant, action := signedChain(t, root, device, deviceDID)
	action["credentialSubject"].(map[string]any)["intent"].(map[string]any)["resource"] = "https://api.bank/invoices/evil"

	result := VerifyDelegatedChain([]map[string]any{grant, action}, VerifyDelegatedChainOptions{
		TrustedRoots: map[string][]byte{rootDID: root.PublicKeyEd25519()},
	})
	if result.OK {
		t.Fatal("expected tampered action to be rejected")
	}
}

func TestLeafIntentPolicy(t *testing.T) {
	root, device, rootDID, deviceDID := rootAndDeviceSigners(t)
	grant, action := signedChain(t, root, device, deviceDID)
	roots := map[string][]byte{rootDID: root.PublicKeyEd25519()}

	ok := VerifyDelegatedChain([]map[string]any{grant, action}, VerifyDelegatedChainOptions{
		TrustedRoots: roots, RequireAction: "charge",
	})
	if !ok.OK {
		t.Fatalf("expected charge action to pass policy, reason: %s", ok.Reason)
	}
	bad := VerifyDelegatedChain([]map[string]any{grant, action}, VerifyDelegatedChainOptions{
		TrustedRoots: roots, RequireAction: "refund",
	})
	if bad.OK {
		t.Fatal("expected refund policy to reject a charge action")
	}
}

func TestRevokedDeviceDIDRejected(t *testing.T) {
	root, device, rootDID, deviceDID := rootAndDeviceSigners(t)
	grant, action := signedChain(t, root, device, deviceDID)
	roots := map[string][]byte{rootDID: root.PublicKeyEd25519()}

	before := VerifyDelegatedChain([]map[string]any{grant, action}, VerifyDelegatedChainOptions{TrustedRoots: roots})
	if !before.OK {
		t.Fatalf("expected valid before revocation, reason: %s", before.Reason)
	}

	after := VerifyDelegatedChain([]map[string]any{grant, action}, VerifyDelegatedChainOptions{
		TrustedRoots: roots,
		Revoked:      func(id string) bool { return id == deviceDID },
	})
	if after.OK {
		t.Fatal("expected revoked device to be rejected")
	}
}

func TestDeviceRegistry(t *testing.T) {
	root, device, rootDID, deviceDID := rootAndDeviceSigners(t)
	grant, action := signedChain(t, root, device, deviceDID)
	roots := map[string][]byte{rootDID: root.PublicKeyEd25519()}

	registry := NewDeviceRegistry()
	registry.Enroll(deviceDID, grant)
	if len(registry.ActiveDevices()) != 1 {
		t.Fatalf("expected 1 active device, got %d", len(registry.ActiveDevices()))
	}

	ok := VerifyDelegatedChain([]map[string]any{grant, action}, VerifyDelegatedChainOptions{
		TrustedRoots: roots, Revoked: registry.IsRevoked,
	})
	if !ok.OK {
		t.Fatalf("expected ok before revoke, reason: %s", ok.Reason)
	}

	registry.Revoke(deviceDID)
	if len(registry.ActiveDevices()) != 0 {
		t.Fatal("expected 0 active devices after revoke")
	}
	after := VerifyDelegatedChain([]map[string]any{grant, action}, VerifyDelegatedChainOptions{
		TrustedRoots: roots, Revoked: registry.IsRevoked,
	})
	if after.OK {
		t.Fatal("expected rejection after revoke")
	}
}

func TestDidKeyLinkResolvesWithoutTrustMap(t *testing.T) {
	root, device, rootDID, deviceDID := rootAndDeviceSigners(t)
	grant, err := EnrollDevice(root, EnrollDeviceOptions{
		DeviceDID: deviceDID, Action: "read", Target: "t", Resource: "https://x/y",
	})
	if err != nil {
		t.Fatalf("EnrollDevice: %v", err)
	}
	action, err := device.SignCredential(SignCredentialOptions{
		Action: "read", Target: "t", Resource: "https://x/y/z", ParentCredential: grant,
	})
	if err != nil {
		t.Fatalf("SignCredential: %v", err)
	}

	// Only the root key is supplied; the device link (did:key) resolves offline.
	result := VerifyDelegatedChain([]map[string]any{grant, action}, VerifyDelegatedChainOptions{
		TrustedRoots: map[string][]byte{rootDID: root.PublicKeyEd25519()},
	})
	if !result.OK {
		t.Fatalf("expected did:key link to resolve offline, reason: %s", result.Reason)
	}
}
