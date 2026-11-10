package signer

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The Go side of the shared delegation-chain vector. The Python reference,
// the Rust core, and the TypeScript SDK read the same file and must return the
// same verdict for every case.
func loadDelegationChainCases(t *testing.T) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "test-vectors", "delegation-chain", "vector.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v struct {
		Cases []map[string]any `json:"cases"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	if len(v.Cases) < 16 {
		t.Fatalf("expected at least 16 cases, got %d", len(v.Cases))
	}
	return v.Cases
}

func TestDelegationChainVector(t *testing.T) {
	for _, c := range loadDelegationChainCases(t) {
		name, _ := c["name"].(string)
		now, _ := c["now"].(string)
		cred, _ := c["credential"].(map[string]any)
		expected, _ := c["expected"].(string)
		t.Run(name, func(t *testing.T) {
			if got := VerifyDelegationChain(cred, now, 30, nil, nil); got != expected {
				t.Fatalf("chain verdict: got %q, want %q", got, expected)
			}
			key, err := Ed25519FromDIDKey(issuerOf(cred))
			if err != nil {
				t.Fatalf("leaf key: %v", err)
			}
			ok, _, err := VerifyCredential(cred, key, now, 30)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if ok != (expected == "") {
				t.Fatalf("full verify = %v, want %v", ok, expected == "")
			}
		})
	}
}

func TestDelegationChainPinnedRootRefusesOtherRoots(t *testing.T) {
	for _, c := range loadDelegationChainCases(t) {
		if c["name"] != "valid_two_hop" {
			continue
		}
		cred, _ := c["credential"].(map[string]any)
		got := VerifyDelegationChain(cred, c["now"].(string), 30, nil, []string{"did:key:z6MkNotTheRoot"})
		if got != "untrusted_principal" {
			t.Fatalf("got %q, want untrusted_principal", got)
		}
		return
	}
	t.Fatal("valid_two_hop case missing")
}

func TestSignerRefusesWidenedChild(t *testing.T) {
	principal := newTestSigner(t, "did:web:principal.example.com")
	worker := newTestSigner(t, "did:web:worker.example.com")
	grant, err := principal.Sign(SignOptions{Intent: map[string]any{
		"action": "charge", "target": "api.bank", "resource": "https://api.bank/invoices",
		"delegatee": worker.DID(),
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ dim, action, target, resource string }{
		{"action", "refund", "api.bank", "https://api.bank/invoices/42"},
		{"target", "charge", "api.payroll", "https://api.bank/invoices/42"},
		{"resource", "charge", "api.bank", "https://api.bank/payroll"},
	} {
		_, err := worker.Sign(SignOptions{Action: c.action, Target: c.target, Resource: c.resource, ParentCredential: grant})
		if err == nil {
			t.Fatalf("widened %s was signed", c.dim)
		}
	}
	child, err := worker.Sign(SignOptions{
		Action: "charge", Target: "api.bank", Resource: "https://api.bank/invoices/42", ParentCredential: grant,
	})
	if err != nil {
		t.Fatalf("in-scope child refused: %v", err)
	}
	roots := map[string]ed25519.PublicKey{principal.DID(): principal.PublicKeyEd25519()}
	if got := VerifyDelegationChain(child, formatISO8601(time.Now()), 30, roots, nil); got != "" {
		t.Fatalf("in-scope chain refused: %s", got)
	}
}

func TestFleetNarrowsActionAndTarget(t *testing.T) {
	root, device, rootDID, deviceDID := rootAndDeviceSigners(t)
	grant, err := EnrollDevice(root, EnrollDeviceOptions{
		DeviceDID: deviceDID, Action: "deploy", Target: "k8s.staging", Resource: "https://k8s.example/apps",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ action, target string }{{"deploy", "k8s.prod"}, {"delete", "k8s.staging"}} {
		leaf, err := device.Sign(SignOptions{Action: c.action, Target: c.target, Resource: "https://k8s.example/apps"})
		if err != nil {
			t.Fatal(err)
		}
		r := VerifyDelegatedChain([]map[string]any{grant, leaf}, VerifyDelegatedChainOptions{
			TrustedRoots: map[string][]byte{rootDID: root.PublicKeyEd25519()},
		})
		if r.OK || !strings.Contains(r.Reason, "not within the granted") {
			t.Fatalf("%s/%s: expected refusal, got ok=%v reason=%q", c.action, c.target, r.OK, r.Reason)
		}
	}
}
