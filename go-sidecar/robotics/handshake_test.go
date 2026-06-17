package robotics

import (
	"encoding/json"
	"testing"
)

const (
	didA = "did:web:robot-a.example.com"
	didB = "did:web:robot-b.example.com"
)

// TestHandshakeFullFlow runs HELLO -> ACCEPT -> CONFIRM end to end and checks the
// session scope is the intersection of the two offers.
func TestHandshakeFullFlow(t *testing.T) {
	a := newRobot(t, didA)
	b := newRobot(t, didB)
	policyB := NewTrustPolicy([]string{"robot-a.example.com"}, false)

	hello, err := BuildHello(a, BuildHelloOptions{ProposedScope: []string{"lift", "carry", "scan"}, PeerDID: didB})
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := hello["nonce"].(string)
	if nonce == "" {
		t.Fatal("hello has no nonce")
	}

	accept, err := BuildAccept(b, BuildAcceptOptions{
		Hello: hello, HelloPublicKey: a.PublicKeyEd25519(), Policy: policyB,
		OfferedScope: []string{"carry", "scan", "weld"},
	})
	if err != nil {
		t.Fatalf("accept failed: %v", err)
	}

	ok, session := VerifyAccept(accept, b.PublicKeyEd25519(), VerifyAcceptOptions{ExpectedNonce: nonce})
	if !ok {
		t.Fatal("A failed to verify B's ACCEPT")
	}
	// Intersection of {lift,carry,scan} and {carry,scan,weld}, sorted.
	want := []string{"carry", "scan"}
	if len(session.Scope) != len(want) || session.Scope[0] != want[0] || session.Scope[1] != want[1] {
		t.Fatalf("bounded scope = %v, want %v", session.Scope, want)
	}
	if session.Initiator != didA || session.Responder != didB {
		t.Fatalf("session parties wrong: %s / %s", session.Initiator, session.Responder)
	}

	confirm, err := BuildConfirm(a, *session)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyConfirm(confirm, a.PublicKeyEd25519(), session.SessionID, nonce) {
		t.Fatal("B failed to verify A's CONFIRM")
	}
}

func TestUntrustedPeerRejected(t *testing.T) {
	a := newRobot(t, didA)
	b := newRobot(t, didB)
	policyB := NewTrustPolicy([]string{"someone-else.example.com"}, false)

	hello, err := BuildHello(a, BuildHelloOptions{ProposedScope: []string{"lift"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildAccept(b, BuildAcceptOptions{
		Hello: hello, HelloPublicKey: a.PublicKeyEd25519(), Policy: policyB, OfferedScope: []string{"lift"},
	}); err == nil {
		t.Fatal("expected an untrusted initiator to be rejected")
	} else if _, isHS := err.(*HandshakeError); !isHS {
		t.Fatalf("expected HandshakeError, got %T", err)
	}
}

func TestAcceptUnknownPolicy(t *testing.T) {
	a := newRobot(t, didA)
	b := newRobot(t, didB)
	open := NewTrustPolicy(nil, true)

	hello, _ := BuildHello(a, BuildHelloOptions{ProposedScope: []string{"lift"}})
	if _, err := BuildAccept(b, BuildAcceptOptions{
		Hello: hello, HelloPublicKey: a.PublicKeyEd25519(), Policy: open, OfferedScope: []string{"lift"},
	}); err != nil {
		t.Fatalf("an open policy should accept any peer: %v", err)
	}
}

func TestTamperedHelloRejected(t *testing.T) {
	a := newRobot(t, didA)
	b := newRobot(t, didB)
	policyB := NewTrustPolicy([]string{"robot-a.example.com"}, false)

	hello, _ := BuildHello(a, BuildHelloOptions{ProposedScope: []string{"lift"}})
	// Broaden the scope after signing; the signature no longer covers it.
	hello["proposedScope"] = []any{"lift", "weld", "drive"}
	if _, err := BuildAccept(b, BuildAcceptOptions{
		Hello: hello, HelloPublicKey: a.PublicKeyEd25519(), Policy: policyB, OfferedScope: []string{"lift", "weld"},
	}); err == nil {
		t.Fatal("expected a tampered HELLO to fail signature verification")
	}
}

func TestVerifyAcceptNonceMismatch(t *testing.T) {
	a := newRobot(t, didA)
	b := newRobot(t, didB)
	policyB := NewTrustPolicy([]string{"robot-a.example.com"}, false)

	hello, _ := BuildHello(a, BuildHelloOptions{ProposedScope: []string{"lift"}})
	accept, err := BuildAccept(b, BuildAcceptOptions{
		Hello: hello, HelloPublicKey: a.PublicKeyEd25519(), Policy: policyB, OfferedScope: []string{"lift"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := VerifyAccept(accept, b.PublicKeyEd25519(), VerifyAcceptOptions{ExpectedNonce: "deadbeef"}); ok {
		t.Fatal("expected a nonce mismatch to fail")
	}
}

func TestVerifyConfirmWrongSession(t *testing.T) {
	a := newRobot(t, didA)
	session := BoundedSession{SessionID: "urn:uuid:abc", Responder: didB, Nonce: "n1", Scope: []string{"lift"}}
	confirm, err := BuildConfirm(a, session)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyConfirm(confirm, a.PublicKeyEd25519(), "urn:uuid:other", "n1") {
		t.Fatal("expected a wrong session id to fail")
	}
	if VerifyConfirm(confirm, a.PublicKeyEd25519(), "urn:uuid:abc", "n2") {
		t.Fatal("expected a wrong nonce to fail")
	}
}

func TestDidWebDomain(t *testing.T) {
	cases := map[string]string{
		"did:web:example.com":             "example.com",
		"did:web:robot.example.com:agent": "robot.example.com",
		"did:key:z6Mk":                    "",
	}
	for in, want := range cases {
		got, ok := didWebDomain(in)
		if want == "" {
			if ok {
				t.Fatalf("%s: expected no domain, got %s", in, got)
			}
			continue
		}
		if !ok || got != want {
			t.Fatalf("%s: got %q (ok=%v), want %q", in, got, ok, want)
		}
	}
}

// TestHandshakeAfterJSONRoundTrip exercises the cross-language path: A's HELLO is
// serialized and decoded (as it would arrive over the wire from a Python or
// TypeScript robot) before B accepts it. The scope, decoded as []any, must still
// intersect correctly and the signature must still verify.
func TestHandshakeAfterJSONRoundTrip(t *testing.T) {
	a := newRobot(t, didA)
	b := newRobot(t, didB)
	policyB := NewTrustPolicy([]string{"robot-a.example.com"}, false)

	hello, err := BuildHello(a, BuildHelloOptions{ProposedScope: []string{"lift", "carry"}, PeerDID: didB})
	if err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(hello)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(blob, &wire); err != nil {
		t.Fatal(err)
	}

	accept, err := BuildAccept(b, BuildAcceptOptions{
		Hello: wire, HelloPublicKey: a.PublicKeyEd25519(), Policy: policyB, OfferedScope: []string{"carry", "weld"},
	})
	if err != nil {
		t.Fatalf("accept of a JSON-decoded HELLO failed: %v", err)
	}
	nonce, _ := wire["nonce"].(string)
	ok, session := VerifyAccept(accept, b.PublicKeyEd25519(), VerifyAcceptOptions{ExpectedNonce: nonce})
	if !ok {
		t.Fatal("verify of accept failed")
	}
	if len(session.Scope) != 1 || session.Scope[0] != "carry" {
		t.Fatalf("bounded scope = %v, want [carry]", session.Scope)
	}
}
