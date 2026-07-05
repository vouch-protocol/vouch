package robotics

import (
	"crypto/ed25519"
	"testing"
	"time"
)

// TestCustodyInteropVectors is the cross-language interop proof: Go verifies the
// custody handoff chain minted by the Python module and pinned in the shared
// interop vector, and localizes the condition change to the responsible holder.
func TestCustodyInteropVectors(t *testing.T) {
	v := loadVector(t)

	rawChain := v["custody_chain"].([]any)
	chain := make([]map[string]any, 0, len(rawChain))
	for _, link := range rawChain {
		chain = append(chain, link.(map[string]any))
	}

	keys := map[string]ed25519.PublicKey{}
	for did, jwk := range v["custody_actor_keys"].(map[string]any) {
		keys[did] = ed25519FromJWK(t, jwk.(map[string]any))
	}

	origin := v["custody_origin_actor"].(string)

	// (a) the chain verifies under the per-actor keys, ending on robot-b.
	ok, current := VerifyHandoffChain(chain, keys, VerifyHandoffChainOptions{OriginActor: origin})
	if !ok {
		t.Fatal("expected the Python-minted custody chain to verify in Go")
	}
	if current != "did:web:robot-b.example.com" {
		t.Fatalf("unexpected current holder: %v", current)
	}

	// (b) the condition change (intact -> damaged) is localized to robot-a, the
	// holder responsible during the change.
	change := LocateConditionChange(chain)
	if change == nil {
		t.Fatal("expected a condition change in the custody chain")
	}
	if change.ResponsibleHolder != "did:web:robot-a.example.com" {
		t.Fatalf("unexpected responsible holder: %v", change.ResponsibleHolder)
	}
	if change.FromCondition != "intact" || change.ToCondition != "damaged" {
		t.Fatalf("unexpected condition change: %+v", change)
	}
}

func TestCustodyRoundTrip(t *testing.T) {
	robot := newRobot(t, "did:web:robot-a.example.com")
	cred, err := BuildHandoff(robot, BuildHandoffOptions{
		TaskID:       "tote-42",
		FromActor:    "did:web:worker-jane.example.com",
		ToActor:      robot.DID(),
		Condition:    "intact",
		ValidSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(cred["type"], CustodyHandoffType) {
		t.Fatal("missing CustodyHandoffCredential type")
	}
	if _, ok := cred["validUntil"]; !ok {
		t.Fatal("expected validUntil to be set when ValidSeconds is positive")
	}
	if iss, _ := cred["issuer"].(string); iss != robot.DID() {
		t.Fatalf("expected issuer to be the receiver: %v", iss)
	}
	ok, subject := VerifyHandoff(cred, robot.PublicKeyEd25519())
	if !ok {
		t.Fatal("handoff round-trip verify failed")
	}
	if subject["toActor"] != robot.DID() {
		t.Fatalf("unexpected toActor: %v", subject["toActor"])
	}
}

// TestCustodyRejectsIssuerNotReceiver ensures that only the receiving actor
// (issuer == subject.toActor) can attest its own acceptance of custody.
func TestCustodyRejectsIssuerNotReceiver(t *testing.T) {
	robot := newRobot(t, "did:web:robot-a.example.com")
	cred, err := BuildHandoff(robot, BuildHandoffOptions{
		TaskID:    "tote-42",
		FromActor: "did:web:worker-jane.example.com",
		ToActor:   robot.DID(),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Re-point toActor away from the issuer while keeping the same signature.
	subject := cred["credentialSubject"].(map[string]any)
	subject["toActor"] = "did:web:other-robot.example.com"
	if ok, _ := VerifyHandoff(cred, robot.PublicKeyEd25519()); ok {
		t.Fatal("expected a handoff whose issuer is not the receiver to be rejected")
	}
}

func TestHandoffChainAcceptAndBrokenLink(t *testing.T) {
	robotA := newRobot(t, "did:web:robot-a.example.com")
	robotB := newRobot(t, "did:web:robot-b.example.com")
	origin := "did:web:worker-jane.example.com"

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h1, err := BuildHandoff(robotA, BuildHandoffOptions{
		TaskID:    "tote-42",
		FromActor: origin,
		ToActor:   robotA.DID(),
		Condition: "intact",
		HandoffAt: base,
	})
	if err != nil {
		t.Fatal(err)
	}
	h2, err := BuildHandoff(robotB, BuildHandoffOptions{
		TaskID:    "tote-42",
		FromActor: robotA.DID(),
		ToActor:   robotB.DID(),
		Condition: "damaged",
		HandoffAt: base.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}

	keys := map[string]ed25519.PublicKey{
		robotA.DID(): robotA.PublicKeyEd25519(),
		robotB.DID(): robotB.PublicKeyEd25519(),
	}

	ok, current := VerifyHandoffChain([]map[string]any{h1, h2}, keys, VerifyHandoffChainOptions{OriginActor: origin})
	if !ok {
		t.Fatal("expected a well-formed custody chain to verify")
	}
	if current != robotB.DID() {
		t.Fatalf("unexpected current holder: %v", current)
	}

	// Broken link: reordering makes the first fromActor miss the origin.
	if ok, _ := VerifyHandoffChain([]map[string]any{h2, h1}, keys, VerifyHandoffChainOptions{OriginActor: origin}); ok {
		t.Fatal("expected an out-of-order custody chain to be rejected")
	}
}

// TestHandoffChainRejectsMissingKey ensures a receiver whose key is absent from
// the map breaks the chain.
func TestHandoffChainRejectsMissingKey(t *testing.T) {
	robotA := newRobot(t, "did:web:robot-a.example.com")
	robotB := newRobot(t, "did:web:robot-b.example.com")
	origin := "did:web:worker-jane.example.com"

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h1, err := BuildHandoff(robotA, BuildHandoffOptions{
		TaskID:    "tote-42",
		FromActor: origin,
		ToActor:   robotA.DID(),
		HandoffAt: base,
	})
	if err != nil {
		t.Fatal(err)
	}
	h2, err := BuildHandoff(robotB, BuildHandoffOptions{
		TaskID:    "tote-42",
		FromActor: robotA.DID(),
		ToActor:   robotB.DID(),
		HandoffAt: base.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}

	// robot-b's key is missing from the map.
	keys := map[string]ed25519.PublicKey{
		robotA.DID(): robotA.PublicKeyEd25519(),
	}
	if ok, _ := VerifyHandoffChain([]map[string]any{h1, h2}, keys, VerifyHandoffChainOptions{OriginActor: origin}); ok {
		t.Fatal("expected a chain with a missing receiver key to be rejected")
	}
}

func TestHolderAt(t *testing.T) {
	robotA := newRobot(t, "did:web:robot-a.example.com")
	robotB := newRobot(t, "did:web:robot-b.example.com")

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h1, err := BuildHandoff(robotA, BuildHandoffOptions{
		TaskID:    "tote-42",
		FromActor: "did:web:worker-jane.example.com",
		ToActor:   robotA.DID(),
		HandoffAt: base,
	})
	if err != nil {
		t.Fatal(err)
	}
	h2, err := BuildHandoff(robotB, BuildHandoffOptions{
		TaskID:    "tote-42",
		FromActor: robotA.DID(),
		ToActor:   robotB.DID(),
		HandoffAt: base.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	chain := []map[string]any{h1, h2}

	// At 00:05, robot-a holds it (only the first handoff has occurred).
	if got := HolderAt(chain, "2026-01-01T00:05:00Z"); got != robotA.DID() {
		t.Fatalf("expected robot-a at 00:05, got %v", got)
	}
	// At 00:15, robot-b holds it (both handoffs have occurred).
	if got := HolderAt(chain, "2026-01-01T00:15:00Z"); got != robotB.DID() {
		t.Fatalf("expected robot-b at 00:15, got %v", got)
	}
}

// TestLocateConditionChangeNoChange confirms a chain whose condition never
// changes localizes nothing.
func TestLocateConditionChangeNoChange(t *testing.T) {
	robotA := newRobot(t, "did:web:robot-a.example.com")
	robotB := newRobot(t, "did:web:robot-b.example.com")

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h1, err := BuildHandoff(robotA, BuildHandoffOptions{
		TaskID:    "tote-42",
		FromActor: "did:web:worker-jane.example.com",
		ToActor:   robotA.DID(),
		Condition: "intact",
		HandoffAt: base,
	})
	if err != nil {
		t.Fatal(err)
	}
	h2, err := BuildHandoff(robotB, BuildHandoffOptions{
		TaskID:    "tote-42",
		FromActor: robotA.DID(),
		ToActor:   robotB.DID(),
		Condition: "intact",
		HandoffAt: base.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if change := LocateConditionChange([]map[string]any{h1, h2}); change != nil {
		t.Fatalf("expected no condition change, got %+v", change)
	}
}
