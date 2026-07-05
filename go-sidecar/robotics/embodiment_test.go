package robotics

import (
	"testing"
	"time"
)

// TestEmbodimentInteropVectors is the cross-language interop proof: Go verifies
// the continuity chain minted by the Python module and pinned in the shared
// interop vector, and confirms the chain is fork-free.
func TestEmbodimentInteropVectors(t *testing.T) {
	v := loadVector(t)
	agentPub := ed25519FromJWK(t, v["embodiment_agent_key"].(map[string]any))

	rawChain := v["embodiment_chain"].([]any)
	chain := make([]map[string]any, 0, len(rawChain))
	for _, link := range rawChain {
		chain = append(chain, link.(map[string]any))
	}

	// (a) the chain verifies under the single agent key, ending on body-b.
	ok, current := VerifyContinuityChain(chain, agentPub, VerifyContinuityChainOptions{})
	if !ok {
		t.Fatal("expected the Python-minted continuity chain to verify in Go")
	}
	if current != "did:web:body-b.example.com" {
		t.Fatalf("unexpected current body: %v", current)
	}

	// (b) the chain is fork-free.
	if ok, conflict := CheckNoFork(chain); !ok {
		t.Fatalf("expected the continuity chain to be fork-free, got conflict %+v", conflict)
	}
}

func TestEmbodimentRoundTrip(t *testing.T) {
	agent := newRobot(t, "did:web:agent.example.com")
	cred, err := BuildEmbodiment(agent, BuildEmbodimentOptions{
		AgentDID:         agent.DID(),
		BodyDID:          "did:web:body-a.example.com",
		BodyHardwareRoot: "uROOTA",
		ValidSeconds:     3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(cred["type"], EmbodimentType) {
		t.Fatal("missing AgentEmbodimentCredential type")
	}
	if _, ok := cred["validUntil"]; !ok {
		t.Fatal("expected validUntil to be set when ValidSeconds is positive")
	}
	ok, subject := VerifyEmbodiment(cred, agent.PublicKeyEd25519())
	if !ok {
		t.Fatal("embodiment round-trip verify failed")
	}
	if subject["body"] != "did:web:body-a.example.com" {
		t.Fatalf("unexpected body: %v", subject["body"])
	}
}

// TestEmbodimentRejectsIssuerNotAgent ensures that only the agent itself
// (issuer == subject.id) can authorize its own embodiment.
func TestEmbodimentRejectsIssuerNotAgent(t *testing.T) {
	agent := newRobot(t, "did:web:agent.example.com")
	// Sign a credential whose subject id claims a different agent than the issuer.
	cred, err := BuildEmbodiment(agent, BuildEmbodimentOptions{
		AgentDID:         agent.DID(),
		BodyDID:          "did:web:body-a.example.com",
		BodyHardwareRoot: "uROOTA",
	})
	if err != nil {
		t.Fatal(err)
	}
	subject := cred["credentialSubject"].(map[string]any)
	subject["id"] = "did:web:other-agent.example.com"
	if ok, _ := VerifyEmbodiment(cred, agent.PublicKeyEd25519()); ok {
		t.Fatal("expected an embodiment whose issuer is not the subject agent to be rejected")
	}
}

func TestContinuityChainAcceptAndBrokenLink(t *testing.T) {
	agent := newRobot(t, "did:web:agent.example.com")
	bodyA := "did:web:body-a.example.com"
	bodyB := "did:web:body-b.example.com"
	origin := "did:web:body-origin.example.com"

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e1, err := BuildEmbodiment(agent, BuildEmbodimentOptions{
		AgentDID:         agent.DID(),
		BodyDID:          bodyA,
		BodyHardwareRoot: "uROOTA",
		FromBody:         origin,
		EmbodiedAt:       base,
		ValidSeconds:     3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	e2, err := BuildEmbodiment(agent, BuildEmbodimentOptions{
		AgentDID:         agent.DID(),
		BodyDID:          bodyB,
		BodyHardwareRoot: "uROOTB",
		FromBody:         bodyA,
		EmbodiedAt:       base.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	ok, current := VerifyContinuityChain([]map[string]any{e1, e2}, agent.PublicKeyEd25519(), VerifyContinuityChainOptions{OriginBody: origin})
	if !ok {
		t.Fatal("expected a well-formed continuity chain to verify")
	}
	if current != bodyB {
		t.Fatalf("unexpected current body: %v", current)
	}

	// Broken link: reordering makes the first fromBody miss the origin.
	if ok, _ := VerifyContinuityChain([]map[string]any{e2, e1}, agent.PublicKeyEd25519(), VerifyContinuityChainOptions{OriginBody: origin}); ok {
		t.Fatal("expected an out-of-order continuity chain to be rejected")
	}
}

// TestContinuityChainRejectsSecondAgentKey ensures the whole chain must verify
// under one agent key: a link signed by a different key breaks it.
func TestContinuityChainRejectsSecondAgentKey(t *testing.T) {
	agent := newRobot(t, "did:web:agent.example.com")
	imposter := newRobot(t, "did:web:agent.example.com")
	bodyA := "did:web:body-a.example.com"
	bodyB := "did:web:body-b.example.com"

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e1, err := BuildEmbodiment(agent, BuildEmbodimentOptions{
		AgentDID:         agent.DID(),
		BodyDID:          bodyA,
		BodyHardwareRoot: "uROOTA",
		EmbodiedAt:       base,
		ValidSeconds:     3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Second link signed by a different key: not the same accountable mind.
	e2, err := BuildEmbodiment(imposter, BuildEmbodimentOptions{
		AgentDID:         imposter.DID(),
		BodyDID:          bodyB,
		BodyHardwareRoot: "uROOTB",
		FromBody:         bodyA,
		EmbodiedAt:       base.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	if ok, _ := VerifyContinuityChain([]map[string]any{e1, e2}, agent.PublicKeyEd25519(), VerifyContinuityChainOptions{}); ok {
		t.Fatal("expected a chain with a link signed by a second key to be rejected")
	}
}

func TestCheckNoForkDetectsOverlap(t *testing.T) {
	agent := newRobot(t, "did:web:agent.example.com")
	bodyA := "did:web:body-a.example.com"
	bodyB := "did:web:body-b.example.com"
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Two embodiments on different bodies with overlapping windows: a fork.
	e1, err := BuildEmbodiment(agent, BuildEmbodimentOptions{
		AgentDID:         agent.DID(),
		BodyDID:          bodyA,
		BodyHardwareRoot: "uROOTA",
		EmbodiedAt:       base,
		ValidSeconds:     7200, // active [00:00, 02:00)
	})
	if err != nil {
		t.Fatal(err)
	}
	e2, err := BuildEmbodiment(agent, BuildEmbodimentOptions{
		AgentDID:         agent.DID(),
		BodyDID:          bodyB,
		BodyHardwareRoot: "uROOTB",
		EmbodiedAt:       base.Add(time.Hour), // active [01:00, ...)
	})
	if err != nil {
		t.Fatal(err)
	}

	ok, conflict := CheckNoFork([]map[string]any{e1, e2})
	if ok {
		t.Fatal("expected overlapping windows on different bodies to be a fork")
	}
	if conflict == nil || conflict.BodyA != bodyA || conflict.BodyB != bodyB {
		t.Fatalf("unexpected conflict: %+v", conflict)
	}

	// A clean handover (first window ends exactly when the second begins) is not
	// a fork.
	e1b, err := BuildEmbodiment(agent, BuildEmbodimentOptions{
		AgentDID:         agent.DID(),
		BodyDID:          bodyA,
		BodyHardwareRoot: "uROOTA",
		EmbodiedAt:       base,
		ValidSeconds:     3600, // active [00:00, 01:00)
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := CheckNoFork([]map[string]any{e1b, e2}); !ok {
		t.Fatal("expected a clean handover not to be a fork")
	}
}
