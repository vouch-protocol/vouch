// Command robotics-vla-accountability-loop runs a VLA control loop with
// provenance on load, a pre-actuation scope gate, and a tamper-evident black
// box (Go). Mirrors examples/robotics_vla_accountability_loop.py.
//
// A robot driven by a vision-language-action model (here Gemini Robotics ER 2)
// composes three Vouch robotics primitives into one accountable control loop:
//
//  1. Provenance on load: before autonomy is enabled, the robot verifies the
//     signed ModelProvenanceAttestation for the exact weights and config it is
//     about to run.
//  2. Pre-actuation scope gate: every action the planner proposes is checked
//     against the robot's signed PhysicalCapabilityScope before actuating; an
//     over-speed or out-of-zone action is denied, not attempted.
//  3. Tamper-evident black box: every decision, allowed or denied, is appended
//     to an encrypted, hash-linked black-box log. Anyone can verify the chain;
//     only a holder of the key can read the payloads.
//
// Run it:  go run ./examples/robotics-vla-accountability-loop   (from go-sidecar/)
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"strings"

	"github.com/vouch-protocol/vouch/go-sidecar/robotics"
	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

const vlaModelName = "Gemini Robotics ER 2"

var vlaConfig = map[string]any{"planner": "er-2", "temperature": 0.0, "max_plan_steps": 8}

type plannedAction struct {
	task   string
	action robotics.PhysicalAction
}

// What the planner proposes during one task episode. The first two stay inside
// the envelope; the sprint exceeds the near-human speed cap and the loading-bay
// fetch leaves the allowed zone, so the gate must deny both.
var plannedActions = []plannedAction{
	{"pick up the cup", robotics.PhysicalAction{ForceN: f(20.0), SpeedMps: f(0.3), NearHumans: true, Zone: "cell-3"}},
	{"hand cup to operator", robotics.PhysicalAction{ForceN: f(10.0), SpeedMps: f(0.2), NearHumans: true, Zone: "cell-3"}},
	{"sprint to the dock", robotics.PhysicalAction{SpeedMps: f(2.5), NearHumans: true, Zone: "cell-3"}},
	{"fetch from loading bay", robotics.PhysicalAction{ForceN: f(15.0), SpeedMps: f(0.5), Zone: "loading-bay"}},
}

func f(v float64) *float64 { return &v }

// digest is the multibase (base64url) SHA-256, the hash form Vouch credentials carry.
func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "u" + base64.RawURLEncoding.EncodeToString(sum[:])
}

func main() {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		log.Fatal(err)
	}
	robotDID := "did:web:ar7.example.com"
	robot, err := signer.New(signer.Config{DID: robotDID, Ed25519Seed: seed})
	if err != nil {
		log.Fatal(err)
	}
	robotPub := robot.PublicKeyEd25519()

	// 1. provenance on load: no verified provenance, no autonomy.
	attestation, err := robotics.BuildProvenanceAttestation(robot, robotics.BuildProvenanceOptions{
		RobotDID:     robotDID,
		ModelName:    vlaModelName,
		WeightsHash:  digest([]byte("gemini-robotics-er-2-weights")),
		SafetyPolicy: digest([]byte("factory-floor-safety-policy-v3")),
		Config:       vlaConfig,
		Version:      "2.0",
	})
	if err != nil {
		log.Fatal(err)
	}
	ok, subject := robotics.VerifyProvenanceAttestation(attestation, robotPub, vlaConfig)
	vla, _ := subject["vla"].(map[string]any)
	fmt.Printf("provenance verifies: %v  model=%v\n", ok, vla["modelName"])
	if !ok {
		log.Fatal("refusing to enable autonomy without verified provenance")
	}

	// 2. pre-actuation scope gate, with every decision black-boxed.
	scopeCred, err := robotics.BuildPhysicalScopeCredential(robot, robotics.BuildPhysicalScopeOptions{
		SubjectDID:            robotDID,
		MaxForceN:             f(80.0),
		MaxSpeedMps:           f(1.5),
		MaxSpeedNearHumansMps: f(0.5),
		AllowedZones:          []string{"cell-3"},
	})
	if err != nil {
		log.Fatal(err)
	}
	scope := scopeCred["credentialSubject"].(map[string]any)["physicalScope"].(map[string]any)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}
	blackbox, err := robotics.NewBlackBoxLog(key, "")
	if err != nil {
		log.Fatal(err)
	}
	for _, p := range plannedActions {
		result := robotics.CheckPhysicalAction(scope, p.action)
		event := "actuation_denied"
		verdict := "DENY "
		if result.OK {
			event = "actuation_allowed"
			verdict = "ALLOW"
		}
		if _, err := blackbox.Append(event, map[string]any{
			"task":       p.task,
			"zone":       p.action.Zone,
			"speedMps":   p.action.SpeedMps,
			"nearHumans": p.action.NearHumans,
			"reasons":    result.Reasons,
		}, ""); err != nil {
			log.Fatal(err)
		}
		why := ""
		if len(result.Reasons) > 0 {
			why = "  (" + strings.Join(result.Reasons, "; ") + ")"
		}
		fmt.Printf("  [%s] %s%s\n", verdict, p.task, why)
	}

	// 3. the black box is tamper-evident without the key.
	entries := blackbox.Entries()
	chain := robotics.VerifyBlackboxChain(entries, "")
	fmt.Printf("black-box chain verifies: %v  entries=%d\n", chain.OK, len(entries))

	// Rewriting history (the denied sprint becomes "allowed") breaks the chain.
	tampered := make([]map[string]any, len(entries))
	for i, e := range entries {
		copied := make(map[string]any, len(e))
		for k, v := range e {
			copied[k] = v
		}
		tampered[i] = copied
	}
	tampered[2]["event"] = "actuation_allowed"
	detected := robotics.VerifyBlackboxChain(tampered, "")
	fmt.Printf("tampered chain detected: %v  (%s)\n", !detected.OK, detected.Reason)
}
