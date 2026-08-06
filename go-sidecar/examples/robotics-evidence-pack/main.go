// Command robotics-evidence-pack assembles a regulatory evidence pack for a
// robot from Vouch robotics credentials (Go). Mirrors
// examples/robotics_ai_act_evidence_pack.py.
//
// A robot presents signed credentials -- a hardware-rooted identity, a model
// provenance attestation, a physical capability scope, a safety record
// anchored to a tamper-evident ledger, a heartbeat carrying a motion digest,
// and perception provenance for its sensor frames -- and the conformance
// checker maps them onto all five built-in regulatory profiles (EU AI Act
// high-risk, ISO 10218, ISO/TS 15066, EU Machinery Regulation 2023/1230,
// UL 3300). An assessor then signs one point-in-time conformance attestation
// per profile that an auditor or notified body can verify offline.
//
// Run it:  go run ./examples/robotics-evidence-pack   (from go-sidecar/)
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/vouch-protocol/vouch/go-sidecar/robotics"
	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// The five built-in conformance profiles. The Go package keeps the profile
// registry private, so the ids are listed here.
var allProfileIDs = []string{
	"eu-ai-act-high-risk",
	"iso-10218",
	"iso-ts-15066",
	"eu-machinery-2023-1230",
	"ul-3300",
}

var robotConfig = map[string]any{"temperature": 0.0, "max_torque": 12.5}

type party struct {
	signer *signer.Signer
	pub    ed25519.PublicKey
	did    string
}

// makeParty generates an identity for one party and wraps it in a Signer.
func makeParty(did string) (party, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return party{}, err
	}
	s, err := signer.New(signer.Config{DID: did, Ed25519Seed: seed})
	if err != nil {
		return party{}, err
	}
	return party{signer: s, pub: s.PublicKeyEd25519(), did: did}, nil
}

// digest is the multibase (base64url) SHA-256, the hash form Vouch credentials carry.
func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "u" + base64.RawURLEncoding.EncodeToString(sum[:])
}

func f(v float64) *float64 { return &v }

// buildBaseCredentials builds the four base credentials: identity, model
// provenance, physical scope, and a safety record over a tamper-evident
// ledger. These satisfy eu-ai-act-high-risk, iso-10218, and
// eu-machinery-2023-1230, but leave gaps in iso-ts-15066 (no motion
// monitoring) and ul-3300 (no perception integrity).
func buildBaseCredentials(robot, authority party) ([]map[string]any, error) {
	rootSeed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(rootSeed); err != nil {
		return nil, err
	}
	root, err := robotics.NewSoftwareRoot(rootSeed, "TPM") // reference; use a real TPM in deployment
	if err != nil {
		return nil, err
	}
	identity, err := robotics.MintRobotIdentity(robot.signer, root, robotics.MintOptions{
		Make: "Acme Robotics", Model: "AR-7", Serial: "SN-000123",
	})
	if err != nil {
		return nil, err
	}

	provenance, err := robotics.BuildProvenanceAttestation(robot.signer, robotics.BuildProvenanceOptions{
		RobotDID:     robot.did,
		ModelName:    "Gemini Robotics ER 2",
		WeightsHash:  digest([]byte("gemini-robotics-er-2-weights")),
		SafetyPolicy: digest([]byte("factory-floor-safety-policy-v3")),
		Config:       robotConfig,
		Version:      "2.0",
	})
	if err != nil {
		return nil, err
	}

	scope, err := robotics.BuildPhysicalScopeCredential(robot.signer, robotics.BuildPhysicalScopeOptions{
		SubjectDID:            robot.did,
		MaxForceN:             f(80.0),
		MaxSpeedMps:           f(1.5),
		MaxSpeedNearHumansMps: f(0.5),
		AllowedZones:          []string{"cell-3"},
	})
	if err != nil {
		return nil, err
	}

	ledger := robotics.NewSafetyEventLog("")
	if _, err := ledger.Append("near_miss", robotics.AppendSafetyOptions{
		Severity: "low", Details: map[string]any{"note": "pallet edge proximity"},
	}); err != nil {
		return nil, err
	}
	if _, err := ledger.Append("manual_override", robotics.AppendSafetyOptions{
		Actor: "did:web:operator.example.com",
	}); err != nil {
		return nil, err
	}
	record, err := robotics.BuildSafetyRecord(authority.signer, robotics.BuildSafetyRecordOptions{
		RobotDID: robot.did, Summary: ledger.Summarize(),
	})
	if err != nil {
		return nil, err
	}

	return []map[string]any{identity, provenance, scope, record}, nil
}

// buildMonitoringCredentials builds the two credentials that close the
// remaining gaps: a heartbeat whose motion digest proves the last interval
// stayed inside the physical envelope (ISO/TS 15066 continuous monitoring),
// and perception provenance binding a captured camera frame to the robot's
// key (UL 3300 sensing integrity).
func buildMonitoringCredentials(robot party, scopeCred map[string]any) ([]map[string]any, error) {
	subject := scopeCred["credentialSubject"].(map[string]any)
	scope := subject["physicalScope"].(map[string]any)

	collector := robotics.NewMotionCollector(scope)
	if err := collector.Record(robotics.MotionRecord{
		ForceN: f(12.0), SpeedMps: f(0.4), NearHumans: true, Zone: "cell-3",
	}); err != nil {
		return nil, err
	}
	if err := collector.Record(robotics.MotionRecord{
		ForceN: f(25.0), SpeedMps: f(1.1), Zone: "cell-3",
	}); err != nil {
		return nil, err
	}
	heartbeat, err := robotics.BuildRobotHeartbeat(robot.signer, robotics.BuildHeartbeatOptions{
		SessionID:       "shift-A",
		IntervalIndex:   0,
		MotionDigest:    collector.Digest(),
		IntervalSeconds: 30,
	})
	if err != nil {
		return nil, err
	}

	frame := []byte("\x89frame-bytes-from-the-front-camera")
	plog := robotics.NewPerceptionLog("")
	if _, err := plog.Record(robotics.RecordOptions{
		SensorID: "cam-front", Modality: "camera", Frame: frame,
	}); err != nil {
		return nil, err
	}
	perception, err := robotics.BuildPerceptionAttestation(robot.signer, robotics.BuildPerceptionOptions{
		RobotDID:  robot.did,
		SensorID:  "cam-front",
		Modality:  "camera",
		FrameHash: robotics.HashFrame(frame),
		LogHead:   plog.Head(),
	})
	if err != nil {
		return nil, err
	}

	return []map[string]any{heartbeat, perception}, nil
}

// checkAllProfiles runs the conformance checker over every built-in profile.
func checkAllProfiles(credentials []map[string]any) (map[string]map[string]any, error) {
	reports := make(map[string]map[string]any, len(allProfileIDs))
	for _, pid := range allProfileIDs {
		report, err := robotics.CheckConformance(credentials, pid)
		if err != nil {
			return nil, err
		}
		reports[pid] = report
	}
	return reports, nil
}

func printSummary(reports map[string]map[string]any) {
	for _, pid := range allProfileIDs {
		report := reports[pid]
		verdict := "GAPS"
		if report["conforms"].(bool) {
			verdict = "CONFORMS"
		}
		fmt.Printf("  %-24s %-8s (%v/%v)  %v\n",
			pid, verdict, report["satisfiedCount"], report["totalCount"], report["regime"])
		for _, raw := range report["requirements"].([]any) {
			r := raw.(map[string]any)
			if !r["satisfied"].(bool) {
				fmt.Printf("    gap: %v: %v\n", r["clause"], r["title"])
			}
		}
	}
}

func main() {
	robot, err := makeParty("did:web:ar7.example.com")
	if err != nil {
		log.Fatal(err)
	}
	assessor, err := makeParty("did:web:assessor.example.com")
	if err != nil {
		log.Fatal(err)
	}

	// The base credential set leaves gaps in two of the five profiles.
	base, err := buildBaseCredentials(robot, assessor)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("base credential set (identity, provenance, scope, safety record):")
	reports, err := checkAllProfiles(base)
	if err != nil {
		log.Fatal(err)
	}
	printSummary(reports)

	// The heartbeat and perception credentials close them.
	monitoring, err := buildMonitoringCredentials(robot, base[2])
	if err != nil {
		log.Fatal(err)
	}
	credentials := append(base, monitoring...)
	fmt.Printf("\nfull evidence pack (%d credentials):\n", len(credentials))
	reports, err = checkAllProfiles(credentials)
	if err != nil {
		log.Fatal(err)
	}
	printSummary(reports)

	// One signed, offline-verifiable conformance attestation per profile.
	fmt.Printf("\nsigned attestations (%d profiles):\n", len(allProfileIDs))
	for _, pid := range allProfileIDs {
		attestation, err := robotics.BuildConformanceAttestation(assessor.signer, robotics.BuildConformanceAttestationOptions{
			RobotDID: robot.did, Report: reports[pid],
		})
		if err != nil {
			log.Fatal(err)
		}
		ok, subject := robotics.VerifyConformanceAttestation(attestation, assessor.pub)
		reportDigest, _ := subject["reportDigest"].(string)
		if len(reportDigest) > 16 {
			reportDigest = reportDigest[:16]
		}
		fmt.Printf("  %-24s verifies=%v  reportDigest=%s...\n", pid, ok, reportDigest)
	}
}
