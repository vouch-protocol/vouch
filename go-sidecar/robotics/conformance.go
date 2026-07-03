// Regulatory conformance profiles for robots (Phase 5.x), Go.
//
// Mirrors vouch/robotics/conformance.py and the TypeScript SDK with
// byte-identical output. A conformance profile is a machine-checkable mapping
// from Vouch robotics credentials to the clauses of a public safety or AI
// regulation. Given the credentials a robot presents, the checker reports which
// clauses are satisfied and cites each one, and an issuer can sign a
// point-in-time conformance attestation an auditor or notified body can consume.
//
// The built-in profiles cover ISO 10218-1/-2 (industrial robots), ISO/TS 15066
// (collaborative, power and force limiting), the EU Machinery Regulation
// 2023/1230, the EU AI Act high-risk requirements, and UL 3300 (service and
// mobile robots). They are a reference crosswalk to make conformance verifiable
// in the open, not legal advice; a deployment confirms the mapping against the
// current text of each regulation.
//
// This is the open layer: declarative profiles, a deterministic checker, and a
// signed point-in-time attestation over the full report. Hosted continuous
// monitoring, maintained and certified profiles, and auditor evidence portals
// are out of scope for the open layer.
package robotics

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"strings"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// ConformanceAttestationType is the credential type for a signed point-in-time
// conformance attestation.
const ConformanceAttestationType = "RobotConformanceAttestation"

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------
//
// A requirement is satisfied when the presented credential set contains a
// credential whose `type` includes `Credential` and whose credentialSubject has
// a non-null, non-empty value at every path in `Fields` (dot-separated, rooted
// at the subject). Profiles are plain data so every language reproduces them
// identically.

// conformanceRequirement is one clause of a regulation mapped to a credential
// type and the subject fields that satisfy it.
type conformanceRequirement struct {
	ID         string
	Clause     string
	Title      string
	Credential string
	Fields     []string
}

// conformanceProfile is a named crosswalk from a regulation to the credentials
// that evidence it.
type conformanceProfile struct {
	Regime       string
	Version      string
	Requirements []conformanceRequirement
}

func req(id, clause, title, credential string, fields ...string) conformanceRequirement {
	if fields == nil {
		fields = []string{}
	}
	return conformanceRequirement{ID: id, Clause: clause, Title: title, Credential: credential, Fields: fields}
}

// conformanceProfiles are the built-in profiles, keyed by profile id. The
// contents (ids, regime strings, versions, and every per-requirement id, clause,
// title, credential type, and field path) match the Python and TypeScript
// references exactly, so the pinned report reproduces in every language.
var conformanceProfiles = map[string]conformanceProfile{
	"iso-10218": {
		Regime:  "ISO 10218-1/-2 industrial robots",
		Version: "2011",
		Requirements: []conformanceRequirement{
			req(
				"iso10218-identification",
				"ISO 10218-1:2011, 5.2",
				"Robot identification bound to its hardware",
				"RobotIdentityCredential",
				"hardwareRoot.kind",
			),
			req(
				"iso10218-software-integrity",
				"ISO 10218-1:2011, 5.3",
				"Control software and configuration integrity",
				"ModelProvenanceAttestation",
				"vla.weightsHash",
			),
			req(
				"iso10218-limits",
				"ISO 10218-1:2011, 5.6",
				"Limiting of speed, force, and workspace",
				"PhysicalCapabilityScope",
				"physicalScope.maxForceN", "physicalScope.maxSpeedMps",
			),
			req(
				"iso10218-records",
				"ISO 10218-2:2011, 5.2",
				"Records of safety-relevant events",
				"RobotSafetyRecordCredential",
				"totalEvents",
			),
		},
	},
	"iso-ts-15066": {
		Regime:  "ISO/TS 15066 collaborative robots",
		Version: "2016",
		Requirements: []conformanceRequirement{
			req(
				"iso15066-power-force-limiting",
				"ISO/TS 15066:2016, 5.5.4",
				"Power and force limiting near humans",
				"PhysicalCapabilityScope",
				"physicalScope.maxSpeedNearHumansMps", "physicalScope.maxForceN",
			),
			req(
				"iso15066-collaborative-workspace",
				"ISO/TS 15066:2016, 5.5.2",
				"Defined collaborative workspace",
				"PhysicalCapabilityScope",
				"physicalScope.allowedZones",
			),
			req(
				"iso15066-monitoring",
				"ISO/TS 15066:2016, 5.2",
				"Continuous monitoring of the collaborative operation",
				"RobotHeartbeatCredential",
				"motionDigest",
			),
		},
	},
	"eu-machinery-2023-1230": {
		Regime:  "EU Machinery Regulation 2023/1230",
		Version: "2023",
		Requirements: []conformanceRequirement{
			req(
				"eu-mr-identification",
				"Reg (EU) 2023/1230, Annex III 1.7.4",
				"Machinery identification and traceability",
				"RobotIdentityCredential",
				"make", "model", "serial",
			),
			req(
				"eu-mr-software-integrity",
				"Reg (EU) 2023/1230, Annex III 1.1.9",
				"Protection against corruption of safety software",
				"ModelProvenanceAttestation",
				"vla.weightsHash", "vla.safetyPolicy",
			),
			req(
				"eu-mr-safe-limits",
				"Reg (EU) 2023/1230, Annex III 1.2.1",
				"Safety and reliability of control systems and limits",
				"PhysicalCapabilityScope",
				"physicalScope.maxForceN",
			),
			req(
				"eu-mr-records",
				"Reg (EU) 2023/1230, Annex III 1.2.1",
				"Recording of safety-relevant data",
				"RobotSafetyRecordCredential",
				"totalEvents",
			),
		},
	},
	"eu-ai-act-high-risk": {
		Regime:  "EU AI Act high-risk systems",
		Version: "2024",
		Requirements: []conformanceRequirement{
			req(
				"eu-aia-record-keeping",
				"Reg (EU) 2024/1689, Art. 12",
				"Automatic recording of events (logging)",
				"RobotSafetyRecordCredential",
				"logHead",
			),
			req(
				"eu-aia-transparency",
				"Reg (EU) 2024/1689, Art. 13",
				"Model and configuration transparency",
				"ModelProvenanceAttestation",
				"vla.modelName", "vla.configHash",
			),
			req(
				"eu-aia-human-oversight",
				"Reg (EU) 2024/1689, Art. 14",
				"Human oversight through enforced operating limits",
				"PhysicalCapabilityScope",
				"physicalScope.maxSpeedNearHumansMps",
			),
			req(
				"eu-aia-accuracy-robustness",
				"Reg (EU) 2024/1689, Art. 15",
				"Accuracy and robustness traceable to a known build",
				"ModelProvenanceAttestation",
				"vla.weightsHash",
			),
		},
	},
	"ul-3300": {
		Regime:  "UL 3300 service, communication, and mobile robots",
		Version: "2022",
		Requirements: []conformanceRequirement{
			req(
				"ul3300-identity",
				"UL 3300, identification",
				"Robot identity bound to its hardware",
				"RobotIdentityCredential",
				"hardwareRoot.kind",
			),
			req(
				"ul3300-operating-limits",
				"UL 3300, operating limits",
				"Enforced speed and zone limits",
				"PhysicalCapabilityScope",
				"physicalScope.maxSpeedMps", "physicalScope.allowedZones",
			),
			req(
				"ul3300-perception-integrity",
				"UL 3300, sensing integrity",
				"Integrity of perception used for safe operation",
				"PerceptionProvenanceCredential",
				"frameHash",
			),
			req(
				"ul3300-records",
				"UL 3300, incident records",
				"Records of safety-relevant incidents",
				"RobotSafetyRecordCredential",
				"totalEvents",
			),
		},
	},
}

// Profile returns a built-in profile by id, or an error if it is unknown.
func Profile(profileID string) (conformanceProfile, error) {
	prof, ok := conformanceProfiles[profileID]
	if !ok {
		return conformanceProfile{}, errors.New("robotics: unknown conformance profile: " + profileID)
	}
	return prof, nil
}

// ---------------------------------------------------------------------------
// Checker
// ---------------------------------------------------------------------------

// pathValue walks the dot-separated path rooted at subject, returning the value
// or nil if any segment is missing or a non-object is traversed.
func pathValue(subject map[string]any, path string) any {
	var node any = subject
	for _, part := range strings.Split(path, ".") {
		m, ok := node.(map[string]any)
		if !ok {
			return nil
		}
		v, ok := m[part]
		if !ok {
			return nil
		}
		node = v
	}
	return node
}

// emptyValue reports whether a resolved field value counts as unsatisfied: nil,
// an empty array, or an empty object.
func emptyValue(v any) bool {
	if v == nil {
		return true
	}
	switch t := v.(type) {
	case []any:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	}
	return false
}

// credentialSatisfies reports whether one credential satisfies a requirement:
// its type array includes the requirement credential type and its subject has a
// non-null, non-empty value at every required field path.
func credentialSatisfies(credential map[string]any, requirement conformanceRequirement) bool {
	if !hasType(credential["type"], requirement.Credential) {
		return false
	}
	subject, _ := credential["credentialSubject"].(map[string]any)
	for _, path := range requirement.Fields {
		if emptyValue(pathValue(subject, path)) {
			return false
		}
	}
	return true
}

// CheckConformance checks the presented credentials against the named profile and
// returns a deterministic report. Each requirement is satisfied when some
// presented credential matches its type and has every required field. The caller
// is expected to have verified the credentials' signatures first; this checks
// structure and coverage, not proofs.
//
// The report marshals to:
//
//	{
//	  "profileId", "regime", "version",
//	  "conforms": bool, "satisfiedCount", "totalCount",
//	  "requirements": [{"id", "clause", "title", "satisfied"}],
//	}
func CheckConformance(credentials []map[string]any, profileID string) (map[string]any, error) {
	prof, err := Profile(profileID)
	if err != nil {
		return nil, err
	}
	results := make([]any, 0, len(prof.Requirements))
	satisfied := 0
	for _, requirement := range prof.Requirements {
		ok := false
		for _, c := range credentials {
			if credentialSatisfies(c, requirement) {
				ok = true
				break
			}
		}
		if ok {
			satisfied++
		}
		results = append(results, map[string]any{
			"id":        requirement.ID,
			"clause":    requirement.Clause,
			"title":     requirement.Title,
			"satisfied": ok,
		})
	}
	total := len(prof.Requirements)
	return map[string]any{
		"profileId":      profileID,
		"regime":         prof.Regime,
		"version":        prof.Version,
		"conforms":       satisfied == total,
		"satisfiedCount": satisfied,
		"totalCount":     total,
		"requirements":   results,
	}, nil
}

// ReportDigest returns the multibase SHA-256 of the JCS-canonical report, for
// binding a report into an attestation. Python, TypeScript, and Go canonicalize
// identically, so the digest is the same byte string in every language.
func ReportDigest(report map[string]any) (string, error) {
	canon, err := signer.Canonicalize(report)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return mb64(sum[:]), nil
}

// ---------------------------------------------------------------------------
// Signed conformance attestation
// ---------------------------------------------------------------------------

// BuildConformanceAttestationOptions configures BuildConformanceAttestation. A
// zero AttestedAt uses now; a zero ValidSeconds omits validUntil.
type BuildConformanceAttestationOptions struct {
	RobotDID     string
	Report       map[string]any
	ValidSeconds int
	AttestedAt   time.Time
}

// BuildConformanceAttestation builds a signed point-in-time conformance
// attestation for RobotDID over a report produced by CheckConformance. The signer
// is the robot, its owner, or an assessing authority. The report is embedded and
// bound by digest.
func BuildConformanceAttestation(s *signer.Signer, opts BuildConformanceAttestationOptions) (map[string]any, error) {
	if opts.RobotDID == "" {
		return nil, errors.New("robotics: robot_did is required")
	}
	if _, ok := opts.Report["profileId"]; !ok {
		return nil, errors.New("robotics: report must come from CheckConformance")
	}
	if _, ok := opts.Report["conforms"]; !ok {
		return nil, errors.New("robotics: report must come from CheckConformance")
	}

	issued := opts.AttestedAt
	if issued.IsZero() {
		issued = time.Now().UTC()
	}

	digest, err := ReportDigest(opts.Report)
	if err != nil {
		return nil, err
	}

	subject := map[string]any{
		"id":             opts.RobotDID,
		"profileId":      opts.Report["profileId"],
		"regime":         opts.Report["regime"],
		"conforms":       opts.Report["conforms"],
		"satisfiedCount": opts.Report["satisfiedCount"],
		"totalCount":     opts.Report["totalCount"],
		"reportDigest":   digest,
		"report":         opts.Report,
	}

	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", ConformanceAttestationType},
		"issuer":            s.DID(),
		"validFrom":         iso(issued),
		"credentialSubject": subject,
	}
	if opts.ValidSeconds > 0 {
		cred["validUntil"] = iso(issued.Add(time.Duration(opts.ValidSeconds) * time.Second))
	}
	return s.AttachProof(cred)
}

// VerifyConformanceAttestation verifies a conformance attestation: the issuer's
// proof, that the embedded report matches its bound digest, and that
// subject.conforms equals the embedded report's conforms. Returns (ok, subject).
func VerifyConformanceAttestation(cred map[string]any, pub ed25519.PublicKey) (bool, map[string]any) {
	if !hasType(cred["type"], ConformanceAttestationType) {
		return false, nil
	}
	if pub == nil {
		return false, nil
	}
	if ok, err := signer.VerifyDataIntegrityProof(cred, pub); err != nil || !ok {
		return false, nil
	}
	subject, _ := cred["credentialSubject"].(map[string]any)
	embedded, ok := subject["report"].(map[string]any)
	if !ok {
		return false, nil
	}
	digest, err := ReportDigest(embedded)
	if err != nil {
		return false, nil
	}
	if d, _ := subject["reportDigest"].(string); d != digest {
		return false, nil
	}
	if !equalValues(subject["conforms"], embedded["conforms"]) {
		return false, nil
	}
	return true, subject
}

// equalValues compares two JSON-decoded booleans, tolerating either concrete
// bool or nil.
func equalValues(a, b any) bool {
	ab, aok := a.(bool)
	bb, bok := b.(bool)
	if aok != bok {
		return false
	}
	return ab == bb
}
