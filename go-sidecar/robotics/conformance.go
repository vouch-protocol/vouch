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
	"reflect"
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

// How well-sourced a requirement's clause citation is. A profile can be a
// useful crosswalk while its citations are only as good as the sources that
// were available, and a reader is entitled to know which. Every report and
// every signed attestation carries these, so a conformance result never implies
// more authority over the regulation than it has.
//
//	CitationVerifiedPrimary      the clause text was read from the official
//	                             published source.
//	CitationUnverifiedSecondary  the mapping is believed sound, but the clause
//	                             number comes from secondary sources rather than
//	                             the standard or official journal itself. The
//	                             default, because it is the honest default.
//	CitationDescriptive          not a clause reference at all, only a
//	                             description of the topic. An assessor cannot
//	                             look it up.
const (
	CitationVerifiedPrimary     = "verified-primary"
	CitationUnverifiedSecondary = "unverified-secondary"
	CitationDescriptive         = "descriptive"
)

// CitationStatuses is every citation provenance value, in report order.
var CitationStatuses = []string{
	CitationVerifiedPrimary,
	CitationUnverifiedSecondary,
	CitationDescriptive,
}

// conformanceRequirement is one clause of a regulation mapped to a credential
// type and the subject fields that satisfy it.
type conformanceRequirement struct {
	ID         string
	Clause     string
	Title      string
	Credential string
	Fields     []string
	// Expect maps a subject path to the exact value it must hold, for
	// requirements where mere presence is not evidence: a heartbeat reporting
	// an envelope breach is not evidence of staying inside the envelope.
	Expect map[string]any
	// Citation is the provenance of the Clause reference, and CitationNote
	// anything a reader should know about it, such as a conflict between
	// sources.
	Citation     string
	CitationNote string
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
	return conformanceRequirement{
		ID:         id,
		Clause:     clause,
		Title:      title,
		Credential: credential,
		Fields:     fields,
		Citation:   CitationUnverifiedSecondary,
	}
}

// expecting returns a copy of the requirement that additionally requires an
// exact value at a subject path.
func (r conformanceRequirement) expecting(path string, want any) conformanceRequirement {
	expect := make(map[string]any, len(r.Expect)+1)
	for k, v := range r.Expect {
		expect[k] = v
	}
	expect[path] = want
	r.Expect = expect
	return r
}

// citing returns a copy of the requirement with the given citation provenance
// and note.
func (r conformanceRequirement) citing(citation, note string) conformanceRequirement {
	r.Citation = citation
	r.CitationNote = note
	return r
}

// noting returns a copy of the requirement with a citation note, keeping the
// default unverified-secondary provenance.
func (r conformanceRequirement) noting(note string) conformanceRequirement {
	return r.citing(CitationUnverifiedSecondary, note)
}

const (
	iso10218EditionNote = "ISO 10218-1/-2:2011 were superseded by the 2025 editions (in force " +
		"1 April 2025); this mapping still cites the 2011 clause numbering and has " +
		"not been migrated."

	isoPaywallNote = "Clause number taken from secondary sources; the standard is paywalled and " +
		"the text has not been read."

	ojNote = "Article number taken from a third-party reproduction of the Official " +
		"Journal text, not from EUR-Lex itself."

	ulNote = "UL 3300 (now ANSI/CAN/UL 3300:2024) is paywalled and no clause numbering " +
		"was available; this names the topic only and cannot be looked up."

	iso10218Note = isoPaywallNote + " " + iso10218EditionNote
)

// conformanceProfiles are the built-in profiles, keyed by profile id. The
// contents (ids, regime strings, versions, and every per-requirement id, clause,
// title, credential type, and field path) match the Python and TypeScript
// references exactly, so the pinned report reproduces in every language.
var conformanceProfiles = map[string]conformanceProfile{
	"iso-10218": {
		Regime:  "ISO 10218-1/-2 industrial robots",
		Version: "2011 (superseded by the 2025 editions; mapping not yet migrated)",
		Requirements: []conformanceRequirement{
			req(
				"iso10218-identification",
				"ISO 10218-1:2011, 5.2",
				"Robot identification bound to its hardware",
				"RobotIdentityCredential",
				"hardwareRoot.kind", "hardwareRoot.attestation",
			).noting(iso10218Note),
			req(
				"iso10218-software-integrity",
				"ISO 10218-1:2011, 5.3",
				"Control software and configuration integrity",
				"ModelProvenanceAttestation",
				"vla.weightsHash",
			).noting(iso10218Note),
			req(
				"iso10218-limits",
				"ISO 10218-1:2011, 5.6",
				"Limiting of speed, force, and workspace",
				"PhysicalCapabilityScope",
				"physicalScope.maxForceN", "physicalScope.maxSpeedMps", "physicalScope.allowedZones",
			).noting(iso10218Note),
			req(
				"iso10218-records",
				"ISO 10218-2:2011, 5.2",
				"Records of safety-relevant events",
				"RobotSafetyRecordCredential",
				"totalEvents", "logHead",
			).noting(iso10218Note),
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
			).noting(isoPaywallNote + " Secondary sources disagree on whether power and " +
				"force limiting is 5.5.4 or 5.5.2; confirm against the published " +
				"table of contents before relying on the number."),
			req(
				"iso15066-collaborative-workspace",
				"ISO/TS 15066:2016, 5.5.2",
				"Defined collaborative workspace",
				"PhysicalCapabilityScope",
				"physicalScope.allowedZones",
			).noting(isoPaywallNote + " Shares the unresolved 5.5.2/5.5.4 numbering " +
				"conflict with iso15066-power-force-limiting."),
			req(
				"iso15066-monitoring",
				"ISO/TS 15066:2016, 5.2",
				"Continuous monitoring of the collaborative operation",
				"RobotHeartbeatCredential",
				"motionDigest",
			).expecting("motionDigest.withinEnvelope", true).noting(isoPaywallNote),
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
			).noting(ojNote),
			req(
				"eu-mr-software-integrity",
				"Reg (EU) 2023/1230, Annex III 1.1.9",
				"Protection against corruption of safety software",
				"ModelProvenanceAttestation",
				"vla.weightsHash", "vla.safetyPolicy",
			).noting(ojNote + " The Annex III subclause for protection against corruption " +
				"has not been confirmed and may need to be re-pointed."),
			req(
				"eu-mr-safe-limits",
				"Reg (EU) 2023/1230, Annex III 1.2.1",
				"Safety and reliability of control systems and limits",
				"PhysicalCapabilityScope",
				"physicalScope.maxForceN",
			).noting(ojNote),
			req(
				"eu-mr-records",
				"Reg (EU) 2023/1230, Annex III 1.2.1",
				"Recording of safety-relevant data",
				"RobotSafetyRecordCredential",
				"totalEvents", "logHead",
			).noting(ojNote),
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
			).noting(ojNote),
			req(
				"eu-aia-transparency",
				"Reg (EU) 2024/1689, Art. 13",
				"Model and configuration transparency",
				"ModelProvenanceAttestation",
				"vla.modelName", "vla.configHash",
			).noting(ojNote),
			req(
				"eu-aia-human-oversight",
				"Reg (EU) 2024/1689, Art. 14",
				"Human oversight through enforced operating limits",
				"PhysicalCapabilityScope",
				"physicalScope.maxSpeedNearHumansMps",
			).noting(ojNote + " Art. 14 also requires a means for the overseer to " +
				"intervene or stop the system, which an operating-limit scope alone " +
				"does not evidence."),
			req(
				"eu-aia-accuracy-robustness",
				"Reg (EU) 2024/1689, Art. 15",
				"Accuracy and robustness traceable to a known build",
				"ModelProvenanceAttestation",
				"vla.weightsHash",
			).noting(ojNote),
		},
	},
	"ul-3300": {
		Regime:  "UL 3300 service, communication, and mobile robots",
		Version: "2022 (see ANSI/CAN/UL 3300:2024)",
		Requirements: []conformanceRequirement{
			req(
				"ul3300-identity",
				"UL 3300, identification",
				"Robot identity bound to its hardware",
				"RobotIdentityCredential",
				"hardwareRoot.kind", "hardwareRoot.attestation",
			).citing(CitationDescriptive, ulNote),
			req(
				"ul3300-operating-limits",
				"UL 3300, operating limits",
				"Enforced speed and zone limits",
				"PhysicalCapabilityScope",
				"physicalScope.maxSpeedMps", "physicalScope.allowedZones",
			).citing(CitationDescriptive, ulNote),
			req(
				"ul3300-perception-integrity",
				"UL 3300, sensing integrity",
				"Integrity of perception used for safe operation",
				"PerceptionProvenanceCredential",
				"frameHash",
			).citing(CitationDescriptive, ulNote),
			req(
				"ul3300-records",
				"UL 3300, incident records",
				"Records of safety-relevant incidents",
				"RobotSafetyRecordCredential",
				"totalEvents", "logHead",
			).citing(CitationDescriptive, ulNote),
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
	for path, want := range requirement.Expect {
		if !reflect.DeepEqual(pathValue(subject, path), want) {
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
// Every requirement carries the provenance of its clause citation, and the
// report totals them, so a result never reads as more authoritative about the
// regulation than its sources are.
//
// The report marshals to:
//
//	{
//	  "profileId", "regime", "version",
//	  "conforms": bool, "satisfiedCount", "totalCount",
//	  "citations": {"verified-primary", "unverified-secondary", "descriptive"},
//	  "requirements": [
//	    {"id", "clause", "title", "satisfied", "citation", "citationNote"?}
//	  ],
//	}
func CheckConformance(credentials []map[string]any, profileID string) (map[string]any, error) {
	prof, err := Profile(profileID)
	if err != nil {
		return nil, err
	}
	results := make([]any, 0, len(prof.Requirements))
	satisfied := 0
	citations := make(map[string]any, len(CitationStatuses))
	for _, status := range CitationStatuses {
		citations[status] = 0
	}
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
		citation := requirement.Citation
		if citation == "" {
			citation = CitationUnverifiedSecondary
		}
		citations[citation] = citations[citation].(int) + 1
		result := map[string]any{
			"id":        requirement.ID,
			"clause":    requirement.Clause,
			"title":     requirement.Title,
			"satisfied": ok,
			"citation":  citation,
		}
		if requirement.CitationNote != "" {
			result["citationNote"] = requirement.CitationNote
		}
		results = append(results, result)
	}
	total := len(prof.Requirements)
	return map[string]any{
		"profileId":      profileID,
		"regime":         prof.Regime,
		"version":        prof.Version,
		"conforms":       satisfied == total,
		"satisfiedCount": satisfied,
		"totalCount":     total,
		"citations":      citations,
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
		"citations":      reportCitations(opts.Report),
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

// reportCitations lifts the citation summary out of a report, tolerating a
// report produced before citations were carried.
func reportCitations(report map[string]any) any {
	if citations, ok := report["citations"]; ok {
		return citations
	}
	return map[string]any{}
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
