// Robot accountable safety record (Phase 5.x), Go.
//
// Mirrors vouch/robotics/safety_record.py and the TypeScript SDK. Where the
// black box is an encrypted flight recorder for confidential telemetry, the
// safety ledger is its accountable, readable counterpart: an append-only,
// hash-linked, plaintext log of the safety-relevant events in a robot's life
// (incidents, near-misses, manual overrides, kill-switch triggers, envelope
// breaches, maintenance). The entries are plaintext on purpose, because their
// value is that an owner, an insurer, or a regulator can read and trust them.
// The chain is tamper-evident, so no entry can be altered or removed without
// detection.
//
// A RobotSafetyRecordCredential is an eddsa-jcs-2022 VC that summarizes a stretch
// of the ledger (counts by event type and by severity, the period covered, and
// the ledger head hash) into one portable, signed artifact that travels with the
// robot across owners and across organizations. The ledger reuses the black-box
// chain semantics (GenesisPrevHash, entryHash, VerifyBlackboxChain) so the two
// logs verify the same way.
package robotics

import (
	"crypto/ed25519"
	"sort"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// Safety-record constants.
const (
	SafetyRecordType = "RobotSafetyRecordCredential"
	SafetyLogVersion = "1.0"
)

// SafetyEventTypes is the interoperable set of safety event types a verifier and
// an insurer can rely on. Implementers MAY use additional types.
var SafetyEventTypes = map[string]bool{
	"incident":        true,
	"near_miss":       true,
	"manual_override": true,
	"kill_switch":     true,
	"envelope_breach": true,
	"maintenance":     true,
}

// SafetySeverities are the severity bands, ordered from least to most serious.
var SafetySeverities = []string{"info", "low", "medium", "high", "critical"}

// SafetyError is returned for invalid safety events and summaries.
type SafetyError struct{ Msg string }

func (e *SafetyError) Error() string { return e.Msg }

// SafetyEventLog is an append-only, plaintext, hash-linked safety event ledger.
// Each appended entry carries a sequence number, a timestamp, the event type, a
// severity, optional details, and the hash of the previous entry, so the log is
// tamper-evident. Unlike the black box, entries are not encrypted: a safety
// record is meant to be read and trusted by third parties.
//
// The zero value is not usable; build one with NewSafetyEventLog.
type SafetyEventLog struct {
	GenesisPrevHash string
	entries         []map[string]any
	head            string
}

// NewSafetyEventLog builds a SafetyEventLog. An empty genesisPrevHash uses
// GenesisPrevHash (the black-box genesis: multibase of 32 zero bytes).
func NewSafetyEventLog(genesisPrevHash string) *SafetyEventLog {
	if genesisPrevHash == "" {
		genesisPrevHash = GenesisPrevHash
	}
	return &SafetyEventLog{GenesisPrevHash: genesisPrevHash, head: genesisPrevHash}
}

// AppendSafetyOptions configures SafetyEventLog.Append. Empty optional fields
// are omitted from the entry, matching the Python reference.
type AppendSafetyOptions struct {
	Severity  string         // "" defaults to "info"
	Details   map[string]any // nil omits the field
	Actor     string         // "" omits the field
	Timestamp string         // "" uses now
}

// Append appends one safety event and returns the new entry.
func (l *SafetyEventLog) Append(eventType string, opts AppendSafetyOptions) (map[string]any, error) {
	if !SafetyEventTypes[eventType] {
		return nil, &SafetyError{"event_type must be a known safety event type, got " + eventType}
	}
	severity := opts.Severity
	if severity == "" {
		severity = "info"
	}
	if !containsStr(SafetySeverities, severity) {
		return nil, &SafetyError{"severity must be one of info/low/medium/high/critical, got " + severity}
	}

	ts := opts.Timestamp
	if ts == "" {
		ts = iso(time.Now().UTC())
	}
	body := map[string]any{
		"version":   SafetyLogVersion,
		"seq":       len(l.entries),
		"timestamp": ts,
		"eventType": eventType,
		"severity":  severity,
		"prevHash":  l.head,
	}
	if opts.Details != nil {
		body["details"] = opts.Details
	}
	if opts.Actor != "" {
		body["actor"] = opts.Actor
	}
	h, err := entryHash(body)
	if err != nil {
		return nil, err
	}
	body["entryHash"] = h
	l.entries = append(l.entries, body)
	l.head = h
	return body, nil
}

// Head returns the current chain head hash.
func (l *SafetyEventLog) Head() string { return l.head }

// Entries returns a shallow copy of the entry list.
func (l *SafetyEventLog) Entries() []map[string]any {
	out := make([]map[string]any, len(l.entries))
	for i, e := range l.entries {
		c := make(map[string]any, len(e))
		for k, v := range e {
			c[k] = v
		}
		out[i] = c
	}
	return out
}

// Summarize produces a summary object for embedding in a safety-record
// credential, anchored to the current ledger head.
func (l *SafetyEventLog) Summarize() map[string]any {
	return SummarizeEntries(l.entries, l.head)
}

// VerifySafetyLog verifies the hash chain over the ledger entries. It is
// tamper-evident. An empty genesisPrevHash uses GenesisPrevHash.
func VerifySafetyLog(entries []map[string]any, genesisPrevHash string) ChainResult {
	return VerifyBlackboxChain(entries, genesisPrevHash)
}

// SummarizeEntries summarizes ledger entries into counts by event type and by
// severity, the total event count, and (when head is non-empty) the ledger head
// hash that anchors the summary to a specific chain state.
func SummarizeEntries(entries []map[string]any, head string) map[string]any {
	eventCounts := map[string]any{}
	for _, t := range sortedEventTypes() {
		eventCounts[t] = 0
	}
	severityCounts := map[string]any{}
	for _, s := range SafetySeverities {
		severityCounts[s] = 0
	}
	for _, e := range entries {
		if et, _ := e["eventType"].(string); SafetyEventTypes[et] {
			eventCounts[et] = eventCounts[et].(int) + 1
		}
		if sv, _ := e["severity"].(string); containsStr(SafetySeverities, sv) {
			severityCounts[sv] = severityCounts[sv].(int) + 1
		}
	}
	summary := map[string]any{
		"eventCounts":    eventCounts,
		"severityCounts": severityCounts,
		"totalEvents":    len(entries),
	}
	if head != "" {
		summary["logHead"] = head
	}
	return summary
}

// ValidateSafetySummary checks the structure of a safety summary. It does not
// judge whether the values are acceptable.
func ValidateSafetySummary(summary map[string]any) error {
	if summary == nil {
		return &SafetyError{"summary must be an object"}
	}
	for _, name := range []string{"eventCounts", "severityCounts"} {
		block, ok := summary[name].(map[string]any)
		if !ok {
			return &SafetyError{"summary." + name + " must be an object"}
		}
		for k, v := range block {
			n, isInt := digestInt(v)
			if !isInt || n < 0 {
				return &SafetyError{"summary." + name + "[" + k + "] must be a non-negative integer"}
			}
		}
	}
	total, isInt := digestInt(summary["totalEvents"])
	if !isInt || total < 0 {
		return &SafetyError{"summary.totalEvents must be a non-negative integer"}
	}
	return nil
}

// BuildSafetyRecordOptions configures BuildSafetyRecord. A zero PeriodStart and
// PeriodEnd omit the period block; a zero ValidFrom uses now; a zero ValidSeconds
// omits validUntil.
type BuildSafetyRecordOptions struct {
	RobotDID     string
	Summary      map[string]any
	PeriodStart  time.Time
	PeriodEnd    time.Time
	ValidSeconds int
	ValidFrom    time.Time
}

// BuildSafetyRecord builds a signed RobotSafetyRecordCredential summarizing a
// robot's safety ledger. The issuer (an owner, an auditor, or the robot itself)
// attests the summary; Summary is produced by SafetyEventLog.Summarize or
// SummarizeEntries.
func BuildSafetyRecord(s *signer.Signer, opts BuildSafetyRecordOptions) (map[string]any, error) {
	if err := ValidateSafetySummary(opts.Summary); err != nil {
		return nil, err
	}

	issued := opts.ValidFrom
	if issued.IsZero() {
		issued = time.Now().UTC()
	}

	subject := map[string]any{"id": opts.RobotDID}
	for k, v := range opts.Summary {
		subject[k] = v
	}
	if !opts.PeriodStart.IsZero() || !opts.PeriodEnd.IsZero() {
		period := map[string]any{}
		if !opts.PeriodStart.IsZero() {
			period["start"] = iso(opts.PeriodStart)
		}
		if !opts.PeriodEnd.IsZero() {
			period["end"] = iso(opts.PeriodEnd)
		}
		subject["period"] = period
	}

	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", SafetyRecordType},
		"issuer":            s.DID(),
		"validFrom":         iso(issued),
		"credentialSubject": subject,
	}
	if opts.ValidSeconds > 0 {
		cred["validUntil"] = iso(issued.Add(time.Duration(opts.ValidSeconds) * time.Second))
	}
	return s.AttachProof(cred)
}

// VerifySafetyRecord verifies a RobotSafetyRecordCredential: the issuer's proof
// and the structural validity of the embedded summary. Returns (ok, subject).
func VerifySafetyRecord(cred map[string]any, pub ed25519.PublicKey) (bool, map[string]any) {
	if !hasType(cred["type"], SafetyRecordType) {
		return false, nil
	}
	if ok, err := signer.VerifyDataIntegrityProof(cred, pub); err != nil || !ok {
		return false, nil
	}
	subject, _ := cred["credentialSubject"].(map[string]any)
	if err := ValidateSafetySummary(subject); err != nil {
		return false, nil
	}
	return true, subject
}

// sortedEventTypes returns the safety event types in sorted order, for callers
// that need a stable iteration (the JCS canonical form sorts keys regardless).
func sortedEventTypes() []string {
	out := make([]string, 0, len(SafetyEventTypes))
	for t := range SafetyEventTypes {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
