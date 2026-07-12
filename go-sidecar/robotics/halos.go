// Halos safety-evidence recorder (NVIDIA Halos integration), Go.
//
// Mirrors vouch/robotics/halos.py. NVIDIA Halos certifies that a robot's stack
// is functionally safe and secure by design. It does not, on its own, produce a
// verifiable record of what a specific robot did, or bind that record to the
// robot's identity. This file is the evidence layer that sits under a
// Halos-certified stack.
//
// A SafetyEventRecorder captures the safety-relevant event stream produced by
// the Halos Outside-In Safety Blueprint components (the Safety AI Monitor, the
// Safety Event Integrator, the Safety Decision Maker, and the sensor input
// pipeline), plus emergency stops and operator actions, into the tamper-evident,
// encrypted black-box. The robot then signs a HalosSafetyEvidenceCredential that
// seals the black-box chain head and entry count and binds them to the robot's
// identity and to the exact Halos stack elements it ran on.
//
// A verifier that holds the sealed credential and the entries confirms, without
// the black-box key, that the record is unaltered, has not been truncated or
// extended since it was sealed, is attributable to that specific robot, and
// names the certified Halos configuration it was produced on. This composes the
// existing black-box and robot-identity primitives and adds no new cryptography.
package robotics

import (
	"crypto/ed25519"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// HalosSafetyEvidenceType is the credential type for a sealed Halos record.
const HalosSafetyEvidenceType = "HalosSafetyEvidenceCredential"

// HalosEventSources is the set of safety-relevant event producers in a
// Halos-certified stack: the four Outside-In Safety Blueprint components, plus
// an emergency stop and an operator action. A recorder rejects any event from a
// source outside this set, so the record maps to a known part of the stack.
var HalosEventSources = map[string]bool{
	"SIPP":     true, // Sensor Input Processing Pipeline
	"SAIM":     true, // Safety AI Monitor
	"SEI":      true, // Safety Event Integrator
	"SDM":      true, // Safety Decision Maker (IGX Functional Safety Island)
	"estop":    true, // emergency stop
	"operator": true, // human operator action
}

// HalosError is returned for invalid Halos safety-evidence input.
type HalosError struct{ Msg string }

func (e *HalosError) Error() string { return e.Msg }

// SafetyEventRecorder records the Halos safety-event stream into the
// tamper-evident black-box. It wraps a BlackBoxLog: each recorded event is
// encrypted and hash-linked, so the stream is confidential yet tamper-evident.
// The key is 32 bytes (AES-256).
type SafetyEventRecorder struct {
	log *BlackBoxLog
}

// NewSafetyEventRecorder builds a recorder over a fresh black-box. The key is 32
// bytes (AES-256).
func NewSafetyEventRecorder(key []byte) (*SafetyEventRecorder, error) {
	log, err := NewBlackBoxLog(key, "")
	if err != nil {
		return nil, err
	}
	return &SafetyEventRecorder{log: log}, nil
}

// Record records one safety event from a named Halos stack source. An empty
// timestamp uses now. A nil detail records an empty object.
func (r *SafetyEventRecorder) Record(source, event string, detail map[string]any, timestamp string) (map[string]any, error) {
	if !HalosEventSources[source] {
		return nil, &HalosError{"unknown Halos event source: " + source}
	}
	if detail == nil {
		detail = map[string]any{}
	}
	payload := map[string]any{"source": source, "detail": detail}
	return r.log.Append(event, payload, timestamp)
}

// Head returns the current black-box chain head hash.
func (r *SafetyEventRecorder) Head() string { return r.log.Head() }

// Count returns the number of recorded entries.
func (r *SafetyEventRecorder) Count() int { return len(r.log.entries) }

// Entries returns a shallow copy of the recorded entries.
func (r *SafetyEventRecorder) Entries() []map[string]any { return r.log.Entries() }

// OpenEntry decrypts one entry with this recorder's black-box key.
func (r *SafetyEventRecorder) OpenEntry(entry map[string]any) (map[string]any, error) {
	return r.log.OpenEntry(entry)
}

// BuildSafetyEvidenceOptions configures BuildSafetyEvidence. Pass either
// Recorder, or both BlackboxHead and an EntryCount via HasEntryCount.
type BuildSafetyEvidenceOptions struct {
	HalosStack map[string]any    // required certified Halos configuration
	Window     map[string]string // required {"from": iso, "to": iso}

	Recorder      *SafetyEventRecorder // source of head and count
	BlackboxHead  string               // explicit head when Recorder is nil
	EntryCount    int                  // explicit count when Recorder is nil
	HasEntryCount bool                 // set when EntryCount is supplied explicitly

	RobotIdentity string    // optional reference to the robot's identity credential
	ValidSeconds  int       // 0 omits validUntil
	ValidFrom     time.Time // zero uses now
}

// BuildSafetyEvidence seals a robot's Halos safety-event record into a signed
// HalosSafetyEvidenceCredential. The robot signs a credential that binds the
// black-box chain head and entry count to its identity, to the Halos stack
// elements it ran on, and to the time window.
func BuildSafetyEvidence(robotSigner *signer.Signer, opts BuildSafetyEvidenceOptions) (map[string]any, error) {
	if len(opts.HalosStack) == 0 {
		return nil, &HalosError{"halos_stack is required"}
	}
	if _, ok := opts.Window["from"]; !ok {
		return nil, &HalosError{"window with 'from' and 'to' is required"}
	}
	if _, ok := opts.Window["to"]; !ok {
		return nil, &HalosError{"window with 'from' and 'to' is required"}
	}

	var head string
	var count int
	if opts.Recorder != nil {
		head = opts.Recorder.Head()
		count = opts.Recorder.Count()
	} else {
		if opts.BlackboxHead == "" || !opts.HasEntryCount {
			return nil, &HalosError{"pass a recorder, or both blackbox_head and entry_count"}
		}
		head = opts.BlackboxHead
		count = opts.EntryCount
	}
	if count < 0 {
		return nil, &HalosError{"entry_count cannot be negative"}
	}

	robotDID := robotSigner.DID()
	issued := opts.ValidFrom
	if issued.IsZero() {
		issued = time.Now().UTC()
	}

	subject := map[string]any{
		"id":           robotDID,
		"blackboxHead": head,
		"entryCount":   count,
		"halosStack":   opts.HalosStack,
		"window":       map[string]any{"from": opts.Window["from"], "to": opts.Window["to"]},
	}
	if opts.RobotIdentity != "" {
		subject["robotIdentity"] = opts.RobotIdentity
	}

	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", HalosSafetyEvidenceType},
		"issuer":            robotDID,
		"validFrom":         iso(issued),
		"credentialSubject": subject,
	}
	if opts.ValidSeconds > 0 {
		cred["validUntil"] = iso(issued.Add(time.Duration(opts.ValidSeconds) * time.Second))
	}
	return robotSigner.AttachProof(cred)
}

// VerifySafetyEvidenceOptions configures VerifySafetyEvidence. When Entries is
// non-nil, the black-box chain is checked against the sealed head and count.
type VerifySafetyEvidenceOptions struct {
	Entries []map[string]any
}

// VerifySafetyEvidence verifies a HalosSafetyEvidenceCredential. It checks the
// robot's proof and that the issuer is the robot. When Entries are supplied, it
// also checks that the black-box chain is intact, that its length matches the
// sealed entry count, and that its head matches the sealed head, so a truncated,
// extended, reordered, or tampered record is rejected. Returns (ok, subject).
func VerifySafetyEvidence(cred map[string]any, robotPub ed25519.PublicKey, opts VerifySafetyEvidenceOptions) (bool, map[string]any) {
	if !hasType(cred["type"], HalosSafetyEvidenceType) {
		return false, nil
	}
	if robotPub == nil {
		return false, nil
	}
	if ok, err := signer.VerifyDataIntegrityProof(cred, robotPub); err != nil || !ok {
		return false, nil
	}

	subject, _ := cred["credentialSubject"].(map[string]any)
	if subject == nil {
		return false, nil
	}
	issuer, _ := cred["issuer"].(string)
	if id, _ := subject["id"].(string); id != issuer {
		return false, nil
	}

	if opts.Entries != nil {
		if r := VerifyBlackboxChain(opts.Entries, ""); !r.OK {
			return false, nil
		}
		sealedCount, ok := toInt(subject["entryCount"])
		if !ok || len(opts.Entries) != sealedCount {
			return false, nil
		}
		head := GenesisPrevHash
		if len(opts.Entries) > 0 {
			head, _ = opts.Entries[len(opts.Entries)-1]["entryHash"].(string)
		}
		if sealedHead, _ := subject["blackboxHead"].(string); head != sealedHead {
			return false, nil
		}
	}

	return true, subject
}
