// Robot perception provenance (Phase 5.x), Go.
//
// Mirrors vouch/robotics/perception.py and the TypeScript SDK. A robot's
// cameras, lidar, radar, and microphones produce the evidence it acts on. This
// module signs the provenance of each captured frame at capture time: a record
// binding the frame's hash, the sensor that produced it, the modality, the
// capture time, and the robot's DID. The records are hash-linked into an
// append-only chain, so the sequence of what the robot perceived is
// tamper-evident, and a signed attestation anchors a frame (or a segment of
// frames, via the chain head) to the robot's key.
//
// The frames themselves are not carried here, only their hashes, so the log
// stays small and the raw sensor data can live wherever the deployment keeps
// it. A verifier with the frame recomputes its hash and checks it against the
// record. This is the open layer: the robot signs frame hashes in software,
// reusing the black-box chain semantics (GenesisPrevHash, entryHash,
// VerifyBlackboxChain) so the logs verify the same way.
package robotics

import (
	"crypto/ed25519"
	"crypto/sha256"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// Perception constants.
const (
	PerceptionType       = "PerceptionProvenanceCredential"
	PerceptionLogVersion = "1.0"
)

// PerceptionModalities is the interoperable set of sensor modalities a verifier
// can rely on. Implementers MAY use additional values.
var PerceptionModalities = map[string]bool{
	"camera":  true,
	"lidar":   true,
	"radar":   true,
	"depth":   true,
	"audio":   true,
	"thermal": true,
}

// PerceptionError is returned for invalid perception records and attestations.
type PerceptionError struct{ Msg string }

func (e *PerceptionError) Error() string { return e.Msg }

// HashFrame returns the multibase (base64url) SHA-256 of a raw sensor frame.
func HashFrame(frame []byte) string {
	sum := sha256.Sum256(frame)
	return mb64(sum[:])
}

// PerceptionLog is an append-only, hash-linked log of sensor-frame provenance
// records. Each entry carries a sequence number, a timestamp, the sensor id,
// the modality, the frame hash, and the hash of the previous entry, so the
// sequence of perceived frames is tamper-evident. The frames are not stored;
// only their hashes are.
//
// The zero value is not usable; build one with NewPerceptionLog.
type PerceptionLog struct {
	GenesisPrevHash string
	entries         []map[string]any
	head            string
}

// NewPerceptionLog builds a PerceptionLog. An empty genesisPrevHash uses
// GenesisPrevHash (the black-box genesis: multibase of 32 zero bytes).
func NewPerceptionLog(genesisPrevHash string) *PerceptionLog {
	if genesisPrevHash == "" {
		genesisPrevHash = GenesisPrevHash
	}
	return &PerceptionLog{GenesisPrevHash: genesisPrevHash, head: genesisPrevHash}
}

// RecordOptions configures PerceptionLog.Record. Provide either Frame (it is
// hashed) or a precomputed FrameHash, not both. An empty Timestamp uses now.
type RecordOptions struct {
	SensorID  string
	Modality  string
	Frame     []byte // nil uses FrameHash
	FrameHash string // ignored when Frame is non-nil
	Timestamp string // "" uses now
}

// Record appends one frame-provenance record and returns it.
func (l *PerceptionLog) Record(opts RecordOptions) (map[string]any, error) {
	if !PerceptionModalities[opts.Modality] {
		return nil, &PerceptionError{"modality must be one of audio/camera/depth/lidar/radar/thermal, got " + opts.Modality}
	}
	if opts.SensorID == "" {
		return nil, &PerceptionError{"sensorId is required"}
	}
	if opts.Frame != nil && opts.FrameHash != "" {
		return nil, &PerceptionError{"provide either frame or frameHash, not both"}
	}
	frameHash := opts.FrameHash
	if opts.Frame != nil {
		frameHash = HashFrame(opts.Frame)
	}
	if frameHash == "" {
		return nil, &PerceptionError{"frame or frameHash is required"}
	}

	ts := opts.Timestamp
	if ts == "" {
		ts = iso(time.Now().UTC())
	}
	body := map[string]any{
		"version":   PerceptionLogVersion,
		"seq":       len(l.entries),
		"timestamp": ts,
		"sensorId":  opts.SensorID,
		"modality":  opts.Modality,
		"frameHash": frameHash,
		"prevHash":  l.head,
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
func (l *PerceptionLog) Head() string { return l.head }

// Entries returns a shallow copy of the entry list.
func (l *PerceptionLog) Entries() []map[string]any {
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

// VerifyPerceptionLog verifies the hash chain over the perception log entries.
// It is tamper-evident. An empty genesisPrevHash uses GenesisPrevHash.
func VerifyPerceptionLog(entries []map[string]any, genesisPrevHash string) ChainResult {
	return VerifyBlackboxChain(entries, genesisPrevHash)
}

// BuildPerceptionOptions configures BuildPerceptionAttestation. A zero CapturedAt
// uses the issue time; a zero ValidFrom uses now; a zero ValidSeconds omits
// validUntil; an empty LogHead omits the field.
type BuildPerceptionOptions struct {
	RobotDID     string
	SensorID     string
	Modality     string
	FrameHash    string
	CapturedAt   time.Time
	LogHead      string
	ValidSeconds int
	ValidFrom    time.Time
}

// BuildPerceptionAttestation builds a signed PerceptionProvenanceCredential
// attesting that a robot's sensor captured a specific frame. When LogHead is
// supplied, the attestation also anchors the segment of frames up to that chain
// head.
func BuildPerceptionAttestation(s *signer.Signer, opts BuildPerceptionOptions) (map[string]any, error) {
	if !PerceptionModalities[opts.Modality] {
		return nil, &PerceptionError{"modality must be one of audio/camera/depth/lidar/radar/thermal, got " + opts.Modality}
	}
	if opts.FrameHash == "" {
		return nil, &PerceptionError{"frameHash is required"}
	}

	issued := opts.ValidFrom
	if issued.IsZero() {
		issued = time.Now().UTC()
	}
	captured := opts.CapturedAt
	if captured.IsZero() {
		captured = issued
	}

	subject := map[string]any{
		"id":         opts.RobotDID,
		"sensorId":   opts.SensorID,
		"modality":   opts.Modality,
		"frameHash":  opts.FrameHash,
		"capturedAt": iso(captured),
	}
	if opts.LogHead != "" {
		subject["logHead"] = opts.LogHead
	}

	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", PerceptionType},
		"issuer":            opts.RobotDID,
		"validFrom":         iso(issued),
		"credentialSubject": subject,
	}
	if opts.ValidSeconds > 0 {
		cred["validUntil"] = iso(issued.Add(time.Duration(opts.ValidSeconds) * time.Second))
	}
	return s.AttachProof(cred)
}

// VerifyPerceptionAttestation verifies a PerceptionProvenanceCredential: the
// robot's proof and, when the raw frame is supplied, that its hash reproduces
// the attested frameHash. Returns (ok, credentialSubject).
func VerifyPerceptionAttestation(cred map[string]any, pub ed25519.PublicKey, frame []byte) (bool, map[string]any) {
	if !hasType(cred["type"], PerceptionType) {
		return false, nil
	}
	if ok, err := signer.VerifyDataIntegrityProof(cred, pub); err != nil || !ok {
		return false, nil
	}
	subject, _ := cred["credentialSubject"].(map[string]any)
	if subject == nil {
		return false, nil
	}
	frameHash, _ := subject["frameHash"].(string)
	modality, _ := subject["modality"].(string)
	if frameHash == "" || !PerceptionModalities[modality] {
		return false, nil
	}
	if frame != nil && HashFrame(frame) != frameHash {
		return false, nil
	}
	return true, subject
}
