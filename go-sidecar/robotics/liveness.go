// Robot liveness heartbeat with safety-envelope conformance (Phase 5.x), Go.
//
// Mirrors vouch/robotics/liveness.py and the TypeScript SDK. A robot's identity
// and capability credentials are otherwise valid until revoked. This file makes
// robot trust living: the robot periodically re-attests that it is alive and
// that its actual motion over the last interval stayed inside the physical
// envelope its capability credential permits. A verifier then treats the robot
// as trusted only while a fresh, conformant heartbeat exists, inverting the
// model from "trusted until revoked" to "untrusted until renewed".
//
// The per-interval motion digest is the physical analogue of the agent
// behavioral digest. It carries aggregates of what the robot actually did over
// the interval (peak force, peak speed, peak speed while a human was near, count
// of zone breaches) and asserts whether those stayed inside the declared
// envelope. A RobotHeartbeatCredential is an eddsa-jcs-2022 VC carrying the
// robot DID, a session id, the interval index, the declared interval length, and
// the motion digest, signed by the robot's own key. Trust freshness is evaluated
// by IsLive, which requires both a recent heartbeat and an in-envelope digest.
package robotics

import (
	"crypto/ed25519"
	"errors"
	"sync"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// RobotHeartbeatType is the credential type for a robot liveness heartbeat.
const RobotHeartbeatType = "RobotHeartbeatCredential"

// DefaultGraceIntervals is the number of missed intervals tolerated before
// trust is considered stale.
const DefaultGraceIntervals = 2

// MotionError is returned for motion-collector and heartbeat failures.
type MotionError struct{ Msg string }

func (e *MotionError) Error() string { return e.Msg }

// MotionCollector accumulates per-interval motion telemetry. When given the
// robot's physical scope, each recorded sample is checked against it and
// breaches are counted. When the scope is nil, the digest still reports observed
// maxima but reports withinEnvelope true with a zero breach count.
//
// The zero value is not usable; build one with NewMotionCollector.
type MotionCollector struct {
	scope        map[string]any
	mu           sync.Mutex
	samples      int
	maxForce     float64
	maxSpeed     float64
	maxSpeedNear float64
	zoneBreaches int
	breaches     int
}

// NewMotionCollector builds a MotionCollector. A nil scope disables conformance
// counting; the digest then reports withinEnvelope true with no breaches.
func NewMotionCollector(scope map[string]any) *MotionCollector {
	return &MotionCollector{scope: scope}
}

// MotionRecord is one observed motion sample. Pointer numerics distinguish "not
// specified" from a meaningful zero, matching capability.PhysicalAction.
type MotionRecord struct {
	ForceN     *float64
	SpeedMps   *float64
	NearHumans bool
	Zone       string // "" = not specified
	TimeHm     string // "HH:MM" local; "" = not specified
}

// Record records a single observed motion sample.
func (c *MotionCollector) Record(r MotionRecord) error {
	if r.ForceN != nil && *r.ForceN < 0 {
		return &MotionError{"force_n must be non-negative"}
	}
	if r.SpeedMps != nil && *r.SpeedMps < 0 {
		return &MotionError{"speed_mps must be non-negative"}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.samples++
	if r.ForceN != nil && *r.ForceN > c.maxForce {
		c.maxForce = *r.ForceN
	}
	if r.SpeedMps != nil {
		if *r.SpeedMps > c.maxSpeed {
			c.maxSpeed = *r.SpeedMps
		}
		if r.NearHumans && *r.SpeedMps > c.maxSpeedNear {
			c.maxSpeedNear = *r.SpeedMps
		}
	}

	if c.scope != nil {
		result := CheckPhysicalAction(c.scope, PhysicalAction{
			ForceN:     r.ForceN,
			SpeedMps:   r.SpeedMps,
			NearHumans: r.NearHumans,
			Zone:       r.Zone,
			TimeHm:     r.TimeHm,
		})
		if !result.OK {
			c.breaches++
			for _, reason := range result.Reasons {
				if len(reason) >= len("zone_not_allowed") && reason[:len("zone_not_allowed")] == "zone_not_allowed" {
					c.zoneBreaches++
					break
				}
			}
		}
	}
	return nil
}

// Digest returns the motionDigest object for embedding in a heartbeat
// credential. Integral fields use Go integers and the three maxima use float64,
// matching the Python types so the JCS canonical form is byte-identical.
func (c *MotionCollector) Digest() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return map[string]any{
		"samples":               c.samples,
		"maxForceN":             c.maxForce,
		"maxSpeedMps":           c.maxSpeed,
		"maxSpeedNearHumansMps": c.maxSpeedNear,
		"zoneBreaches":          c.zoneBreaches,
		"breachCount":           c.breaches,
		"withinEnvelope":        c.breaches == 0,
	}
}

// Reset clears all state. Call after submitting a heartbeat to start fresh.
func (c *MotionCollector) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.samples = 0
	c.maxForce = 0
	c.maxSpeed = 0
	c.maxSpeedNear = 0
	c.zoneBreaches = 0
	c.breaches = 0
}

// ValidateMotionDigest checks the structure of a motionDigest object. It does
// not judge whether the values are acceptable; that is policy, expressed through
// IsLive and the verifier's thresholds.
func ValidateMotionDigest(digest map[string]any) error {
	if digest == nil {
		return &MotionError{"motionDigest must be an object"}
	}
	for _, name := range []string{"samples", "zoneBreaches", "breachCount"} {
		v, ok := digest[name]
		if !ok {
			return &MotionError{"motionDigest." + name + " is required"}
		}
		n, isInt := digestInt(v)
		if !isInt || n < 0 {
			return &MotionError{"motionDigest." + name + " must be a non-negative integer"}
		}
	}
	for _, name := range []string{"maxForceN", "maxSpeedMps", "maxSpeedNearHumansMps"} {
		v, ok := digest[name]
		if !ok {
			return &MotionError{"motionDigest." + name + " is required"}
		}
		f, isNum := digestNum(v)
		if !isNum {
			return &MotionError{"motionDigest." + name + " must be a number"}
		}
		if f < 0 {
			return &MotionError{"motionDigest." + name + " must be non-negative"}
		}
	}
	if v, ok := digest["withinEnvelope"]; !ok {
		return &MotionError{"motionDigest.withinEnvelope is required"}
	} else if _, isBool := v.(bool); !isBool {
		return &MotionError{"motionDigest.withinEnvelope must be a boolean"}
	}
	return nil
}

// BuildHeartbeatOptions configures BuildRobotHeartbeat.
type BuildHeartbeatOptions struct {
	SessionID       string
	IntervalIndex   int
	MotionDigest    map[string]any
	IntervalSeconds int
	ValidFrom       time.Time // zero uses now
}

// BuildRobotHeartbeat builds a signed RobotHeartbeatCredential. The robot
// self-issues the credential with its own Vouch key. The motion digest is
// produced by a MotionCollector over the interval; IntervalSeconds is the
// declared heartbeat cadence, which a verifier uses to judge freshness.
func BuildRobotHeartbeat(robotSigner *signer.Signer, opts BuildHeartbeatOptions) (map[string]any, error) {
	if opts.IntervalIndex < 0 {
		return nil, &MotionError{"interval_index must be non-negative"}
	}
	if opts.IntervalSeconds <= 0 {
		return nil, &MotionError{"interval_seconds must be positive"}
	}
	if err := ValidateMotionDigest(opts.MotionDigest); err != nil {
		return nil, err
	}

	issued := opts.ValidFrom
	if issued.IsZero() {
		issued = time.Now().UTC()
	}
	robotDID := robotSigner.DID()
	subject := map[string]any{
		"id":              robotDID,
		"sessionId":       opts.SessionID,
		"intervalIndex":   opts.IntervalIndex,
		"intervalSeconds": opts.IntervalSeconds,
		"motionDigest":    opts.MotionDigest,
	}
	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", RobotHeartbeatType},
		"issuer":            robotDID,
		"validFrom":         iso(issued),
		"credentialSubject": subject,
	}
	return robotSigner.AttachProof(cred)
}

// VerifyRobotHeartbeat verifies a RobotHeartbeatCredential: the credential proof
// (robot key) and the structural validity of the embedded motion digest. This
// checks authenticity and shape only. Whether the robot is currently trusted is
// a separate, time-dependent question answered by IsLive. Returns (ok, subject).
func VerifyRobotHeartbeat(cred map[string]any, robotPub ed25519.PublicKey) (bool, map[string]any) {
	if !hasType(cred["type"], RobotHeartbeatType) {
		return false, nil
	}
	if ok, err := signer.VerifyDataIntegrityProof(cred, robotPub); err != nil || !ok {
		return false, nil
	}
	subject, _ := cred["credentialSubject"].(map[string]any)
	digest, _ := subject["motionDigest"].(map[string]any)
	if err := ValidateMotionDigest(digest); err != nil {
		return false, nil
	}
	return true, subject
}

// IsLiveOptions configures IsLive. A zero Now uses time.Now().UTC(). A zero
// IntervalSeconds falls back to the cadence the heartbeat itself declares. A
// zero GraceIntervals uses DefaultGraceIntervals.
type IsLiveOptions struct {
	Now             time.Time
	IntervalSeconds int
	GraceIntervals  int
}

// IsLive decides whether a robot is currently trusted, given its most recent
// heartbeat. A robot is live only if BOTH hold:
//
//  1. Freshness: the heartbeat was issued within GraceIntervals cadence periods
//     of Now. A robot that stopped sending heartbeats loses trust.
//  2. Conformance: the heartbeat's motion digest reports withinEnvelope true. A
//     robot that exceeded its physical envelope loses trust even if recent.
func IsLive(cred map[string]any, opts IsLiveOptions) (bool, error) {
	subject, _ := cred["credentialSubject"].(map[string]any)
	digest, _ := subject["motionDigest"].(map[string]any)
	if within, _ := digest["withinEnvelope"].(bool); !within {
		return false, nil
	}

	cadence := opts.IntervalSeconds
	if cadence == 0 {
		if n, ok := digestInt(subject["intervalSeconds"]); ok {
			cadence = n
		}
	}
	if cadence <= 0 {
		return false, nil
	}

	grace := opts.GraceIntervals
	if grace == 0 {
		grace = DefaultGraceIntervals
	}
	if grace < 1 {
		return false, errors.New("robotics: grace_intervals must be at least 1")
	}

	raw, _ := cred["validFrom"].(string)
	if raw == "" {
		return false, nil
	}
	issued, err := time.Parse("2006-01-02T15:04:05Z", raw)
	if err != nil {
		return false, nil
	}
	issued = issued.UTC()

	moment := opts.Now
	if moment.IsZero() {
		moment = time.Now()
	}
	moment = moment.UTC()

	cadenceDur := time.Duration(cadence) * time.Second
	deadline := issued.Add(time.Duration(cadence*grace) * time.Second)
	// A heartbeat from the future (clock skew beyond one cadence) is not trusted.
	if moment.Add(cadenceDur).Before(issued) {
		return false, nil
	}
	return !moment.After(deadline), nil
}

// digestInt reports a value as a Go int when it is an integer, coercing the
// float64 that JSON decoding produces as well as native Go integers. A float64
// with a fractional part is rejected.
func digestInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		if n == float64(int64(n)) {
			return int(n), true
		}
	}
	return 0, false
}

// digestNum reports a value as a float64 when it is numeric, rejecting booleans.
func digestNum(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}
