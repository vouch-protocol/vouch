// Event-triggered intent recheck: bind seal freshness to the action.
//
// A pure-Go port of the intent-recheck logic in core/vouch-core/src/reasoning.rs
// (and vouch/intent_recheck.py). The Heartbeat Protocol proves an agent is alive
// across an interval. It does not prove the agent's intent is current at the
// moment of a sensitive action. A justification sealed early in an interval still
// passes for an action executed much later in the same interval, so a
// sophisticated actor who knows the pulse interval can time a sensitive action to
// land after a pulse boundary while reusing an intent sealed before it. This binds
// seal freshness to the action: for a sensitive consequence tier the seal must
// post-date the last pulse boundary and be within a configurable max age. The
// stable reason strings, tier policy, and pulse arithmetic match the core byte for
// byte. It reuses the justification primitives and adds no new cryptography.
package signer

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"
)

// Intent-recheck reasons (stable prefixes; carry a structured suffix).
const (
	ReasonIntentSealStale   = "intent_seal_stale"
	ReasonIntentSealExpired = "intent_seal_expired"
	ReasonIntentSealMissing = "intent_seal_missing"
)

// Consequence tiers, aligned with the PAD-017 commitment levels (0..4) and the
// trust-entropy stakes bands. Higher tiers demand a fresher seal.
const (
	TierRoutine  = 0
	TierLow      = 1
	TierMedium   = 2
	TierHigh     = 3
	TierCritical = 4
)

// PulseWindow reports where an execution time falls relative to the current pulse
// window [lastPulse, lastPulse + interval).
type PulseWindow struct {
	InWindow          bool
	InGap             bool
	SecondsIntoWindow int64
}

// PulseWindowOf classifies an action's execution time against the pulse schedule.
// lastPulse is the issue time of the most recent heartbeat; intervalSeconds is the
// heartbeat period. Both timestamps are ISO-8601 "YYYY-MM-DDTHH:MM:SSZ".
func PulseWindowOf(lastPulse string, intervalSeconds int64, execTime string) (PulseWindow, error) {
	pulse, err := isoEpoch(lastPulse)
	if err != nil {
		return PulseWindow{}, err
	}
	exec, err := isoEpoch(execTime)
	if err != nil {
		return PulseWindow{}, err
	}
	delta := exec - pulse
	return PulseWindow{
		InWindow:          delta >= 0 && delta < intervalSeconds,
		InGap:             delta >= intervalSeconds,
		SecondsIntoWindow: delta,
	}, nil
}

// FreshnessRequirement is the freshness a consequence tier imposes on a seal.
// MaxAgeSeconds == math.MaxInt64 means no age bound.
type FreshnessRequirement struct {
	RequireFreshSeal bool
	MaxAgeSeconds    int64
}

// RequirementNone imposes no freshness requirement.
var RequirementNone = FreshnessRequirement{RequireFreshSeal: false, MaxAgeSeconds: math.MaxInt64}

// DefaultRequirement is the reference intent-freshness policy: routine, low, and
// medium tiers inherit the last pulse's assurance; high and critical tiers require
// a seal made after the last pulse boundary, within a tightening max age.
// Deployments substitute their own thresholds; these match the Rust core.
func DefaultRequirement(tier int) FreshnessRequirement {
	switch {
	case tier >= TierCritical:
		return FreshnessRequirement{RequireFreshSeal: true, MaxAgeSeconds: 60}
	case tier == TierHigh:
		return FreshnessRequirement{RequireFreshSeal: true, MaxAgeSeconds: 300}
	default:
		return RequirementNone
	}
}

// SealTimestamp reads the seal timestamp from a reasoned-action credential: the
// justification's sealedAt if present, else the escrow receipt's depositedAt.
// Returns "" when no seal timestamp is present.
func SealTimestamp(credential map[string]any) string {
	jblock := justificationBlock(credential)
	if sealed := str(jblock["sealedAt"]); sealed != "" {
		return sealed
	}
	receipt, _ := jblock["escrowReceipt"].(map[string]any)
	subject, _ := receipt["credentialSubject"].(map[string]any)
	return str(subject["depositedAt"])
}

// CheckSealFreshness is the core intent-recheck rule. It returns "" when the seal
// is fresh enough for the requirement, else a stable reason string:
//
//   - intent_seal_stale:sealed_at=<t>,last_pulse=<t> when a pulse boundary elapsed
//     between sealing and execution (the timing-the-gap case).
//   - intent_seal_expired:sealed_at=<t>,max_age=<n>s when the seal is within the
//     current window but older than the tier's max age.
func CheckSealFreshness(sealedAt, execTime, lastPulse string, req FreshnessRequirement) (string, error) {
	if !req.RequireFreshSeal {
		return "", nil
	}
	sealed, err := isoEpoch(sealedAt)
	if err != nil {
		return "", err
	}
	exec, err := isoEpoch(execTime)
	if err != nil {
		return "", err
	}
	pulse, err := isoEpoch(lastPulse)
	if err != nil {
		return "", err
	}
	if sealed < pulse {
		return fmt.Sprintf("%s:sealed_at=%s,last_pulse=%s", ReasonIntentSealStale, sealedAt, lastPulse), nil
	}
	if req.MaxAgeSeconds != math.MaxInt64 && exec-sealed > req.MaxAgeSeconds {
		return fmt.Sprintf("%s:sealed_at=%s,max_age=%ds", ReasonIntentSealExpired, sealedAt, req.MaxAgeSeconds), nil
	}
	return "", nil
}

// VerifyIntentFreshness verifies intent freshness for a reasoned-action credential
// at a consequence tier. Returns "" when the tier does not require a fresh seal or
// the seal is fresh; else a stable reason string. When the tier requires a fresh
// seal but the credential carries no seal timestamp, returns
// intent_seal_missing:tier=<n>. Run it alongside CheckReasonedAction, which
// verifies the signature and the commitment.
func VerifyIntentFreshness(credential map[string]any, tier int, lastPulse string, req FreshnessRequirement) (string, error) {
	if !req.RequireFreshSeal {
		return "", nil
	}
	execTime := str(credential["validFrom"])
	if execTime == "" {
		return "", errors.New("credential has no validFrom")
	}
	sealedAt := SealTimestamp(credential)
	if sealedAt == "" {
		return fmt.Sprintf("%s:tier=%d", ReasonIntentSealMissing, tier), nil
	}
	return CheckSealFreshness(sealedAt, execTime, lastPulse, req)
}

// ResealIntent is the execution-time reseal helper: seal the intent at now and
// issue a fresh ReasonedActionCredential whose sealedAt and validFrom are both now,
// so a sensitive action carries a seal made in the current pulse window. Reuses
// BuildJustification and SignReasonedAction; no new cryptography.
func ResealIntent(key ed25519.PrivateKey, issuerDID, verificationMethod string, intent map[string]any, anchors []map[string]any, commitmentLevel *int, now, credentialID string, includeReasoning bool) (map[string]any, error) {
	justification, err := BuildJustification(intent, anchors, commitmentLevel)
	if err != nil {
		return nil, err
	}
	return SignReasonedAction(key, issuerDID, verificationMethod, intent, justification, now, credentialID, SignReasonedActionOptions{
		IncludeReasoning: includeReasoning,
		SealedAt:         now,
	})
}
