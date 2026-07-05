// Robot wear and degradation attestation with capability auto-attenuation, Go.
//
// Mirrors vouch/robotics/wear.py and the other SDKs. A robot does not stay as
// capable as it left the factory. Actuators wear, joints develop backlash,
// sensors drift out of calibration, and error rates creep up. This module lets a
// robot sign its own degradation state, bound to its identity and hash-linked
// over time so the history is tamper-evident, and it derives a narrowed physical
// capability scope from that state, so a worn robot operates inside a tighter,
// verifiable envelope instead of trusting the static limit it shipped with.
//
// A wear attestation carries a normalized wear level (0 for as-new, 1 for fully
// worn) and optional detailed metrics (actuator wear, calibration drift, cycle
// count, fault rate), signed by the robot. Linking each attestation to the
// previous one by its proof forms a chain a verifier walks to see how the robot
// degraded over its life. AttenuateForWear derives a physical scope whose numeric
// caps are scaled down by the wear level, and the result is a valid attenuation
// of the original scope, so the same attenuation rule the rest of Vouch uses
// carries the derating.
//
// This is the open layer: the robot signs its wear state and derives the narrowed
// scope credential in software. Firmware-level enforcement of the narrowed
// envelope and managed predictive-maintenance modeling are out of scope for the
// open layer.
package robotics

import (
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// WearAttestationType is the wear-and-degradation attestation credential type.
const WearAttestationType = "RobotWearAttestation"

// deratedCaps are the numeric caps that scale down with wear. Zones and shift
// windows are preserved unchanged, so the derived scope stays a valid
// attenuation of the original.
var deratedCaps = []string{"maxForceN", "maxSpeedMps", "maxSpeedNearHumansMps"}

// BuildWearAttestationOptions configures BuildWearAttestation. A zero AttestedAt
// uses the issue time; a zero ValidFrom uses now; a zero ValidSeconds omits
// validUntil. Metrics and PrevProof are optional. When PrevProof is the proof
// value of the previous attestation, the new attestation links to it, forming a
// tamper-evident wear history.
type BuildWearAttestationOptions struct {
	RobotDID     string
	WearLevel    float64
	Metrics      map[string]any // nil omits the field
	PrevProof    string         // "" omits the field
	AttestedAt   time.Time
	ValidSeconds int
	ValidFrom    time.Time
}

// BuildWearAttestation builds a signed RobotWearAttestation: the robot attests
// its own degradation as a normalized WearLevel in [0, 1], optionally with
// detailed Metrics. Signed by the robot. The issuer is RobotDID.
func BuildWearAttestation(robotSigner *signer.Signer, opts BuildWearAttestationOptions) (map[string]any, error) {
	if opts.RobotDID == "" {
		return nil, errors.New("robotics: robot_did is required")
	}
	if opts.WearLevel < 0.0 || opts.WearLevel > 1.0 {
		return nil, errors.New("robotics: wear_level must be between 0.0 and 1.0")
	}

	issued := opts.ValidFrom
	if issued.IsZero() {
		issued = time.Now().UTC()
	}
	attested := opts.AttestedAt
	if attested.IsZero() {
		attested = issued
	}

	subject := map[string]any{
		"id":         opts.RobotDID,
		"wearLevel":  opts.WearLevel,
		"attestedAt": iso(attested),
	}
	if opts.Metrics != nil {
		subject["metrics"] = opts.Metrics
	}
	if opts.PrevProof != "" {
		subject["prevProof"] = opts.PrevProof
	}

	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", WearAttestationType},
		"issuer":            opts.RobotDID,
		"validFrom":         iso(issued),
		"credentialSubject": subject,
	}
	if opts.ValidSeconds > 0 {
		cred["validUntil"] = iso(issued.Add(time.Duration(opts.ValidSeconds) * time.Second))
	}
	return robotSigner.AttachProof(cred)
}

// VerifyWearAttestation verifies a RobotWearAttestation: the robot's proof, that
// the issuer is the robot, and that the wear level is in range. Returns (ok,
// credentialSubject).
func VerifyWearAttestation(cred map[string]any, pub ed25519.PublicKey) (bool, map[string]any) {
	ok, subject := verifyTyped(cred, pub, WearAttestationType)
	if !ok || subject == nil {
		return false, nil
	}
	issuer, _ := cred["issuer"].(string)
	id, _ := subject["id"].(string)
	if issuer != id {
		return false, nil
	}
	level, ok := scopeNum(subject, "wearLevel")
	if !ok || level < 0.0 || level > 1.0 {
		return false, nil
	}
	return true, subject
}

// VerifyWearChain verifies an ordered wear history: each attestation verifies
// under the robot's key, and each one after the first links to the previous by
// its proof value. Returns (ok, latestSubject).
func VerifyWearChain(attestations []map[string]any, pub ed25519.PublicKey) (bool, map[string]any) {
	if len(attestations) == 0 {
		return false, nil
	}
	prevProof := ""
	var latest map[string]any
	for _, att := range attestations {
		ok, subject := VerifyWearAttestation(att, pub)
		if !ok || subject == nil {
			return false, nil
		}
		if prevProof != "" {
			linked, _ := subject["prevProof"].(string)
			if linked != prevProof {
				return false, nil
			}
		}
		proof, _ := att["proof"].(map[string]any)
		prevProof, _ = proof["proofValue"].(string)
		latest = subject
	}
	return true, latest
}

// AttenuateForWear derives a physical scope narrowed for the given wear level:
// each numeric cap is scaled by (1 - wearLevel), and the allowed zones and shift
// windows are carried through unchanged. The result is a valid attenuation of
// scope (never broader on any dimension), so the same attenuation check the rest
// of Vouch uses accepts it. A wear level of 0 returns the caps unchanged.
func AttenuateForWear(scope map[string]any, wearLevel float64) (map[string]any, error) {
	if wearLevel < 0.0 || wearLevel > 1.0 {
		return nil, errors.New("robotics: wear_level must be between 0.0 and 1.0")
	}
	factor := 1.0 - wearLevel
	narrowed := make(map[string]any, len(scope))
	for key, value := range scope {
		if isDeratedCap(key) {
			if n, ok := scopeNum(scope, key); ok {
				narrowed[key] = n * factor
				continue
			}
		}
		narrowed[key] = value
	}
	return narrowed, nil
}

func isDeratedCap(key string) bool {
	for _, k := range deratedCaps {
		if k == key {
			return true
		}
	}
	return false
}
