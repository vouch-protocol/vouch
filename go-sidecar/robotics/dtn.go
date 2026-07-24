// Disconnected-edge / DTN trust primitives (PAD-106 to PAD-124), Go.
//
// Mirrors vouch/robotics (Python), core/vouch-core/src/robotics_dtn.rs (Rust), and
// packages/sdk-ts/src/robotics/dtn.ts (TypeScript) with byte-identical credential
// shapes, so a disconnected-edge credential signed in any language verifies in every
// other. Covers all 19 PADs: bounded-staleness revocation, presenter freshness +
// graded decay, channel-geometry presence, ephemeris-scoped authority, two-body
// kinematic plausibility, distributed proof-of-location, beam presence, dead-man
// revocation, a dynamic sparse-Merkle revocation accumulator, swarm quarantine,
// quorum-of-orbits trust distribution, offline key continuity, time-quality,
// connectivity-scaled autonomy, integrity-risk, perception consensus, mesh standing,
// and DTN bundle custody.
//
// Open layer only: signed formats and deterministic verifier predicates. Hardware
// acquisition (ranging, TPM, orbital state) is the caller's concern.
package robotics

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// jsonKey returns a stable string key for a JSON-able value (Go marshals map keys
// sorted), used to group corroborations by (scope, change).
func jsonKey(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// Credential types.
const (
	FreshnessTokenType        = "FreshnessToken"
	PresenceAttestationType   = "ChannelGeometryPresenceAttestation"
	GeoscopedGrantType        = "EphemerisScopedGrantCredential"
	RangeObservationType      = "RangeObservationCredential"
	ProofOfLocationType       = "ProofOfLocationCredential"
	BeamPresenceType          = "BeamPresenceAttestation"
	ConditionalRevocationType = "ConditionalRevocationCredential"
	RevocationAccumulatorType = "RevocationAccumulatorRoot"
	DistressType              = "DistressAttestation"
	TrustStateUpdateType      = "TrustStateUpdate"
	KeyContinuityPredelType   = "KeyContinuityPredelegation"
	ContinuityApprovalType    = "ContinuityApproval"
	TimeQualityType           = "TimeQualityAttestation"
	AutonomyScheduleType      = "AutonomyDecaySchedule"
	IntegrityRiskType         = "IntegrityRiskAttestation"
	PerceptionClaimType       = "SharedPerceptionClaim"
	InteractionAttestType     = "InteractionAttestation"
	BundleCredentialType      = "BundleTrustCredential"
	CustodyTransferType       = "BundleCustodyTransfer"
)

// Consequence tiers.
const (
	ConsequenceRoutine   = "routine"
	ConsequenceSensitive = "sensitive"
	ConsequenceCritical  = "critical"
)

// Physical constants.
const (
	SpeedOfLightMps = 299792458.0
	MuEarth         = 3.986004418e14
)

// Integrity levels.
const (
	IntegrityFull     = "full"
	IntegrityNarrowed = "narrowed"
	IntegritySuspect  = "suspect"
)

func tierOrCritical(t string) string {
	switch t {
	case ConsequenceRoutine, ConsequenceSensitive, ConsequenceCritical:
		return t
	default:
		return ConsequenceCritical
	}
}

func signSubject(s *signer.Signer, credType string, subject map[string]any) (map[string]any, error) {
	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", credType},
		"issuer":            s.DID(),
		"credentialSubject": subject,
	}
	return s.AttachProof(cred)
}

func verifyTypedDTN(cred map[string]any, pub ed25519.PublicKey, credType string) map[string]any {
	if !hasType(cred["type"], credType) {
		return nil
	}
	if ok, err := signer.VerifyDataIntegrityProof(cred, pub); err != nil || !ok {
		return nil
	}
	subject, _ := cred["credentialSubject"].(map[string]any)
	return subject
}

func asFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}

func asInt(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int:
		return int64(n), true
	case int64:
		return n, true
	default:
		return 0, false
	}
}

func asVec3(v any) ([3]float64, bool) {
	arr, ok := v.([]any)
	if !ok || len(arr) != 3 {
		return [3]float64{}, false
	}
	var out [3]float64
	for i := 0; i < 3; i++ {
		f, ok := asFloat(arr[i])
		if !ok {
			return [3]float64{}, false
		}
		out[i] = f
	}
	return out, true
}

func vec3Slice(v [3]float64) []any { return []any{v[0], v[1], v[2]} }

// ---- PAD-106: bounded-staleness revocation --------------------------------

// DefaultStalenessBudgetSeconds returns the default max snapshot age per tier.
func DefaultStalenessBudgetSeconds(tier string) int64 {
	switch tierOrCritical(tier) {
	case ConsequenceRoutine:
		return 30 * 24 * 60 * 60
	case ConsequenceSensitive:
		return 24 * 60 * 60
	default:
		return 60 * 60
	}
}

// FreshnessVerdict is the outcome of EvaluateFreshness.
type FreshnessVerdict struct {
	Allow           bool
	Tier            string
	Reason          string
	StalenessSecond int64
	HasStaleness    bool
	BudgetSeconds   int64
}

func snapshotAsOf(snapshot map[string]any, nowEpoch int64) (int64, bool) {
	vf, ok := snapshot["validFrom"].(string)
	if !ok {
		return 0, false
	}
	t, err := parseISO(vf)
	if err != nil {
		return 0, false
	}
	if vu, ok := snapshot["validUntil"].(string); ok {
		vt, err := parseISO(vu)
		if err != nil || nowEpoch > vt.Unix() {
			return 0, false
		}
	}
	return t.Unix(), true
}

// EvaluateFreshness decides whether a locally-held revocation snapshot is fresh
// enough for the given consequence tier, at now. Fails closed on ambiguity.
// A nil snapshot means the verifier holds no revocation view. budgetOverride is
// used when non-nil.
func EvaluateFreshness(tier string, snapshot map[string]any, now time.Time, budgetOverride *int64) FreshnessVerdict {
	t := tierOrCritical(tier)
	budget := DefaultStalenessBudgetSeconds(t)
	if budgetOverride != nil {
		budget = *budgetOverride
	}
	nowEpoch := now.UTC().Unix()
	var asOf int64
	var ok bool
	if snapshot != nil {
		asOf, ok = snapshotAsOf(snapshot, nowEpoch)
	}
	if !ok {
		if t == ConsequenceRoutine {
			return FreshnessVerdict{Allow: true, Tier: t, Reason: "no usable revocation snapshot; routine tier tolerates it", BudgetSeconds: budget}
		}
		return FreshnessVerdict{Allow: false, Tier: t, Reason: "no usable revocation snapshot; " + t + " tier fails closed", BudgetSeconds: budget}
	}
	staleness := nowEpoch - asOf
	allow := staleness <= budget
	return FreshnessVerdict{Allow: allow, Tier: t, Reason: "snapshot age evaluated", StalenessSecond: staleness, HasStaleness: true, BudgetSeconds: budget}
}

// ---- PAD-107 / 119: freshness token + graded decay ------------------------

// DefaultMaxEpochGap returns the default acceptable epoch gap per tier.
func DefaultMaxEpochGap(tier string) int64 {
	switch tierOrCritical(tier) {
	case ConsequenceRoutine:
		return 100
	case ConsequenceSensitive:
		return 10
	default:
		return 1
	}
}

// BuildFreshnessToken issues subjectDID a token proving recent contact at epoch.
func BuildFreshnessToken(s *signer.Signer, subjectDID string, epoch int64, nonce string) (map[string]any, error) {
	if epoch < 0 {
		return nil, errors.New("robotics: epoch must be non-negative")
	}
	return signSubject(s, FreshnessTokenType, map[string]any{"id": subjectDID, "epoch": epoch, "nonce": nonce})
}

// VerifyFreshnessTokenOptions configures VerifyFreshnessToken.
type VerifyFreshnessTokenOptions struct {
	VerifierEpoch   int64
	Tier            string
	MaxEpochGap     *int64
	ExpectedSubject string
	SeenEpoch       *int64
}

// VerifyFreshnessToken verifies a FreshnessToken and its consequence-scaled epoch gap.
func VerifyFreshnessToken(token map[string]any, relayPub ed25519.PublicKey, opts VerifyFreshnessTokenOptions) map[string]any {
	subject := verifyTypedDTN(token, relayPub, FreshnessTokenType)
	if subject == nil {
		return nil
	}
	if opts.ExpectedSubject != "" {
		if id, _ := subject["id"].(string); id != opts.ExpectedSubject {
			return nil
		}
	}
	tokenEpoch, ok := asInt(subject["epoch"])
	if !ok {
		return nil
	}
	if opts.SeenEpoch != nil && tokenEpoch < *opts.SeenEpoch {
		return nil
	}
	budget := DefaultMaxEpochGap(opts.Tier)
	if opts.MaxEpochGap != nil {
		budget = *opts.MaxEpochGap
	}
	gap := opts.VerifierEpoch - tokenEpoch
	if gap < 0 || gap > budget {
		return nil
	}
	return subject
}

// DecayWeight returns a continuously-decaying trust weight in [0,1].
func DecayWeight(elapsedEpochs int64, halfLifeEpochs float64, form string) (float64, error) {
	if elapsedEpochs < 0 {
		return 0, errors.New("robotics: elapsedEpochs must be non-negative")
	}
	if halfLifeEpochs <= 0 {
		return 0, errors.New("robotics: halfLifeEpochs must be positive")
	}
	e := float64(elapsedEpochs)
	switch form {
	case "exponential":
		return math.Pow(0.5, e/halfLifeEpochs), nil
	case "linear":
		return math.Max(0, 1-e/(2*halfLifeEpochs)), nil
	default:
		return 0, errors.New("robotics: unknown decay form")
	}
}

// DefaultWeightThreshold returns the default minimum trust weight per tier.
func DefaultWeightThreshold(tier string) float64 {
	switch tierOrCritical(tier) {
	case ConsequenceRoutine:
		return 0.1
	case ConsequenceSensitive:
		return 0.5
	default:
		return 0.9
	}
}

// DecayPermits admits an action only if the decayed weight meets the tier threshold.
func DecayPermits(elapsedEpochs int64, halfLifeEpochs float64, tier, form string, thresholdOverride *float64) (bool, error) {
	w, err := DecayWeight(elapsedEpochs, halfLifeEpochs, form)
	if err != nil {
		return false, err
	}
	need := DefaultWeightThreshold(tier)
	if thresholdOverride != nil {
		need = *thresholdOverride
	}
	return w >= need, nil
}

// ---- PAD-108: channel-geometry presence -----------------------------------

// ExpectedRangeM returns the Euclidean distance between two positions.
func ExpectedRangeM(a, b [3]float64) float64 {
	return math.Sqrt((a[0]-b[0])*(a[0]-b[0]) + (a[1]-b[1])*(a[1]-b[1]) + (a[2]-b[2])*(a[2]-b[2]))
}

// RadialVelocityMps returns the peer's velocity along the line of sight.
func RadialVelocityMps(verifier, peer, peerVel [3]float64) float64 {
	los := [3]float64{peer[0] - verifier[0], peer[1] - verifier[1], peer[2] - verifier[2]}
	dist := math.Sqrt(los[0]*los[0] + los[1]*los[1] + los[2]*los[2])
	if dist == 0 {
		return 0
	}
	return (los[0]*peerVel[0] + los[1]*peerVel[1] + los[2]*peerVel[2]) / dist
}

// ExpectedDopplerHz returns the predicted Doppler shift (Hz); negative when receding.
func ExpectedDopplerHz(verifier, peer, peerVel [3]float64, carrierHz, propagationMps float64) float64 {
	return -(RadialVelocityMps(verifier, peer, peerVel) / propagationMps) * carrierHz
}

// CheckPresence reports whether a measured range agrees with the claimed position.
func CheckPresence(verifierPosition, claimedPeerPosition [3]float64, measuredRangeM, toleranceM float64) bool {
	return math.Abs(measuredRangeM-ExpectedRangeM(verifierPosition, claimedPeerPosition)) <= toleranceM
}

// BuildPresenceOptions configures BuildPresenceAttestation.
type BuildPresenceOptions struct {
	PeerDID         string
	Nonce           string
	ClaimedPosition [3]float64
	MeasuredRangeM  float64
	ToleranceM      float64
	ClaimedVelocity *[3]float64
}

// BuildPresenceAttestation builds a signed channel-geometry presence attestation.
func BuildPresenceAttestation(s *signer.Signer, opts BuildPresenceOptions) (map[string]any, error) {
	geometry := map[string]any{
		"claimedPosition": vec3Slice(opts.ClaimedPosition),
		"measuredRangeM":  opts.MeasuredRangeM,
		"toleranceM":      opts.ToleranceM,
	}
	if opts.ClaimedVelocity != nil {
		geometry["claimedVelocity"] = vec3Slice(*opts.ClaimedVelocity)
	}
	return signSubject(s, PresenceAttestationType, map[string]any{"id": opts.PeerDID, "nonce": opts.Nonce, "geometry": geometry})
}

// VerifyPresenceAttestation verifies the proof, optional nonce, and geometry.
func VerifyPresenceAttestation(att map[string]any, pub ed25519.PublicKey, verifierPosition [3]float64, expectedNonce string) map[string]any {
	subject := verifyTypedDTN(att, pub, PresenceAttestationType)
	if subject == nil {
		return nil
	}
	if expectedNonce != "" {
		if n, _ := subject["nonce"].(string); n != expectedNonce {
			return nil
		}
	}
	geometry, ok := subject["geometry"].(map[string]any)
	if !ok {
		return nil
	}
	claimed, ok := asVec3(geometry["claimedPosition"])
	if !ok {
		return nil
	}
	measured, ok := asFloat(geometry["measuredRangeM"])
	if !ok {
		return nil
	}
	tolerance, ok := asFloat(geometry["toleranceM"])
	if !ok {
		return nil
	}
	if !CheckPresence(verifierPosition, claimed, measured, tolerance) {
		return nil
	}
	return subject
}

// ---- PAD-109: ephemeris-scoped authority ----------------------------------

// RegionContains reports whether position lies inside the region predicate.
func RegionContains(region map[string]any, position [3]float64) (bool, error) {
	switch region["type"] {
	case "sphere":
		center, ok := asVec3(region["centerM"])
		radius, ok2 := asFloat(region["radiusM"])
		if !ok || !ok2 {
			return false, errors.New("robotics: sphere needs centerM and radiusM")
		}
		if radius < 0 {
			return false, errors.New("robotics: radiusM must be non-negative")
		}
		return ExpectedRangeM(position, center) <= radius, nil
	case "box":
		lo, ok := asVec3(region["minM"])
		hi, ok2 := asVec3(region["maxM"])
		if !ok || !ok2 {
			return false, errors.New("robotics: box needs minM and maxM")
		}
		for i := 0; i < 3; i++ {
			if position[i] < lo[i] || position[i] > hi[i] {
				return false, nil
			}
		}
		return true, nil
	case "altitudeBand":
		lo, ok := asFloat(region["minM"])
		hi, ok2 := asFloat(region["maxM"])
		if !ok || !ok2 {
			return false, errors.New("robotics: altitudeBand needs minM and maxM")
		}
		return lo <= position[2] && position[2] <= hi, nil
	default:
		return false, errors.New("robotics: unknown region type")
	}
}

// RegionAttenuates reports whether child is fully contained in parent.
func RegionAttenuates(parent, child map[string]any) (bool, error) {
	if parent["type"] != child["type"] {
		return false, nil
	}
	switch parent["type"] {
	case "sphere":
		pc, ok1 := asVec3(parent["centerM"])
		cc, ok2 := asVec3(child["centerM"])
		pr, ok3 := asFloat(parent["radiusM"])
		cr, ok4 := asFloat(child["radiusM"])
		if !ok1 || !ok2 || !ok3 || !ok4 {
			return false, nil
		}
		if pr < 0 || cr < 0 {
			return false, errors.New("robotics: radii must be non-negative")
		}
		return ExpectedRangeM(cc, pc)+cr <= pr, nil
	case "box":
		plo, o1 := asVec3(parent["minM"])
		phi, o2 := asVec3(parent["maxM"])
		clo, o3 := asVec3(child["minM"])
		chi, o4 := asVec3(child["maxM"])
		if !o1 || !o2 || !o3 || !o4 {
			return false, nil
		}
		for i := 0; i < 3; i++ {
			if plo[i] > clo[i] || chi[i] > phi[i] {
				return false, nil
			}
		}
		return true, nil
	case "altitudeBand":
		plo, o1 := asFloat(parent["minM"])
		phi, o2 := asFloat(parent["maxM"])
		clo, o3 := asFloat(child["minM"])
		chi, o4 := asFloat(child["maxM"])
		if !o1 || !o2 || !o3 || !o4 {
			return false, nil
		}
		return plo <= clo && chi <= phi, nil
	default:
		return false, errors.New("robotics: unknown region type")
	}
}

// BuildGeoscopedGrantOptions configures BuildGeoscopedGrant.
type BuildGeoscopedGrantOptions struct {
	HolderDID     string
	GrantID       string
	Region        map[string]any
	PhysicalScope map[string]any
	ParentGrantID string
}

// BuildGeoscopedGrant builds a signed EphemerisScopedGrantCredential.
func BuildGeoscopedGrant(s *signer.Signer, opts BuildGeoscopedGrantOptions) (map[string]any, error) {
	if opts.GrantID == "" {
		return nil, errors.New("robotics: grantId is required")
	}
	if _, err := RegionContains(opts.Region, [3]float64{0, 0, 0}); err != nil {
		return nil, err
	}
	subject := map[string]any{"id": opts.HolderDID, "grantId": opts.GrantID, "region": opts.Region}
	if opts.PhysicalScope != nil {
		subject["physicalScope"] = opts.PhysicalScope
	}
	if opts.ParentGrantID != "" {
		subject["parentGrantId"] = opts.ParentGrantID
	}
	return signSubject(s, GeoscopedGrantType, subject)
}

// VerifyGeoscopedGrant verifies the proof and (when parentRegion != nil) attenuation.
func VerifyGeoscopedGrant(cred map[string]any, pub ed25519.PublicKey, parentRegion map[string]any) map[string]any {
	subject := verifyTypedDTN(cred, pub, GeoscopedGrantType)
	if subject == nil {
		return nil
	}
	region, ok := subject["region"].(map[string]any)
	if !ok {
		return nil
	}
	if parentRegion != nil {
		att, err := RegionAttenuates(parentRegion, region)
		if err != nil || !att {
			return nil
		}
	}
	return subject
}

// GeoscopePermits reports whether a verified grant permits action at position.
func GeoscopePermits(subject map[string]any, position [3]float64) bool {
	region, ok := subject["region"].(map[string]any)
	if !ok {
		return false
	}
	res, err := RegionContains(region, position)
	return err == nil && res
}

// ---- PAD-114: two-body propagation + kinematic plausibility ---------------

func stumpffC(z float64) float64 {
	if z > 1e-12 {
		return (1 - math.Cos(math.Sqrt(z))) / z
	}
	if z < -1e-12 {
		return (math.Cosh(math.Sqrt(-z)) - 1) / -z
	}
	return 0.5
}

func stumpffS(z float64) float64 {
	if z > 1e-12 {
		s := math.Sqrt(z)
		return (s - math.Sin(s)) / (s * s * s)
	}
	if z < -1e-12 {
		s := math.Sqrt(-z)
		return (math.Sinh(s) - s) / (s * s * s)
	}
	return 1.0 / 6.0
}

func dot3(a, b [3]float64) float64 { return a[0]*b[0] + a[1]*b[1] + a[2]*b[2] }
func norm3(a [3]float64) float64   { return math.Sqrt(dot3(a, a)) }

// PropagateTwoBody propagates a state vector forward by dt seconds under two-body gravity.
func PropagateTwoBody(r0, v0 [3]float64, dt, mu float64) ([3]float64, [3]float64, error) {
	if mu <= 0 {
		return r0, v0, errors.New("robotics: mu must be positive")
	}
	if dt == 0 {
		return r0, v0, nil
	}
	r0mag := norm3(r0)
	if r0mag == 0 {
		return r0, v0, errors.New("robotics: degenerate state |r0|=0")
	}
	v0mag := norm3(v0)
	sqrtMu := math.Sqrt(mu)
	vr0 := dot3(r0, v0) / r0mag
	alpha := 2/r0mag - v0mag*v0mag/mu
	chi := sqrtMu * math.Abs(alpha) * dt
	converged := false
	for i := 0; i < 100; i++ {
		z := alpha * chi * chi
		c := stumpffC(z)
		sfn := stumpffS(z)
		f := (r0mag*vr0/sqrtMu)*chi*chi*c + (1-alpha*r0mag)*chi*chi*chi*sfn + r0mag*chi - sqrtMu*dt
		df := (r0mag*vr0/sqrtMu)*chi*(1-alpha*chi*chi*sfn) + (1-alpha*r0mag)*chi*chi*c + r0mag
		if df == 0 {
			return r0, v0, errors.New("robotics: two-body propagation stalled")
		}
		dchi := f / df
		chi -= dchi
		if math.Abs(dchi) < 1e-8 {
			converged = true
			break
		}
	}
	if !converged {
		return r0, v0, errors.New("robotics: two-body propagation did not converge")
	}
	z := alpha * chi * chi
	c := stumpffC(z)
	sfn := stumpffS(z)
	fl := 1 - (chi*chi/r0mag)*c
	gl := dt - (chi*chi*chi/sqrtMu)*sfn
	r := [3]float64{fl*r0[0] + gl*v0[0], fl*r0[1] + gl*v0[1], fl*r0[2] + gl*v0[2]}
	rmag := norm3(r)
	if rmag == 0 {
		return r0, v0, errors.New("robotics: degenerate propagated state")
	}
	fdot := (sqrtMu / (rmag * r0mag)) * (alpha*chi*chi*chi*sfn - chi)
	gdot := 1 - (chi*chi/rmag)*c
	v := [3]float64{fdot*r0[0] + gdot*v0[0], fdot*r0[1] + gdot*v0[1], fdot*r0[2] + gdot*v0[2]}
	return r, v, nil
}

// ReachableTwoBody reports whether claimed is reachable from the prior orbital state.
func ReachableTwoBody(priorPosition, priorVelocity, claimedPosition [3]float64, elapsedSeconds, mu, maxDeltaVMps, toleranceM float64) (bool, error) {
	if elapsedSeconds < 0 {
		return false, errors.New("robotics: elapsedSeconds must be non-negative")
	}
	rPred, _, err := PropagateTwoBody(priorPosition, priorVelocity, elapsedSeconds, mu)
	if err != nil {
		return false, err
	}
	return ExpectedRangeM(claimedPosition, rPred) <= maxDeltaVMps*elapsedSeconds+toleranceM, nil
}

// KinematicallyReachable dispatches on the envelope: surface, orbital ball, or two-body.
func KinematicallyReachable(priorPosition, claimedPosition [3]float64, elapsedSeconds float64, envelope map[string]any, priorVelocity *[3]float64, toleranceM float64) (bool, error) {
	if elapsedSeconds < 0 {
		return false, errors.New("robotics: elapsedSeconds must be non-negative")
	}
	if envelope["model"] == "two-body" {
		if priorVelocity == nil {
			return false, errors.New("robotics: two-body model requires priorVelocity")
		}
		mu := MuEarth
		if m, ok := asFloat(envelope["muM3S2"]); ok {
			mu = m
		}
		dv := 0.0
		if d, ok := asFloat(envelope["maxDeltaVMps"]); ok {
			dv = d
		}
		return ReachableTwoBody(priorPosition, *priorVelocity, claimedPosition, elapsedSeconds, mu, dv, toleranceM)
	}
	d := ExpectedRangeM(priorPosition, claimedPosition)
	var reach float64
	if dv, ok := asFloat(envelope["maxDeltaVMps"]); ok {
		v0 := 0.0
		if priorVelocity != nil {
			v0 = norm3(*priorVelocity)
		}
		reach = (v0 + dv) * elapsedSeconds
	} else {
		ms, _ := asFloat(envelope["maxSpeedMps"])
		reach = ms * elapsedSeconds
	}
	return d <= reach+toleranceM, nil
}

// ---- PAD-113: distributed proof of location -------------------------------

// BuildRangeObservation signs one observer's measured range to a target.
func BuildRangeObservation(s *signer.Signer, targetDID string, observerPosition [3]float64, measuredRangeM float64, nonce string, epoch int64) (map[string]any, error) {
	return signSubject(s, RangeObservationType, map[string]any{
		"id":               targetDID,
		"observer":         s.DID(),
		"observerPosition": vec3Slice(observerPosition),
		"measuredRangeM":   measuredRangeM,
		"nonce":            nonce,
		"epoch":            epoch,
	})
}

// VerifyRangeObservation verifies an observer's signed range observation.
func VerifyRangeObservation(obs map[string]any, observerPub ed25519.PublicKey) map[string]any {
	return verifyTypedDTN(obs, observerPub, RangeObservationType)
}

// CountConsistent counts observations consistent with claimedPosition.
func CountConsistent(subjects []map[string]any, claimedPosition [3]float64, toleranceM float64) int {
	n := 0
	for _, s := range subjects {
		p, ok := asVec3(s["observerPosition"])
		m, ok2 := asFloat(s["measuredRangeM"])
		if ok && ok2 && math.Abs(m-ExpectedRangeM(p, claimedPosition)) <= toleranceM {
			n++
		}
	}
	return n
}

// LocationConfirmed reports whether at least threshold observations agree.
func LocationConfirmed(subjects []map[string]any, claimedPosition [3]float64, toleranceM float64, threshold int) bool {
	return threshold > 0 && CountConsistent(subjects, claimedPosition, toleranceM) >= threshold
}

// BuildProofOfLocation issues a combiner proof-of-location credential.
func BuildProofOfLocation(s *signer.Signer, targetDID string, position [3]float64, observerDIDs []string, epoch int64) (map[string]any, error) {
	obs := make([]any, len(observerDIDs))
	for i, d := range observerDIDs {
		obs[i] = d
	}
	return signSubject(s, ProofOfLocationType, map[string]any{"id": targetDID, "position": vec3Slice(position), "observers": obs, "epoch": epoch})
}

// ---- PAD-121: narrow-beam presence ----------------------------------------

// WithinBeam reports whether peerDirection lies within half the beamwidth.
func WithinBeam(pointing, peerDirection [3]float64, beamwidthRad float64) bool {
	if beamwidthRad < 0 {
		return false
	}
	na, nb := norm3(pointing), norm3(peerDirection)
	if na == 0 || nb == 0 {
		return false
	}
	cos := dot3(pointing, peerDirection) / (na * nb)
	if cos > 1 {
		cos = 1
	} else if cos < -1 {
		cos = -1
	}
	return math.Acos(cos) <= beamwidthRad/2
}

// BuildBeamPresence signs a narrow-beam presence attestation.
func BuildBeamPresence(s *signer.Signer, peerDID, nonce string, pointing [3]float64, beamwidthRad float64) (map[string]any, error) {
	return signSubject(s, BeamPresenceType, map[string]any{"id": peerDID, "nonce": nonce, "pointing": vec3Slice(pointing), "beamwidthRad": beamwidthRad})
}

// VerifyBeamPresence verifies the proof, nonce, and beam geometry.
func VerifyBeamPresence(att map[string]any, pub ed25519.PublicKey, peerDirection [3]float64, expectedNonce string) map[string]any {
	subject := verifyTypedDTN(att, pub, BeamPresenceType)
	if subject == nil {
		return nil
	}
	if expectedNonce != "" {
		if n, _ := subject["nonce"].(string); n != expectedNonce {
			return nil
		}
	}
	pointing, ok := asVec3(subject["pointing"])
	beamwidth, ok2 := asFloat(subject["beamwidthRad"])
	if !ok || !ok2 {
		return nil
	}
	if !WithinBeam(pointing, peerDirection, beamwidth) {
		return nil
	}
	return subject
}

// ---- PAD-112: conditional dead-man revocation -----------------------------

// BuildConditionalRevocation pre-signs a dead-man revocation.
func BuildConditionalRevocation(s *signer.Signer, targetCredentialID, subjectDID string, deadlineEpoch int64) (map[string]any, error) {
	if targetCredentialID == "" {
		return nil, errors.New("robotics: targetCredentialId is required")
	}
	if deadlineEpoch < 0 {
		return nil, errors.New("robotics: deadlineEpoch must be non-negative")
	}
	return signSubject(s, ConditionalRevocationType, map[string]any{
		"id":                 subjectDID,
		"targetCredentialId": targetCredentialID,
		"deadlineEpoch":      deadlineEpoch,
		"renewalPredicate":   "renewal_epoch_gte_deadline",
	})
}

// VerifyConditionalRevocation verifies the authority's proof.
func VerifyConditionalRevocation(cred map[string]any, authorityPub ed25519.PublicKey) map[string]any {
	return verifyTypedDTN(cred, authorityPub, ConditionalRevocationType)
}

// ConditionalRevocationActive reports whether the dead-man revocation has fired.
func ConditionalRevocationActive(subject map[string]any, currentEpoch int64, lastRenewalEpoch *int64) (bool, error) {
	deadline, ok := asInt(subject["deadlineEpoch"])
	if !ok {
		return false, errors.New("robotics: subject missing integer deadlineEpoch")
	}
	if currentEpoch <= deadline {
		return false, nil
	}
	renewed := lastRenewalEpoch != nil && *lastRenewalEpoch >= deadline
	return !renewed, nil
}

// ---- PAD-120: dynamic revocation accumulator (sparse Merkle tree) ----------

const smtDepth = 256

func sha256sum(parts ...[]byte) [32]byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

var (
	emptyLeaf   [32]byte
	revokedLeaf = sha256sum([]byte("vouch:smt:revoked-leaf:v1"))
	smtDefaults [smtDepth + 1][32]byte
	smtOnce     sync.Once
)

func initDefaults() {
	smtOnce.Do(func() {
		smtDefaults[smtDepth] = emptyLeaf
		for i := smtDepth - 1; i >= 0; i-- {
			smtDefaults[i] = sha256sum(smtDefaults[i+1][:], smtDefaults[i+1][:])
		}
	})
}

func smtKey(credentialID string) [32]byte { return sha256sum([]byte(credentialID)) }

func smtBit(key [32]byte, level int) byte { return (key[level>>3] >> (7 - (level & 7))) & 1 }

func smtNode(level int, keys [][32]byte) [32]byte {
	if len(keys) == 0 {
		return smtDefaults[level]
	}
	if level == smtDepth {
		return revokedLeaf
	}
	var left, right [][32]byte
	for _, k := range keys {
		if smtBit(k, level) == 0 {
			left = append(left, k)
		} else {
			right = append(right, k)
		}
	}
	l := smtNode(level+1, left)
	r := smtNode(level+1, right)
	return sha256sum(l[:], r[:])
}

// SparseMerkleTree is a dynamic revocation accumulator over the revoked set.
type SparseMerkleTree struct {
	revoked map[[32]byte]struct{}
}

// NewSparseMerkleTree returns an empty accumulator.
func NewSparseMerkleTree() *SparseMerkleTree {
	initDefaults()
	return &SparseMerkleTree{revoked: map[[32]byte]struct{}{}}
}

// Revoke marks a credential id as revoked.
func (t *SparseMerkleTree) Revoke(credentialID string) { t.revoked[smtKey(credentialID)] = struct{}{} }

// Unrevoke clears a credential id.
func (t *SparseMerkleTree) Unrevoke(credentialID string) { delete(t.revoked, smtKey(credentialID)) }

// IsRevoked reports whether a credential id is revoked.
func (t *SparseMerkleTree) IsRevoked(credentialID string) bool {
	_, ok := t.revoked[smtKey(credentialID)]
	return ok
}

func (t *SparseMerkleTree) keys() [][32]byte {
	out := make([][32]byte, 0, len(t.revoked))
	for k := range t.revoked {
		out = append(out, k)
	}
	return out
}

// Root returns the sparse-Merkle root.
func (t *SparseMerkleTree) Root() [32]byte { return smtNode(0, t.keys()) }

// RootMultibase returns the multibase-encoded root.
func (t *SparseMerkleTree) RootMultibase() string {
	r := t.Root()
	return mb64(r[:])
}

// NonRevocationProof builds a compressed non-membership proof.
func (t *SparseMerkleTree) NonRevocationProof(credentialID string) map[string]any {
	key := smtKey(credentialID)
	keys := t.keys()
	bitmap := make([]byte, smtDepth/8)
	siblings := []any{}
	for level := 0; level < smtDepth; level++ {
		var left, right [][32]byte
		for _, k := range keys {
			if smtBit(k, level) == 0 {
				left = append(left, k)
			} else {
				right = append(right, k)
			}
		}
		var sib [32]byte
		if smtBit(key, level) == 0 {
			sib = smtNode(level+1, right)
			keys = left
		} else {
			sib = smtNode(level+1, left)
			keys = right
		}
		if sib != smtDefaults[level+1] {
			bitmap[level>>3] |= 1 << (7 - (level & 7))
			siblings = append(siblings, mb64(sib[:]))
		}
	}
	return map[string]any{"bitmap": mb64(bitmap), "siblings": siblings}
}

// VerifyNonRevocationProof verifies a non-membership proof against root.
func VerifyNonRevocationProof(credentialID string, proof map[string]any, root [32]byte) bool {
	initDefaults()
	key := smtKey(credentialID)
	bitmapStr, ok := proof["bitmap"].(string)
	if !ok {
		return false
	}
	bitmap, err := unmb64(bitmapStr)
	if err != nil || len(bitmap) != smtDepth/8 {
		return false
	}
	sibsRaw, ok := proof["siblings"].([]any)
	if !ok {
		return false
	}
	sibList := make([][32]byte, 0, len(sibsRaw))
	for _, s := range sibsRaw {
		str, ok := s.(string)
		if !ok {
			return false
		}
		b, err := unmb64(str)
		if err != nil || len(b) != 32 {
			return false
		}
		var a [32]byte
		copy(a[:], b)
		sibList = append(sibList, a)
	}
	var sibByLevel [smtDepth][32]byte
	idx := 0
	for level := 0; level < smtDepth; level++ {
		if (bitmap[level>>3]>>(7-(level&7)))&1 == 1 {
			if idx >= len(sibList) {
				return false
			}
			sibByLevel[level] = sibList[idx]
			idx++
		} else {
			sibByLevel[level] = smtDefaults[level+1]
		}
	}
	if idx != len(sibList) {
		return false
	}
	current := emptyLeaf
	for level := smtDepth - 1; level >= 0; level-- {
		sib := sibByLevel[level]
		if smtBit(key, level) == 0 {
			current = sha256sum(current[:], sib[:])
		} else {
			current = sha256sum(sib[:], current[:])
		}
	}
	return current == root
}

// BuildRevocationAccumulatorRoot signs the current accumulator root.
func BuildRevocationAccumulatorRoot(s *signer.Signer, tree *SparseMerkleTree, epoch int64) (map[string]any, error) {
	if epoch < 0 {
		return nil, errors.New("robotics: epoch must be non-negative")
	}
	return signSubject(s, RevocationAccumulatorType, map[string]any{"id": s.DID(), "epoch": epoch, "revocationRoot": tree.RootMultibase()})
}

// BuildNonRevocationProof builds a carried non-membership proof.
func BuildNonRevocationProof(tree *SparseMerkleTree, credentialID string) map[string]any {
	return tree.NonRevocationProof(credentialID)
}

// VerifyNonRevocation verifies non-revocation against a signed accumulator root.
func VerifyNonRevocation(credentialID string, proof, signedRoot map[string]any, authorityPub ed25519.PublicKey) bool {
	subject := verifyTypedDTN(signedRoot, authorityPub, RevocationAccumulatorType)
	if subject == nil {
		return false
	}
	rootMb, ok := subject["revocationRoot"].(string)
	if !ok {
		return false
	}
	b, err := unmb64(rootMb)
	if err != nil || len(b) != 32 {
		return false
	}
	var root [32]byte
	copy(root[:], b)
	return VerifyNonRevocationProof(credentialID, proof, root)
}

// ---- PAD-110/111/116: quarantine, quorum, key continuity ------------------

// BuildDistressAttestation signs evidence-bound distress against a target.
func BuildDistressAttestation(s *signer.Signer, targetDID, reason, evidenceRef string, epoch int64) (map[string]any, error) {
	if targetDID == "" || reason == "" || evidenceRef == "" {
		return nil, errors.New("robotics: targetDid, reason, evidenceRef required")
	}
	return signSubject(s, DistressType, map[string]any{"id": targetDID, "observer": s.DID(), "reason": reason, "evidenceRef": evidenceRef, "epoch": epoch})
}

// VerifyDistressAttestation verifies an observer's distress attestation.
func VerifyDistressAttestation(att map[string]any, observerPub ed25519.PublicKey) map[string]any {
	return verifyTypedDTN(att, observerPub, DistressType)
}

// IsQuarantined reports whether a threshold of distinct attested members signed distress.
func IsQuarantined(distressSubjects []map[string]any, targetDID string, threshold int, memberDIDs map[string]struct{}, window *[2]int64) bool {
	if threshold == 0 {
		return false
	}
	signers := map[string]struct{}{}
	for _, s := range distressSubjects {
		if id, _ := s["id"].(string); id != targetDID {
			continue
		}
		observer, _ := s["observer"].(string)
		if _, ok := memberDIDs[observer]; !ok {
			continue
		}
		if window != nil {
			e, ok := asInt(s["epoch"])
			if !ok || e < window[0] || e > window[1] {
				continue
			}
		}
		signers[observer] = struct{}{}
	}
	return len(signers) >= threshold
}

// BuildTrustStateUpdate signs an anchor's trust-state change.
func BuildTrustStateUpdate(s *signer.Signer, scope string, change map[string]any, epoch int64, failureDomain string) (map[string]any, error) {
	if scope == "" || failureDomain == "" {
		return nil, errors.New("robotics: scope and failureDomain required")
	}
	return signSubject(s, TrustStateUpdateType, map[string]any{"id": s.DID(), "scope": scope, "change": change, "epoch": epoch, "failureDomain": failureDomain})
}

// VerifyTrustStateUpdate verifies an anchor's trust-state update.
func VerifyTrustStateUpdate(update map[string]any, anchorPub ed25519.PublicKey) map[string]any {
	return verifyTypedDTN(update, anchorPub, TrustStateUpdateType)
}

// AcceptTrustStateUpdate accepts a change on distinct-failure-domain corroboration with no rollback.
func AcceptTrustStateUpdate(corroborating []map[string]any, currentEpoch int64, threshold int) bool {
	if threshold == 0 || len(corroborating) == 0 {
		return false
	}
	ref := corroborating[0]
	scope := jsonKey(ref["scope"])
	change := jsonKey(ref["change"])
	epoch, ok := asInt(ref["epoch"])
	if !ok || epoch < currentEpoch {
		return false
	}
	domains := map[string]struct{}{}
	for _, s := range corroborating {
		e, _ := asInt(s["epoch"])
		if jsonKey(s["scope"]) != scope || jsonKey(s["change"]) != change || e != epoch {
			continue
		}
		if fd, ok := s["failureDomain"].(string); ok {
			domains[fd] = struct{}{}
		}
	}
	return len(domains) >= threshold
}

// BuildKeyContinuityPredelegation pre-delegates a threshold of members to re-issue.
func BuildKeyContinuityPredelegation(s *signer.Signer, missionCredentialID string, memberDIDs []string, threshold int) (map[string]any, error) {
	set := map[string]struct{}{}
	for _, m := range memberDIDs {
		set[m] = struct{}{}
	}
	members := make([]string, 0, len(set))
	for m := range set {
		members = append(members, m)
	}
	sort.Strings(members)
	if threshold == 0 || threshold > len(members) {
		return nil, errors.New("robotics: threshold must be in 1..=len(members)")
	}
	membersAny := make([]any, len(members))
	for i, m := range members {
		membersAny[i] = m
	}
	return signSubject(s, KeyContinuityPredelType, map[string]any{"id": missionCredentialID, "members": membersAny, "threshold": threshold, "bound": "preserve_or_narrow"})
}

// BuildContinuityApproval signs a member's approval of a re-issuance.
func BuildContinuityApproval(s *signer.Signer, reissuanceID, supersedes string, epoch int64) (map[string]any, error) {
	return signSubject(s, ContinuityApprovalType, map[string]any{"id": reissuanceID, "member": s.DID(), "supersedes": supersedes, "epoch": epoch})
}

// VerifyKeyContinuity confirms a threshold of distinct authorized members approved a re-issuance.
func VerifyKeyContinuity(predelegationSubject map[string]any, reissuanceID, supersedes string, approvalSubjects []map[string]any) bool {
	members := map[string]struct{}{}
	if arr, ok := predelegationSubject["members"].([]any); ok {
		for _, m := range arr {
			if str, ok := m.(string); ok {
				members[str] = struct{}{}
			}
		}
	}
	threshold, ok := asInt(predelegationSubject["threshold"])
	if !ok || threshold <= 0 {
		return false
	}
	approvers := map[string]struct{}{}
	for _, s := range approvalSubjects {
		if id, _ := s["id"].(string); id != reissuanceID {
			continue
		}
		if sup, _ := s["supersedes"].(string); sup != supersedes {
			continue
		}
		if m, ok := s["member"].(string); ok {
			if _, isMember := members[m]; isMember {
				approvers[m] = struct{}{}
			}
		}
	}
	return int64(len(approvers)) >= threshold
}

// ---- PAD-115/117/118: time-quality, autonomy, integrity -------------------

// DefaultTimeUncertaintyBudget returns the default max time uncertainty (s) per tier.
func DefaultTimeUncertaintyBudget(tier string) float64 {
	switch tierOrCritical(tier) {
	case ConsequenceRoutine:
		return 3600
	case ConsequenceSensitive:
		return 60
	default:
		return 1
	}
}

// BuildTimeQualityAttestation signs a node's clock quality.
func BuildTimeQualityAttestation(s *signer.Signer, sourceClass string, sinceDisciplineS, uncertaintyS float64) (map[string]any, error) {
	if uncertaintyS < 0 || sinceDisciplineS < 0 {
		return nil, errors.New("robotics: uncertaintyS and sinceDisciplineS must be non-negative")
	}
	return signSubject(s, TimeQualityType, map[string]any{"id": s.DID(), "sourceClass": sourceClass, "sinceDisciplineS": sinceDisciplineS, "uncertaintyS": uncertaintyS})
}

// VerifyTimeQualityAttestation verifies a time-quality attestation.
func VerifyTimeQualityAttestation(att map[string]any, pub ed25519.PublicKey) map[string]any {
	return verifyTypedDTN(att, pub, TimeQualityType)
}

// TimeQualityPermits admits a time-dependent decision only if uncertainty is within budget.
func TimeQualityPermits(subject map[string]any, tier string, budgetOverride *float64) bool {
	unc, ok := asFloat(subject["uncertaintyS"])
	if !ok {
		return false
	}
	budget := DefaultTimeUncertaintyBudget(tier)
	if budgetOverride != nil {
		budget = *budgetOverride
	}
	return unc <= budget
}

// BuildAutonomySchedule signs a decay schedule of attenuating steps.
func BuildAutonomySchedule(s *signer.Signer, subjectDID string, steps []map[string]any) (map[string]any, error) {
	if len(steps) == 0 {
		return nil, errors.New("robotics: steps must be non-empty")
	}
	var prevThresh int64 = -1
	var prevScope map[string]any
	stepsAny := make([]any, len(steps))
	for i, st := range steps {
		thresh, ok := asInt(st["maxStalenessEpochs"])
		if !ok || thresh <= prevThresh {
			return nil, errors.New("robotics: maxStalenessEpochs must be strictly ascending integers")
		}
		scope, ok := st["physicalScope"].(map[string]any)
		if !ok {
			return nil, errors.New("robotics: each step needs a physicalScope object")
		}
		if prevScope != nil && !Attenuates(prevScope, scope) {
			return nil, errors.New("robotics: each step scope must attenuate the previous")
		}
		prevThresh = thresh
		prevScope = scope
		stepsAny[i] = st
	}
	return signSubject(s, AutonomyScheduleType, map[string]any{"id": subjectDID, "steps": stepsAny})
}

// VerifyAutonomySchedule verifies a decay schedule.
func VerifyAutonomySchedule(schedule map[string]any, pub ed25519.PublicKey) map[string]any {
	return verifyTypedDTN(schedule, pub, AutonomyScheduleType)
}

// SelectEnvelope selects the physical scope for the current staleness.
func SelectEnvelope(scheduleSubject map[string]any, stalenessEpochs int64) map[string]any {
	steps, ok := scheduleSubject["steps"].([]any)
	if !ok || len(steps) == 0 {
		return nil
	}
	for _, st := range steps {
		m, _ := st.(map[string]any)
		if t, ok := asInt(m["maxStalenessEpochs"]); ok && stalenessEpochs <= t {
			sc, _ := m["physicalScope"].(map[string]any)
			return sc
		}
	}
	last, _ := steps[len(steps)-1].(map[string]any)
	sc, _ := last["physicalScope"].(map[string]any)
	return sc
}

// AutonomyPermits admits an action only if it fits the staleness-selected envelope.
func AutonomyPermits(scheduleSubject map[string]any, stalenessEpochs int64, action PhysicalAction) bool {
	scope := SelectEnvelope(scheduleSubject, stalenessEpochs)
	if scope == nil {
		return false
	}
	return CheckPhysicalAction(scope, action).OK
}

// BuildIntegrityRiskAttestation signs a node's cumulative key-store integrity risk.
func BuildIntegrityRiskAttestation(s *signer.Signer, cumulativeRisk float64, metrics map[string]any, prevHash string) (map[string]any, error) {
	if cumulativeRisk < 0 {
		return nil, errors.New("robotics: cumulativeRisk must be non-negative")
	}
	subject := map[string]any{"id": s.DID(), "cumulativeRisk": cumulativeRisk}
	if metrics != nil {
		subject["metrics"] = metrics
	}
	if prevHash != "" {
		subject["prevHash"] = prevHash
	}
	return signSubject(s, IntegrityRiskType, subject)
}

// VerifyIntegrityRiskAttestation verifies an integrity-risk attestation.
func VerifyIntegrityRiskAttestation(att map[string]any, pub ed25519.PublicKey) map[string]any {
	return verifyTypedDTN(att, pub, IntegrityRiskType)
}

// IntegrityAuthorityLevel maps cumulative risk to an authority level.
func IntegrityAuthorityLevel(cumulativeRisk, narrowThreshold, suspectThreshold float64) string {
	if cumulativeRisk >= suspectThreshold {
		return IntegritySuspect
	}
	if cumulativeRisk >= narrowThreshold {
		return IntegrityNarrowed
	}
	return IntegrityFull
}

// ---- PAD-122/123: perception consensus + mesh -----------------------------

// BuildPerceptionClaim signs a node's perception of a shared feature.
func BuildPerceptionClaim(s *signer.Signer, sceneNonce, feature string, value any, epoch int64) (map[string]any, error) {
	if sceneNonce == "" || feature == "" {
		return nil, errors.New("robotics: sceneNonce and feature required")
	}
	return signSubject(s, PerceptionClaimType, map[string]any{"id": s.DID(), "sceneNonce": sceneNonce, "feature": feature, "value": value, "epoch": epoch})
}

// VerifyPerceptionClaim verifies a perception claim.
func VerifyPerceptionClaim(claim map[string]any, pub ed25519.PublicKey) map[string]any {
	return verifyTypedDTN(claim, pub, PerceptionClaimType)
}

func valueDistance(a, b any) (float64, bool) {
	if fa, ok := asFloat(a); ok {
		if fb, ok := asFloat(b); ok {
			return math.Abs(fa - fb), true
		}
		return 0, false
	}
	aa, ok1 := a.([]any)
	bb, ok2 := b.([]any)
	if ok1 && ok2 && len(aa) == len(bb) {
		sum := 0.0
		for i := range aa {
			fa, o1 := asFloat(aa[i])
			fb, o2 := asFloat(bb[i])
			if !o1 || !o2 {
				return 0, false
			}
			sum += (fa - fb) * (fa - fb)
		}
		return math.Sqrt(sum), true
	}
	return 0, false
}

// CrossCheckPerception returns corroborated and flagged node DIDs (sorted).
func CrossCheckPerception(claimSubjects []map[string]any, tolerance float64, threshold int) (corroborated, flagged []string) {
	type entry struct {
		did string
		val any
	}
	var entries []entry
	for _, s := range claimSubjects {
		did, ok := s["id"].(string)
		if !ok {
			continue
		}
		val, has := s["value"]
		if !has {
			continue
		}
		entries = append(entries, entry{did, val})
	}
	for _, e := range entries {
		agree := 0
		for _, o := range entries {
			if o.did == e.did {
				continue
			}
			if d, ok := valueDistance(e.val, o.val); ok && d <= tolerance {
				agree++
			}
		}
		if agree >= threshold {
			corroborated = append(corroborated, e.did)
		} else {
			flagged = append(flagged, e.did)
		}
	}
	sort.Strings(corroborated)
	sort.Strings(flagged)
	return
}

// BuildInteractionAttestation signs a pairwise interaction attestation.
func BuildInteractionAttestation(s *signer.Signer, peerDID, outcome string, epoch int64) (map[string]any, error) {
	if peerDID == "" {
		return nil, errors.New("robotics: peerDid required")
	}
	return signSubject(s, InteractionAttestType, map[string]any{"id": peerDID, "attestor": s.DID(), "outcome": outcome, "epoch": epoch})
}

// VerifyInteractionAttestation verifies an interaction attestation.
func VerifyInteractionAttestation(att map[string]any, attestorPub ed25519.PublicKey) map[string]any {
	return verifyTypedDTN(att, attestorPub, InteractionAttestType)
}

// NodeStanding computes a node's decay-weighted standing from distinct-neighbor attestations.
func NodeStanding(attestationSubjects []map[string]any, nodeDID string, currentEpoch int64, halfLifeEpochs float64, positiveOutcomes []string) float64 {
	pos := map[string]struct{}{}
	for _, o := range positiveOutcomes {
		pos[o] = struct{}{}
	}
	freshest := map[string]int64{}
	for _, s := range attestationSubjects {
		if id, _ := s["id"].(string); id != nodeDID {
			continue
		}
		outcome, _ := s["outcome"].(string)
		if _, ok := pos[outcome]; !ok {
			continue
		}
		attestor, ok := s["attestor"].(string)
		e, ok2 := asInt(s["epoch"])
		if !ok || !ok2 || e > currentEpoch {
			continue
		}
		if cur, seen := freshest[attestor]; !seen || e > cur {
			freshest[attestor] = e
		}
	}
	total := 0.0
	for _, e := range freshest {
		if w, err := DecayWeight(currentEpoch-e, halfLifeEpochs, "exponential"); err == nil {
			total += w
		}
	}
	return total
}

// ---- PAD-124: DTN bundle custody ------------------------------------------

// BindCredentialToBundle binds an originator credential and payload hash to a bundle.
func BindCredentialToBundle(s *signer.Signer, bundleID, payloadHash string, intent map[string]any) (map[string]any, error) {
	if bundleID == "" || payloadHash == "" {
		return nil, errors.New("robotics: bundleId and payloadHash required")
	}
	return signSubject(s, BundleCredentialType, map[string]any{"id": bundleID, "originator": s.DID(), "payloadHash": payloadHash, "intent": intent})
}

// VerifyBundleTrust verifies the originator proof and payload hash.
func VerifyBundleTrust(bundleCredential map[string]any, originatorPub ed25519.PublicKey, payloadHash string) map[string]any {
	subject := verifyTypedDTN(bundleCredential, originatorPub, BundleCredentialType)
	if subject == nil {
		return nil
	}
	if ph, _ := subject["payloadHash"].(string); ph != payloadHash {
		return nil
	}
	return subject
}

// BuildCustodyTransfer signs a relay's acceptance of custody.
func BuildCustodyTransfer(s *signer.Signer, bundleID string, previousCustodian *string, epoch int64) (map[string]any, error) {
	var prev any
	if previousCustodian != nil {
		prev = *previousCustodian
	} else {
		prev = nil
	}
	return signSubject(s, CustodyTransferType, map[string]any{"id": bundleID, "custodian": s.DID(), "previousCustodian": prev, "epoch": epoch})
}

// VerifyCustodyTransfer verifies a custody transfer.
func VerifyCustodyTransfer(transfer map[string]any, custodianPub ed25519.PublicKey) map[string]any {
	return verifyTypedDTN(transfer, custodianPub, CustodyTransferType)
}

// CustodyChainOk confirms custody transfers form an unbroken chain for bundleID.
func CustodyChainOk(transferSubjects []map[string]any, bundleID, originator string) bool {
	var chain []map[string]any
	for _, s := range transferSubjects {
		if id, _ := s["id"].(string); id == bundleID {
			chain = append(chain, s)
		}
	}
	if len(chain) == 0 {
		return false
	}
	expectedPrev := originator
	for _, s := range chain {
		prev, _ := s["previousCustodian"].(string)
		if prev != expectedPrev {
			return false
		}
		custodian, ok := s["custodian"].(string)
		if !ok {
			return false
		}
		expectedPrev = custodian
	}
	return true
}
