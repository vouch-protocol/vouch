// Authority Freshness: authority state as a first-class input to trust freshness.
//
// Mirrors vouch/authority_state.py and core/vouch-core/src/authority_state.rs.
// A signed AuthorityState credential carries a monotonic authorityEpoch and a
// status. The collapse rule (EvaluateAuthorityFreshness) rejects a voucher
// minted under a stale epoch for a state-freshness action, even when its
// time-decay trust still passes. The credential is a plain VC Data Model 2.0
// object signed with the shared eddsa-jcs-2022 path, so it canonicalizes
// byte-identically across every language binding and shares the interop vector
// in test-vectors/authority-state/.

package signer

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strconv"
	"time"
)

const (
	AuthorityStateType = "AuthorityState"

	StatusActive           = "active"
	StatusSuspended        = "suspended"
	StatusIncident         = "incident"
	StatusExposureBreached = "exposure_breached"
	StatusRevoked          = "revoked"

	// Consequence tiers, ordered by how much a stale authority view is
	// tolerated. Shared vocabulary with bounded-staleness revocation.
	ConsequenceRoutine   = "routine"
	ConsequenceSensitive = "sensitive"
	ConsequenceCritical  = "critical"
)

// epochStr renders an epoch for a reason code; "?" when absent, so the string
// is identical across every language binding.
func epochStr(epoch *int64) string {
	if epoch == nil {
		return "?"
	}
	return strconv.FormatInt(*epoch, 10)
}

func validAuthorityStatus(status string) bool {
	switch status {
	case StatusActive, StatusSuspended, StatusIncident, StatusExposureBreached, StatusRevoked:
		return true
	default:
		return false
	}
}

// BuildAuthorityStateOptions configures BuildAuthorityState. Deterministic and
// clock-free: the caller supplies the id and validity window.
type BuildAuthorityStateOptions struct {
	IssuerDID      string
	AuthorityEpoch int64
	Status         string // defaults to "active"
	ValidSeconds   int
	ValidFrom      time.Time
	CredentialID   string
	SubjectDID     string // defaults to IssuerDID
}

// BuildAuthorityState constructs an unsigned AuthorityState credential. The
// caller attaches a Data Integrity proof via BuildDataIntegrityProof.
func BuildAuthorityState(opts BuildAuthorityStateOptions) (map[string]any, error) {
	if opts.AuthorityEpoch < 0 {
		return nil, errors.New("authorityEpoch must be non-negative")
	}
	status := opts.Status
	if status == "" {
		status = StatusActive
	}
	if !validAuthorityStatus(status) {
		return nil, fmt.Errorf("invalid status: %q", status)
	}
	if opts.IssuerDID == "" {
		return nil, errors.New("issuer_did is required")
	}

	issuedAt := opts.ValidFrom
	if issuedAt.IsZero() {
		issuedAt = time.Now().UTC()
	} else {
		issuedAt = issuedAt.UTC()
	}
	validSeconds := opts.ValidSeconds
	if validSeconds <= 0 {
		validSeconds = 300
	}
	expiresAt := issuedAt.Add(time.Duration(validSeconds) * time.Second)

	subjectDID := opts.SubjectDID
	if subjectDID == "" {
		subjectDID = opts.IssuerDID
	}

	credID := opts.CredentialID
	if credID == "" {
		uuid, err := newUUIDURN()
		if err != nil {
			return nil, err
		}
		credID = uuid
	}

	subject := map[string]any{
		"id":             subjectDID,
		"authorityEpoch": opts.AuthorityEpoch,
		"status":         status,
	}

	vc := map[string]any{
		"@context":          []any{VCContextV2, VouchContextV1},
		"id":                credID,
		"type":              []any{VCType, AuthorityStateType},
		"issuer":            opts.IssuerDID,
		"validFrom":         formatISO8601(issuedAt),
		"validUntil":        formatISO8601(expiresAt),
		"credentialSubject": subject,
	}
	return vc, nil
}

// AuthorityVerifyResult reports the proof and temporal checks separately so a
// caller can distinguish "bad signature" from "expired".
type AuthorityVerifyResult struct {
	ProofValid bool
	TimeValid  bool
}

func (r AuthorityVerifyResult) IsValid() bool {
	return r.ProofValid && r.TimeValid
}

// VerifyAuthorityState verifies an AuthorityState credential's Data Integrity
// proof and validity window against nowISO.
func VerifyAuthorityState(
	credential map[string]any,
	publicKey ed25519.PublicKey,
	nowISO string,
	clockSkewSeconds int64,
) (AuthorityVerifyResult, error) {
	types, _ := credential["type"].([]any)
	isAuthorityState := false
	for _, t := range types {
		if s, _ := t.(string); s == AuthorityStateType {
			isAuthorityState = true
			break
		}
	}
	if !isAuthorityState {
		return AuthorityVerifyResult{}, errors.New("credential is not an AuthorityState")
	}

	proofValid, err := VerifyDataIntegrityProof(credential, publicKey)
	if err != nil {
		return AuthorityVerifyResult{}, err
	}
	timeValid, err := verifyAuthorityTemporal(credential, nowISO, clockSkewSeconds)
	if err != nil {
		return AuthorityVerifyResult{}, err
	}
	return AuthorityVerifyResult{ProofValid: proofValid, TimeValid: timeValid}, nil
}

func verifyAuthorityTemporal(credential map[string]any, nowISO string, clockSkewSeconds int64) (bool, error) {
	vf, _ := credential["validFrom"].(string)
	vu, _ := credential["validUntil"].(string)
	if vf == "" || vu == "" {
		return false, errors.New("credential missing validFrom or validUntil")
	}
	now, err := time.Parse("2006-01-02T15:04:05Z", nowISO)
	if err != nil {
		return false, fmt.Errorf("parse nowISO: %w", err)
	}
	from, err := time.Parse("2006-01-02T15:04:05Z", vf)
	if err != nil {
		return false, fmt.Errorf("parse validFrom: %w", err)
	}
	until, err := time.Parse("2006-01-02T15:04:05Z", vu)
	if err != nil {
		return false, fmt.Errorf("parse validUntil: %w", err)
	}
	skew := time.Duration(clockSkewSeconds) * time.Second
	return !now.Before(from.Add(-skew)) && !now.After(until.Add(skew)), nil
}

// ReadAuthorityEpoch reads credentialSubject.authorityEpoch without verifying
// the proof. For deciding which of two credentials is newer.
func ReadAuthorityEpoch(credential map[string]any) (int64, error) {
	subject, ok := credential["credentialSubject"].(map[string]any)
	if !ok {
		return 0, errors.New("missing credentialSubject")
	}
	switch e := subject["authorityEpoch"].(type) {
	case float64:
		if e < 0 {
			return 0, errors.New("authorityEpoch must be non-negative")
		}
		return int64(e), nil
	case int64:
		return e, nil
	case int:
		return int64(e), nil
	default:
		return 0, errors.New("missing or invalid authorityEpoch")
	}
}

// ReadAuthorityStatus reads credentialSubject.status without verifying the proof.
func ReadAuthorityStatus(credential map[string]any) (string, error) {
	subject, ok := credential["credentialSubject"].(map[string]any)
	if !ok {
		return "", errors.New("missing credentialSubject")
	}
	status, _ := subject["status"].(string)
	if !validAuthorityStatus(status) {
		return "", errors.New("missing or invalid status")
	}
	return status, nil
}

// FreshnessRule is how a consequence tier treats authority state.
type FreshnessRule struct {
	EnforceEpoch      bool
	RequireLiveCosign bool
}

// FreshnessRuleFor returns the policy for a tier. Unknown tiers coerce to the
// strictest rule.
func FreshnessRuleFor(tier string) FreshnessRule {
	switch tier {
	case ConsequenceRoutine:
		return FreshnessRule{EnforceEpoch: false, RequireLiveCosign: false}
	case ConsequenceSensitive:
		return FreshnessRule{EnforceEpoch: true, RequireLiveCosign: false}
	default:
		return FreshnessRule{EnforceEpoch: true, RequireLiveCosign: true}
	}
}

// AuthorityFreshnessVerdict is the outcome of an Authority Freshness evaluation.
type AuthorityFreshnessVerdict struct {
	Allow  bool
	Tier   string
	Reason string
}

// EvaluateAuthorityFreshness decides whether an action passes the Authority
// Freshness gate. voucherEpoch and lastSeenEpoch are nil when unknown;
// currentStatus is "" when the verifier holds no current AuthorityState;
// liveCosignOK is nil unless a live co-sign was evaluated.
func EvaluateAuthorityFreshness(
	tier string,
	voucherEpoch *int64,
	lastSeenEpoch *int64,
	currentStatus string,
	liveCosignOK *bool,
) AuthorityFreshnessVerdict {
	canonicalTier := tier
	switch tier {
	case ConsequenceRoutine, ConsequenceSensitive, ConsequenceCritical:
	default:
		canonicalTier = ConsequenceCritical
	}
	rule := FreshnessRuleFor(canonicalTier)
	mk := func(allow bool, reason string) AuthorityFreshnessVerdict {
		return AuthorityFreshnessVerdict{Allow: allow, Tier: canonicalTier, Reason: reason}
	}

	if !rule.EnforceEpoch && !rule.RequireLiveCosign {
		return mk(true, "routine tier: time-decay only")
	}

	if currentStatus != "" && currentStatus != StatusActive {
		return mk(false, fmt.Sprintf("authority_status_not_active:status=%s", currentStatus))
	}

	if rule.RequireLiveCosign && (liveCosignOK == nil || !*liveCosignOK) {
		return mk(false, fmt.Sprintf("live_cosign_required:tier=%s", canonicalTier))
	}

	if rule.EnforceEpoch {
		if voucherEpoch == nil || lastSeenEpoch == nil {
			// An absent epoch renders as "?" so the reason code is identical in
			// every language binding. Pinned by the interop vector.
			return mk(false, fmt.Sprintf(
				"authority_epoch_unknown:voucher=%s,seen=%s",
				epochStr(voucherEpoch), epochStr(lastSeenEpoch),
			))
		}
		if *voucherEpoch < *lastSeenEpoch {
			return mk(false, fmt.Sprintf("authority_epoch_stale:seen=%d,voucher=%d", *lastSeenEpoch, *voucherEpoch))
		}
	}

	return mk(true, fmt.Sprintf("%s tier: authority state fresh", canonicalTier))
}
