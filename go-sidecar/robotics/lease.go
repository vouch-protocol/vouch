// Robot delegation lease (Phase 5.x), Go.
//
// Mirrors vouch/robotics/lease.py and the TypeScript SDK. A delegation lease is a
// short-lived, scope-bounded, offline-verifiable grant of authority. A robot often
// has to act where there is no connectivity, so it cannot call home to check
// whether it is still allowed to do something. A lease is a self-contained
// credential it can verify and act on entirely offline: an authority bounds what
// the robot may physically do (a physical capability scope, including the zones it
// may operate in) for a fixed, short window. The robot verifies the lease's
// signature, that the window is current, and that a proposed action fits the
// scope, with no network call.
//
// Leases nest: an authority can grant a lease, and the holder can sub-grant a
// narrower lease, each link attenuating (never widening) the one above it. This is
// the open layer: a plain, offline-verifiable lease.
package robotics

import (
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// DelegationLeaseType is the credential type for a delegation lease.
const DelegationLeaseType = "DelegationLeaseCredential"

// BuildLeaseOptions configures BuildDelegationLease. A zero ValidFrom uses now; an
// empty ParentLeaseID omits the field (set it when sub-granting from another lease).
type BuildLeaseOptions struct {
	RobotDID      string
	LeaseID       string
	Scope         map[string]any
	ValidSeconds  int
	ValidFrom     time.Time
	ParentLeaseID string
}

// BuildDelegationLease builds a signed DelegationLeaseCredential granting RobotDID
// a bounded physical Scope for a fixed window. Scope is a physicalScope object (the
// same shape as a PhysicalCapabilityScope credentialSubject.physicalScope). Leases
// are short-lived by design, so ValidSeconds is required.
func BuildDelegationLease(s *signer.Signer, opts BuildLeaseOptions) (map[string]any, error) {
	if opts.ValidSeconds <= 0 {
		return nil, errors.New("robotics: valid_seconds must be positive")
	}
	if opts.LeaseID == "" {
		return nil, errors.New("robotics: lease_id is required")
	}
	if opts.Scope == nil {
		return nil, errors.New("robotics: scope must be a physicalScope object")
	}

	issued := opts.ValidFrom
	if issued.IsZero() {
		issued = time.Now().UTC()
	}

	subject := map[string]any{
		"id":            opts.RobotDID,
		"leaseId":       opts.LeaseID,
		"physicalScope": opts.Scope,
	}
	if opts.ParentLeaseID != "" {
		subject["parentLeaseId"] = opts.ParentLeaseID
	}

	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", DelegationLeaseType},
		"issuer":            s.DID(),
		"validFrom":         iso(issued),
		"validUntil":        iso(issued.Add(time.Duration(opts.ValidSeconds) * time.Second)),
		"credentialSubject": subject,
	}
	return s.AttachProof(cred)
}

// VerifyLeaseOptions configures VerifyDelegationLease. A zero Now uses the current
// time; a nil ParentScope skips the attenuation check.
type VerifyLeaseOptions struct {
	Now         time.Time
	ParentScope map[string]any
}

// VerifyDelegationLease verifies a DelegationLeaseCredential offline: the issuer's
// proof, that the window is current, and (when ParentScope is supplied) that this
// lease's scope attenuates the parent. No network call. Returns (ok, subject).
func VerifyDelegationLease(cred map[string]any, pub ed25519.PublicKey, opts VerifyLeaseOptions) (bool, map[string]any) {
	if !hasType(cred["type"], DelegationLeaseType) {
		return false, nil
	}
	if ok, err := signer.VerifyDataIntegrityProof(cred, pub); err != nil || !ok {
		return false, nil
	}
	if !leaseWindowCurrent(cred, opts.Now) {
		return false, nil
	}

	subject, _ := cred["credentialSubject"].(map[string]any)
	scope, ok := subject["physicalScope"].(map[string]any)
	if !ok {
		return false, nil
	}
	if opts.ParentScope != nil && !Attenuates(opts.ParentScope, scope) {
		return false, nil
	}
	return true, subject
}

// LeasePermitsOptions configures LeasePermits. A zero Now uses the current time.
type LeasePermitsOptions struct {
	Now time.Time
}

// LeasePermits decides whether a verified lease permits a proposed physical action:
// the action must fit the lease scope, and (when the full credential is supplied)
// the window must still be current. Pass cred = nil to skip the window check.
func LeasePermits(subject map[string]any, action PhysicalAction, cred map[string]any, opts LeasePermitsOptions) bool {
	if cred != nil && !leaseWindowCurrent(cred, opts.Now) {
		return false
	}
	scope, _ := subject["physicalScope"].(map[string]any)
	return CheckPhysicalAction(scope, action).OK
}

// leaseWindowCurrent reports whether the moment falls inside the credential's
// validFrom and validUntil window.
func leaseWindowCurrent(cred map[string]any, now time.Time) bool {
	moment := now
	if moment.IsZero() {
		moment = time.Now().UTC()
	}
	moment = moment.UTC()

	if vf, ok := cred["validFrom"].(string); ok && vf != "" {
		t, err := parseISO(vf)
		if err != nil || moment.Before(t) {
			return false
		}
	}
	if vu, ok := cred["validUntil"].(string); ok && vu != "" {
		t, err := parseISO(vu)
		if err != nil || moment.After(t) {
			return false
		}
	}
	return true
}

func parseISO(s string) (time.Time, error) {
	return time.Parse("2006-01-02T15:04:05Z", s)
}
