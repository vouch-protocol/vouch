// Robot-to-infrastructure bounded trust: authenticate a robot to physical
// resources, Go.
//
// Mirrors vouch/robotics/access.py and the other SDKs. A robot in a warehouse,
// hospital, or building needs to open doors, call elevators, dock at chargers,
// and operate machines. This gives it a bounded, revocable, auditable way to do
// so. The infrastructure operator issues an access grant naming a resource, the
// permitted operations, an optional zone, and a time window, signed by the
// operator. The robot presents a signed access request for a specific operation
// on a specific resource, and the resource authorizes it offline: the grant must
// be valid and operator-signed, the request valid and robot-signed, the
// operation permitted, and the moment inside the window. The grant plus the
// request is a tamper-evident, attributable record of the access.
//
// This is the open layer: signed grants and requests, an offline authorize
// decision, shrink-only attenuation, and the audit record. Hardware-enforced
// actuation in the resource and managed fleet access-policy orchestration are out
// of scope for the open layer.
package robotics

import (
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// AccessGrantType is the infrastructure access grant credential type.
const AccessGrantType = "InfrastructureAccessGrant"

// AccessRequestType is the infrastructure access request credential type.
const AccessRequestType = "InfrastructureAccessRequest"

// ---------------------------------------------------------------------------
// Access grant (operator -> robot)
// ---------------------------------------------------------------------------

// BuildAccessGrantOptions configures BuildAccessGrant. An empty Zone omits the
// field; a zero GrantedAt uses now.
type BuildAccessGrantOptions struct {
	RobotDID     string
	Resource     string
	Operations   []string
	Zone         string
	ValidSeconds int
	GrantedAt    time.Time
}

// BuildAccessGrant builds a signed access grant: the infrastructure operator
// grants RobotDID permission to perform Operations on Resource (optionally within
// Zone) for ValidSeconds. Signed by the operator. The issuer is the operator DID.
func BuildAccessGrant(operatorSigner *signer.Signer, opts BuildAccessGrantOptions) (map[string]any, error) {
	if opts.RobotDID == "" || opts.Resource == "" {
		return nil, errors.New("robotics: robot_did and resource are required")
	}
	if len(opts.Operations) == 0 {
		return nil, errors.New("robotics: operations must be a non-empty list")
	}

	issued := opts.GrantedAt
	if issued.IsZero() {
		issued = time.Now().UTC()
	}

	operations := make([]any, len(opts.Operations))
	for i, op := range opts.Operations {
		operations[i] = op
	}
	subject := map[string]any{
		"id":         opts.RobotDID,
		"resource":   opts.Resource,
		"operations": operations,
	}
	if opts.Zone != "" {
		subject["zone"] = opts.Zone
	}

	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", AccessGrantType},
		"issuer":            operatorSigner.DID(),
		"validFrom":         iso(issued),
		"validUntil":        iso(issued.Add(time.Duration(opts.ValidSeconds) * time.Second)),
		"credentialSubject": subject,
	}
	return operatorSigner.AttachProof(cred)
}

// VerifyAccessGrantOptions configures VerifyAccessGrant. A zero Now uses the
// current time.
type VerifyAccessGrantOptions struct {
	Now time.Time
}

// VerifyAccessGrant verifies an access grant: the operator's proof and that the
// grant is within its validity window at Now. Returns (ok, subject).
func VerifyAccessGrant(grant map[string]any, operatorPub ed25519.PublicKey, opts VerifyAccessGrantOptions) (bool, map[string]any) {
	ok, subject := verifyTyped(grant, operatorPub, AccessGrantType)
	if !ok {
		return false, nil
	}
	resource, _ := subject["resource"].(string)
	operations, _ := subject["operations"].([]any)
	if resource == "" || len(operations) == 0 {
		return false, nil
	}
	if !withinWindow(grant, opts.Now) {
		return false, nil
	}
	return true, subject
}

// ---------------------------------------------------------------------------
// Access request (robot) + authorize decision (resource, offline)
// ---------------------------------------------------------------------------

// BuildAccessRequestOptions configures BuildAccessRequest. A zero RequestedAt
// uses now.
type BuildAccessRequestOptions struct {
	RobotDID    string
	Resource    string
	Operation   string
	RequestedAt time.Time
}

// BuildAccessRequest builds a signed access request: the robot requests to
// perform Operation on Resource. Signed by the robot. The issuer is RobotDID.
func BuildAccessRequest(robotSigner *signer.Signer, opts BuildAccessRequestOptions) (map[string]any, error) {
	if opts.RobotDID == "" || opts.Resource == "" || opts.Operation == "" {
		return nil, errors.New("robotics: robot_did, resource, and operation are required")
	}

	issued := opts.RequestedAt
	if issued.IsZero() {
		issued = time.Now().UTC()
	}

	subject := map[string]any{
		"id":        opts.RobotDID,
		"resource":  opts.Resource,
		"operation": opts.Operation,
	}
	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", AccessRequestType},
		"issuer":            opts.RobotDID,
		"validFrom":         iso(issued),
		"credentialSubject": subject,
	}
	return robotSigner.AttachProof(cred)
}

// AuthorizeResult is the outcome of an offline access authorization: ok plus any
// reasons it failed.
type AuthorizeResult struct {
	Ok      bool
	Reasons []string
}

// AuthorizeAccessOptions configures AuthorizeAccess. A zero Now uses the current
// time.
type AuthorizeAccessOptions struct {
	Now time.Time
}

// AuthorizeAccess decides, offline, whether to allow the requested access. The
// grant must verify under the operator's key and be in window, the request must
// verify under the robot's key, the grant and request must name the same robot
// and resource, and the requested operation must be permitted by the grant.
// Returns an AuthorizeResult with the reasons for any refusal.
func AuthorizeAccess(grant, request map[string]any, operatorPub, robotPub ed25519.PublicKey, opts AuthorizeAccessOptions) AuthorizeResult {
	reasons := []string{}

	grantOK, grantSubject := VerifyAccessGrant(grant, operatorPub, VerifyAccessGrantOptions{Now: opts.Now})
	if !grantOK {
		reasons = append(reasons, "grant invalid or out of window")
		return AuthorizeResult{Ok: false, Reasons: reasons}
	}

	reqOK, reqSubject := verifyTyped(request, robotPub, AccessRequestType)
	reqIssuer, _ := request["issuer"].(string)
	reqID, _ := reqSubject["id"].(string)
	if !reqOK || reqIssuer != reqID {
		reasons = append(reasons, "request invalid")
		return AuthorizeResult{Ok: false, Reasons: reasons}
	}

	grantID, _ := grantSubject["id"].(string)
	if grantID != reqID {
		reasons = append(reasons, "grant and request name different robots")
	}
	grantResource, _ := grantSubject["resource"].(string)
	reqResource, _ := reqSubject["resource"].(string)
	if grantResource != reqResource {
		reasons = append(reasons, "grant and request name different resources")
	}
	if !operationPermitted(reqSubject["operation"], grantSubject["operations"]) {
		reasons = append(reasons, "operation not permitted by the grant")
	}

	return AuthorizeResult{Ok: len(reasons) == 0, Reasons: reasons}
}

// ---------------------------------------------------------------------------
// Attenuation (a sub-grant may only narrow)
// ---------------------------------------------------------------------------

// AttenuatesGrant reports whether child is a valid attenuation of parent: the
// same resource, a subset of the operations, and the same zone (or the parent had
// no zone). A sub-grant may only narrow, never widen, the access it inherits.
func AttenuatesGrant(parent, child map[string]any) bool {
	p, _ := parent["credentialSubject"].(map[string]any)
	c, _ := child["credentialSubject"].(map[string]any)

	pResource, _ := p["resource"].(string)
	cResource, _ := c["resource"].(string)
	if pResource != cResource {
		return false
	}
	if !operationsSubset(c["operations"], p["operations"]) {
		return false
	}
	pZone, pHasZone := p["zone"].(string)
	if pHasZone && pZone != "" {
		cZone, _ := c["zone"].(string)
		if cZone != pZone {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// withinWindow reports whether the moment falls inside the credential's validFrom
// and validUntil window. An absent or unparsable bound is treated as no
// constraint.
func withinWindow(cred map[string]any, now time.Time) bool {
	moment := now
	if moment.IsZero() {
		moment = time.Now().UTC()
	}
	moment = moment.UTC()

	if vf, ok := cred["validFrom"].(string); ok && vf != "" {
		if start, err := parseISO(vf); err == nil && moment.Before(start) {
			return false
		}
	}
	if vu, ok := cred["validUntil"].(string); ok && vu != "" {
		if end, err := parseISO(vu); err == nil && moment.After(end) {
			return false
		}
	}
	return true
}

// operationPermitted reports whether the requested operation is one of the
// operations named by the grant.
func operationPermitted(operation any, granted any) bool {
	want, ok := operation.(string)
	if !ok {
		return false
	}
	list, _ := granted.([]any)
	for _, op := range list {
		if s, _ := op.(string); s == want {
			return true
		}
	}
	return false
}

// operationsSubset reports whether every operation in child is also in parent.
func operationsSubset(child any, parent any) bool {
	childList, _ := child.([]any)
	parentList, _ := parent.([]any)
	parentSet := make(map[string]struct{}, len(parentList))
	for _, op := range parentList {
		if s, ok := op.(string); ok {
			parentSet[s] = struct{}{}
		}
	}
	for _, op := range childList {
		s, ok := op.(string)
		if !ok {
			return false
		}
		if _, ok := parentSet[s]; !ok {
			return false
		}
	}
	return true
}
