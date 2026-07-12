// Physical quorum (Phase 5.x), Go.
//
// Mirrors vouch/robotics/physical_quorum.py and the TypeScript SDK. A physical
// quorum is a cryptographic two-person rule for high-consequence robot acts. Some
// physical actions are serious enough that no single authority should be able to
// order them alone: applying large force near a person, entering a restricted
// area, an irreversible cut or weld. A physical quorum requires M approvals out of
// a set of N approvers before the action is authorized. Each approver signs an
// approval over the same action, and the action is authorized only when at least
// the threshold number of distinct, valid approvers from the set have approved it.
//
// This is the open layer: a plain M-of-N over distinct approvers.
package robotics

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"sort"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// Physical-quorum constants.
const (
	ActionApprovalType = "PhysicalActionApprovalCredential"
	Approve            = "approve"
	Reject             = "reject"
)

// BuildApprovalOptions configures BuildActionApproval. An empty Decision defaults
// to Approve; a zero ValidFrom uses now; a zero ValidSeconds omits validUntil.
type BuildApprovalOptions struct {
	ActionID     string
	RobotDID     string
	Decision     string
	ValidSeconds int
	ValidFrom    time.Time
}

// BuildActionApproval builds a signed approval (or rejection) by one approver for a
// specific physical action, identified by ActionID, that RobotDID would perform.
func BuildActionApproval(approver *signer.Signer, opts BuildApprovalOptions) (map[string]any, error) {
	decision := opts.Decision
	if decision == "" {
		decision = Approve
	}
	if decision != Approve && decision != Reject {
		return nil, errors.New("robotics: decision must be 'approve' or 'reject', got " + decision)
	}
	if opts.ActionID == "" {
		return nil, errors.New("robotics: action_id is required")
	}

	issued := opts.ValidFrom
	if issued.IsZero() {
		issued = time.Now().UTC()
	}

	subject := map[string]any{
		"id":       approver.DID(),
		"actionId": opts.ActionID,
		"robotDid": opts.RobotDID,
		"decision": decision,
	}
	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", ActionApprovalType},
		"issuer":            approver.DID(),
		"validFrom":         iso(issued),
		"credentialSubject": subject,
	}
	if opts.ValidSeconds > 0 {
		cred["validUntil"] = iso(issued.Add(time.Duration(opts.ValidSeconds) * time.Second))
	}
	return approver.AttachProof(cred)
}

// VerifyAuthorizationOptions configures VerifyActionAuthorization. ApproverKeys maps
// an approver DID to its Ed25519 public-key JWK (a map[string]any with an "x"
// field) or directly to an ed25519.PublicKey. A nil ApproverSet skips the
// set-membership check; a zero Now uses the current time.
type VerifyAuthorizationOptions struct {
	ActionID     string
	RobotDID     string
	ApproverKeys map[string]any
	Threshold    int
	ApproverSet  map[string]bool
	Now          time.Time
}

// VerifyActionAuthorization verifies that a high-consequence physical action is
// authorized by a quorum.
//
// Each approval must be the right type, carry an in-date proof signed by the
// approver's key (looked up in ApproverKeys by issuer DID), match ActionID and
// RobotDID, and carry an approve decision. When ApproverSet is supplied, the
// approver must be in it. The action is authorized when at least Threshold DISTINCT
// valid approvers have approved. A single approver counts once even if it submits
// several approvals. Returns (authorized, sorted list of the distinct approving
// DIDs).
func VerifyActionAuthorization(approvals []map[string]any, opts VerifyAuthorizationOptions) (bool, []string, error) {
	if opts.Threshold < 1 {
		return false, nil, errors.New("robotics: threshold must be at least 1")
	}

	moment := opts.Now
	if moment.IsZero() {
		moment = time.Now().UTC()
	}
	moment = moment.UTC()

	approvers := map[string]bool{}
	for _, approval := range approvals {
		if !hasType(approval["type"], ActionApprovalType) {
			continue
		}
		subject, _ := approval["credentialSubject"].(map[string]any)
		issuer, _ := approval["issuer"].(string)
		if subject["actionId"] != opts.ActionID || subject["robotDid"] != opts.RobotDID {
			continue
		}
		if subject["decision"] != Approve {
			continue
		}
		if opts.ApproverSet != nil && !opts.ApproverSet[issuer] {
			continue
		}
		keyEntry, ok := opts.ApproverKeys[issuer]
		if !ok {
			continue
		}
		if !quorumWindowCurrent(approval, moment) {
			continue
		}

		pub, ok := coerceEd25519(keyEntry)
		if !ok {
			continue
		}
		if vok, err := signer.VerifyDataIntegrityProof(approval, pub); err != nil || !vok {
			continue
		}

		approvers[issuer] = true
	}

	out := make([]string, 0, len(approvers))
	for did := range approvers {
		out = append(out, did)
	}
	sort.Strings(out)
	return len(approvers) >= opts.Threshold, out, nil
}

// coerceEd25519 resolves an approver key entry, which may be an Ed25519 public-key
// JWK (map with a base64url "x" field) or an ed25519.PublicKey, to raw key bytes.
func coerceEd25519(entry any) (ed25519.PublicKey, bool) {
	switch v := entry.(type) {
	case ed25519.PublicKey:
		if len(v) == ed25519.PublicKeySize {
			return v, true
		}
	case []byte:
		if len(v) == ed25519.PublicKeySize {
			return ed25519.PublicKey(v), true
		}
	case map[string]any:
		x, _ := v["x"].(string)
		if x == "" {
			return nil, false
		}
		raw, err := base64.RawURLEncoding.DecodeString(x)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, false
		}
		return ed25519.PublicKey(raw), true
	}
	return nil, false
}

func quorumWindowCurrent(cred map[string]any, moment time.Time) bool {
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
