// Physical custody handoff: an accountable chain for a task or object across
// actors, Go.
//
// Mirrors vouch/robotics/custody.py and the other SDKs. A physical task or
// object passes across a chain of actors, human and robot: a person picks an
// item, hands it to a robot, that robot hands it to another robot, which places
// it. Each handoff is a signed custody transition, so a physical-world incident
// (damage, loss, mis-delivery) traces to the exact hop and the actor
// responsible.
//
// A custody handoff credential records that a receiving actor accepted custody
// of a task or object from a releasing actor, signed by the receiver. Linking
// each handoff to the previous forms a chain a verifier walks to establish who
// held the task at any time. A condition attested at each handoff lets a
// physical state change be localized to the specific hop whose holder was
// responsible.
//
// This is the open layer: signed handoff credentials, chain verification, a
// holder-at-time helper, and software condition localization. Managed logistics
// custody orchestration and fleet-scale tracking are out of scope for the open
// layer.
package robotics

import (
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// CustodyHandoffType is the custody handoff credential type.
const CustodyHandoffType = "CustodyHandoffCredential"

// ---------------------------------------------------------------------------
// Handoff credential + custody chain
// ---------------------------------------------------------------------------

// BuildHandoffOptions configures BuildHandoff. An empty Condition omits the
// field; a zero HandoffAt uses now; a zero ValidSeconds omits validUntil.
type BuildHandoffOptions struct {
	TaskID       string
	FromActor    string
	ToActor      string
	Condition    string
	HandoffAt    time.Time
	ValidSeconds int
}

// BuildHandoff builds a signed custody handoff: the receiving actor ToActor
// accepts custody of TaskID from FromActor, signed by the receiver (the party
// taking responsibility). Condition optionally attests the state of the task or
// object as received (for example a status, a quantity, or a hash of an
// inspection), which lets a later state change be localized to a hop. FromActor
// and ToActor may be human or robot DIDs. The issuer is ToActor.
func BuildHandoff(receiverSigner *signer.Signer, opts BuildHandoffOptions) (map[string]any, error) {
	if opts.TaskID == "" || opts.FromActor == "" || opts.ToActor == "" {
		return nil, errors.New("robotics: task_id, from_actor, and to_actor are required")
	}

	issued := opts.HandoffAt
	if issued.IsZero() {
		issued = time.Now().UTC()
	}

	subject := map[string]any{
		"id":        opts.TaskID,
		"fromActor": opts.FromActor,
		"toActor":   opts.ToActor,
	}
	if opts.Condition != "" {
		subject["condition"] = opts.Condition
	}

	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", CustodyHandoffType},
		"issuer":            opts.ToActor,
		"validFrom":         iso(issued),
		"credentialSubject": subject,
	}
	if opts.ValidSeconds > 0 {
		cred["validUntil"] = iso(issued.Add(time.Duration(opts.ValidSeconds) * time.Second))
	}
	return receiverSigner.AttachProof(cred)
}

// VerifyHandoff verifies a custody handoff: the receiver's proof and that the
// issuer is the receiving actor (a party attests its own acceptance of custody),
// plus the presence of fromActor and toActor. Returns (ok, subject).
func VerifyHandoff(cred map[string]any, receiverPub ed25519.PublicKey) (bool, map[string]any) {
	ok, subject := verifyTyped(cred, receiverPub, CustodyHandoffType)
	if !ok {
		return false, nil
	}
	from, _ := subject["fromActor"].(string)
	to, _ := subject["toActor"].(string)
	if from == "" || to == "" {
		return false, nil
	}
	if iss, _ := cred["issuer"].(string); iss != to {
		return false, nil
	}
	return true, subject
}

// VerifyHandoffChainOptions configures VerifyHandoffChain. An empty OriginActor
// skips the first-fromActor check.
type VerifyHandoffChainOptions struct {
	OriginActor string
}

// VerifyHandoffChain verifies an ordered list of handoff credentials forms a
// valid custody chain: each handoff verifies under its receiver's key, every
// link's toActor matches the next link's fromActor, and (when given) the first
// fromActor is OriginActor. publicKeys maps an actor DID (human or robot) to its
// key. Returns (ok, currentHolder).
func VerifyHandoffChain(handoffs []map[string]any, publicKeys map[string]ed25519.PublicKey, opts VerifyHandoffChainOptions) (bool, string) {
	expectedFrom := opts.OriginActor
	currentHolder := opts.OriginActor
	for _, handoff := range handoffs {
		receiver, _ := handoff["issuer"].(string)
		pub, ok := publicKeys[receiver]
		if !ok {
			return false, ""
		}
		ok, subject := VerifyHandoff(handoff, pub)
		if !ok {
			return false, ""
		}
		if expectedFrom != "" {
			if from, _ := subject["fromActor"].(string); from != expectedFrom {
				return false, ""
			}
		}
		currentHolder, _ = subject["toActor"].(string)
		expectedFrom = currentHolder
	}
	return true, currentHolder
}

// ---------------------------------------------------------------------------
// Holder-at-time and condition localization
// ---------------------------------------------------------------------------

// HolderAt returns the actor holding the task at ISO time at: the receiver
// (toActor) of the most recent handoff whose handoff time is at or before at.
// Returns "" if no handoff had occurred yet or at is unparsable. handoffs is
// assumed in chain order.
func HolderAt(handoffs []map[string]any, at string) string {
	when, err := parseISO(at)
	if err != nil {
		return ""
	}
	holder := ""
	for _, handoff := range handoffs {
		startStr, _ := handoff["validFrom"].(string)
		subject, _ := handoff["credentialSubject"].(map[string]any)
		start, err := parseISO(startStr)
		if err == nil && !start.After(when) {
			holder, _ = subject["toActor"].(string)
		}
	}
	return holder
}

// ConditionChange names the hop where the attested condition changed and the
// holder responsible for it.
type ConditionChange struct {
	ResponsibleHolder string
	FromCondition     string
	ToCondition       string
}

// LocateConditionChange finds the first hop where the attested condition differs
// from the previous handoff. The holder responsible for the change is the actor
// who held the task during it (the previous handoff's receiver). Returns a
// *ConditionChange, or nil if the condition never changed. Handoffs without a
// condition are skipped for the comparison.
func LocateConditionChange(handoffs []map[string]any) *ConditionChange {
	prevCondition := ""
	prevHolder := ""
	havePrev := false
	for _, handoff := range handoffs {
		subject, _ := handoff["credentialSubject"].(map[string]any)
		condition, ok := subject["condition"].(string)
		if !ok {
			continue
		}
		if havePrev && condition != prevCondition {
			return &ConditionChange{
				ResponsibleHolder: prevHolder,
				FromCondition:     prevCondition,
				ToCondition:       condition,
			}
		}
		prevCondition = condition
		prevHolder, _ = subject["toActor"].(string)
		havePrev = true
	}
	return nil
}
