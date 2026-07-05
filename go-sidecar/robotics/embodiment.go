// Cross-embodiment identity continuity: one accountable agent across robot
// bodies, Go.
//
// Mirrors vouch/robotics/embodiment.py and the TypeScript SDK. An AI agent (a
// "mind": a policy with its own Vouch identity) can run on one robot body today
// and a different body tomorrow. This makes that continuous and accountable. An
// embodiment credential binds the agent identity to a specific body (a
// hardware-rooted robot identity) and that body's hardware root for a period,
// signed by the agent's own persistent key. Linking each embodiment to the
// previous forms a continuity chain a verifier walks to confirm the same
// accountable agent persisted across bodies, re-binding to each body's hardware
// root as it moved. A fork check confirms the agent was never actively embodied
// in two bodies at once.
//
// This is the inverse of the ownership custody chain: there one body passes
// between owners; here one mind passes between bodies, and the constant that
// signs every link is the agent identity itself.
//
// This is the open layer: plain signed embodiment credentials, continuity-chain
// verification, and software fork detection. Managed key custody and fleet-scale
// migration are out of scope for the open layer.
package robotics

import (
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// EmbodimentType is the embodiment credential type.
const EmbodimentType = "AgentEmbodimentCredential"

// ---------------------------------------------------------------------------
// Embodiment credential + continuity chain
// ---------------------------------------------------------------------------

// BuildEmbodimentOptions configures BuildEmbodiment. An empty FromBody omits the
// field (set it when linking to the body the agent left); a zero EmbodiedAt uses
// now; a zero ValidSeconds omits validUntil.
type BuildEmbodimentOptions struct {
	AgentDID         string
	BodyDID          string
	BodyHardwareRoot string
	FromBody         string
	EmbodiedAt       time.Time
	ValidSeconds     int
}

// BuildEmbodiment builds a signed embodiment credential: the agent AgentDID
// authorizes running on BodyDID, re-binding to that body's hardware root
// BodyHardwareRoot. Signed by the agent's own persistent key, so the whole
// continuity chain is signed by one accountable identity. FromBody links this
// embodiment to the body the agent left, forming the chain. ValidSeconds, when
// positive, bounds the active window (used by fork detection).
func BuildEmbodiment(agentSigner *signer.Signer, opts BuildEmbodimentOptions) (map[string]any, error) {
	if opts.AgentDID == "" || opts.BodyDID == "" || opts.BodyHardwareRoot == "" {
		return nil, errors.New("robotics: agent_did, body_did, and body_hardware_root are required")
	}

	issued := opts.EmbodiedAt
	if issued.IsZero() {
		issued = time.Now().UTC()
	}

	subject := map[string]any{
		"id":               opts.AgentDID,
		"body":             opts.BodyDID,
		"bodyHardwareRoot": opts.BodyHardwareRoot,
	}
	if opts.FromBody != "" {
		subject["fromBody"] = opts.FromBody
	}

	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", EmbodimentType},
		"issuer":            opts.AgentDID,
		"validFrom":         iso(issued),
		"credentialSubject": subject,
	}
	if opts.ValidSeconds > 0 {
		cred["validUntil"] = iso(issued.Add(time.Duration(opts.ValidSeconds) * time.Second))
	}
	return agentSigner.AttachProof(cred)
}

// VerifyEmbodiment verifies an embodiment credential: the agent's proof and that
// the issuer is the agent itself (a mind authorizes its own embodiment), plus
// the presence of body and bodyHardwareRoot. Returns (ok, subject).
func VerifyEmbodiment(cred map[string]any, agentPub ed25519.PublicKey) (bool, map[string]any) {
	ok, subject := verifyTyped(cred, agentPub, EmbodimentType)
	if !ok {
		return false, nil
	}
	body, _ := subject["body"].(string)
	root, _ := subject["bodyHardwareRoot"].(string)
	if body == "" || root == "" {
		return false, nil
	}
	id, _ := subject["id"].(string)
	if iss, _ := cred["issuer"].(string); iss != id {
		return false, nil
	}
	return true, subject
}

// VerifyContinuityChainOptions configures VerifyContinuityChain. An empty
// OriginBody skips the first-fromBody check.
type VerifyContinuityChainOptions struct {
	OriginBody string
}

// VerifyContinuityChain verifies an ordered list of embodiment credentials forms
// a valid continuity chain for one agent: every link verifies under the SAME
// agent key (the persistent mind), each link's fromBody matches the previous
// link's body, and (when given) the first fromBody is OriginBody. Returns
// (ok, currentBody).
func VerifyContinuityChain(embodiments []map[string]any, agentPub ed25519.PublicKey, opts VerifyContinuityChainOptions) (bool, string) {
	expectedFrom := opts.OriginBody
	currentBody := opts.OriginBody
	for _, embodiment := range embodiments {
		ok, subject := VerifyEmbodiment(embodiment, agentPub)
		if !ok {
			return false, ""
		}
		if expectedFrom != "" {
			if from, _ := subject["fromBody"].(string); from != expectedFrom {
				return false, ""
			}
		}
		currentBody, _ = subject["body"].(string)
		expectedFrom = currentBody
	}
	return true, currentBody
}

// ---------------------------------------------------------------------------
// Fork detection (a mind cannot be actively embodied in two bodies at once)
// ---------------------------------------------------------------------------

// ForkConflict names the two bodies whose active windows overlap.
type ForkConflict struct {
	BodyA string
	BodyB string
}

// CheckNoFork confirms no two embodiments place the agent in different bodies
// with overlapping active windows. Each embodiment is active from validFrom to
// validUntil (a missing validUntil is treated as open-ended). Two embodiments on
// different bodies whose windows overlap are a fork. Returns (ok, conflict) where
// conflict, when non-nil, names the two conflicting bodies.
func CheckNoFork(embodiments []map[string]any) (bool, *ForkConflict) {
	type window struct {
		body    string
		start   time.Time
		end     time.Time
		openEnd bool
	}
	windows := make([]window, 0, len(embodiments))
	for _, embodiment := range embodiments {
		subject, _ := embodiment["credentialSubject"].(map[string]any)
		body, _ := subject["body"].(string)
		startStr, _ := embodiment["validFrom"].(string)
		start, err := parseISO(startStr)
		if body == "" || startStr == "" || err != nil {
			return false, nil
		}
		w := window{body: body, start: start.UTC(), openEnd: true}
		if endStr, ok := embodiment["validUntil"].(string); ok && endStr != "" {
			if end, err := parseISO(endStr); err == nil {
				w.end = end.UTC()
				w.openEnd = false
			}
		}
		windows = append(windows, w)
	}

	for i := 0; i < len(windows); i++ {
		for j := i + 1; j < len(windows); j++ {
			if windows[i].body == windows[j].body {
				continue
			}
			if overlaps(windows[i].start, windows[i].end, windows[i].openEnd,
				windows[j].start, windows[j].end, windows[j].openEnd) {
				return false, &ForkConflict{BodyA: windows[i].body, BodyB: windows[j].body}
			}
		}
	}
	return true, nil
}

// overlaps reports whether two half-open intervals [start, end) overlap, where an
// open end (openEnd true) is +infinity. A clean handover sets one window's end to
// the next window's start, which does not overlap.
func overlaps(startA, endA time.Time, openA bool, startB, endB time.Time, openB bool) bool {
	aBeforeB := !openA && !endA.After(startB)
	bBeforeA := !openB && !endB.After(startA)
	return !(aBeforeB || bBeforeA)
}
