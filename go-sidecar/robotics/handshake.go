// Robot-to-robot trust handshake (Phase 5.4), Go.
//
// Mirrors vouch/robotics/handshake.py and the TypeScript SDK. Two robots in
// different trust domains authenticate and establish a bounded-trust session via
// three signed messages (HELLO, ACCEPT, CONFIRM). The session scope is the
// intersection of what each side offers, never the union, and the responder
// checks the initiator's domain against its trust policy. Each message is an
// eddsa-jcs-2022 signed object, so authentication reuses the shared signer and
// verifier and is interoperable with Python and TypeScript.
package robotics

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// Handshake message types.
const (
	HELLO   = "handshake_hello"
	ACCEPT  = "handshake_accept"
	CONFIRM = "handshake_confirm"
)

// HandshakeError is returned when a handshake step fails (untrusted peer, bad
// signature, malformed message).
type HandshakeError struct{ Msg string }

func (e *HandshakeError) Error() string { return e.Msg }

func handshakeErr(format string, a ...any) error {
	return &HandshakeError{Msg: fmt.Sprintf(format, a...)}
}

// TrustPolicy decides whether a peer DID is trusted. A peer is trusted when its
// did:web domain is in TrustedDomains, or when AcceptUnknown is set.
type TrustPolicy struct {
	TrustedDomains map[string]bool
	AcceptUnknown  bool
}

// NewTrustPolicy builds a TrustPolicy from a list of allowed did:web domains.
func NewTrustPolicy(domains []string, acceptUnknown bool) *TrustPolicy {
	set := make(map[string]bool, len(domains))
	for _, d := range domains {
		set[d] = true
	}
	return &TrustPolicy{TrustedDomains: set, AcceptUnknown: acceptUnknown}
}

// IsTrusted reports whether the given DID is trusted under this policy.
func (p *TrustPolicy) IsTrusted(did string) bool {
	if p.AcceptUnknown {
		return true
	}
	d, ok := didWebDomain(did)
	return ok && p.TrustedDomains[d]
}

// BoundedSession is the agreed cooperation session after a successful handshake.
type BoundedSession struct {
	SessionID  string
	Initiator  string
	Responder  string
	Scope      []string
	Nonce      string
	ValidUntil string
}

func didWebDomain(did string) (string, bool) {
	const prefix = "did:web:"
	if !strings.HasPrefix(did, prefix) {
		return "", false
	}
	rest := did[len(prefix):]
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		return "", false
	}
	return rest, true
}

func strsToAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func uuidV4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// BuildHelloOptions configures BuildHello.
type BuildHelloOptions struct {
	ProposedScope []string
	Nonce         string // "" generates a fresh 16-byte hex nonce
	PeerDID       string // "" leaves "to" as null
}

// BuildHello opens the handshake (initiator A) with a proposed scope and a fresh
// nonce.
func BuildHello(s *signer.Signer, opts BuildHelloOptions) (map[string]any, error) {
	nonce := opts.Nonce
	if nonce == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		nonce = hex.EncodeToString(b)
	}
	var to any // nil marshals to JSON null, matching the TypeScript default
	if opts.PeerDID != "" {
		to = opts.PeerDID
	}
	hello := map[string]any{
		"type":          HELLO,
		"from":          s.DID(),
		"to":            to,
		"nonce":         nonce,
		"proposedScope": strsToAny(opts.ProposedScope),
		"issuedAt":      iso(time.Now().UTC()),
	}
	return s.AttachProof(hello)
}

// BuildAcceptOptions configures BuildAccept.
type BuildAcceptOptions struct {
	Hello          map[string]any
	HelloPublicKey ed25519.PublicKey
	Policy         *TrustPolicy
	OfferedScope   []string
	ValidSeconds   int    // 0 defaults to 300
	SessionID      string // "" generates a urn:uuid
}

// BuildAccept verifies A's HELLO and identity domain, intersects the scope, and
// signs an acceptance (responder B). Returns a HandshakeError if A is untrusted
// or the HELLO is invalid.
func BuildAccept(s *signer.Signer, opts BuildAcceptOptions) (map[string]any, error) {
	if t, _ := opts.Hello["type"].(string); t != HELLO {
		return nil, handshakeErr("not a HELLO message")
	}
	if ok, err := signer.VerifyDataIntegrityProof(opts.Hello, opts.HelloPublicKey); err != nil || !ok {
		return nil, handshakeErr("HELLO signature invalid")
	}
	initiator, _ := opts.Hello["from"].(string)
	if opts.Policy == nil || !opts.Policy.IsTrusted(initiator) {
		return nil, handshakeErr("peer %s is not in this trust domain's policy", initiator)
	}

	offered := make(map[string]bool, len(opts.OfferedScope))
	for _, x := range opts.OfferedScope {
		offered[x] = true
	}
	seen := map[string]bool{}
	var bounded []string
	for _, sc := range toStrSlice(opts.Hello["proposedScope"]) {
		if offered[sc] && !seen[sc] {
			seen[sc] = true
			bounded = append(bounded, sc)
		}
	}
	sort.Strings(bounded)

	sid := opts.SessionID
	if sid == "" {
		u, err := uuidV4()
		if err != nil {
			return nil, err
		}
		sid = "urn:uuid:" + u
	}
	validSeconds := opts.ValidSeconds
	if validSeconds == 0 {
		validSeconds = 300
	}
	validUntil := iso(time.Now().UTC().Add(time.Duration(validSeconds) * time.Second))

	accept := map[string]any{
		"type":         ACCEPT,
		"from":         s.DID(),
		"to":           initiator,
		"sessionId":    sid,
		"nonce":        opts.Hello["nonce"],
		"boundedScope": strsToAny(bounded),
		"validUntil":   validUntil,
	}
	return s.AttachProof(accept)
}

// VerifyAcceptOptions configures VerifyAccept.
type VerifyAcceptOptions struct {
	ExpectedNonce string
	Policy        *TrustPolicy // optional; when set, the responder must be trusted
}

// VerifyAccept verifies B's ACCEPT (initiator A): the signature, that the nonce
// echoes A's HELLO, and optionally that B is trusted. Returns (ok, session).
func VerifyAccept(accept map[string]any, acceptPublicKey ed25519.PublicKey, opts VerifyAcceptOptions) (bool, *BoundedSession) {
	if t, _ := accept["type"].(string); t != ACCEPT {
		return false, nil
	}
	if ok, err := signer.VerifyDataIntegrityProof(accept, acceptPublicKey); err != nil || !ok {
		return false, nil
	}
	if n, _ := accept["nonce"].(string); n != opts.ExpectedNonce {
		return false, nil
	}
	responder, _ := accept["from"].(string)
	if opts.Policy != nil && !opts.Policy.IsTrusted(responder) {
		return false, nil
	}

	initiator, _ := accept["to"].(string)
	sid, _ := accept["sessionId"].(string)
	nonce, _ := accept["nonce"].(string)
	validUntil, _ := accept["validUntil"].(string)
	return true, &BoundedSession{
		SessionID:  sid,
		Initiator:  initiator,
		Responder:  responder,
		Scope:      toStrSlice(accept["boundedScope"]),
		Nonce:      nonce,
		ValidUntil: validUntil,
	}
}

// BuildConfirm signs A's confirmation of the bounded session to B.
func BuildConfirm(s *signer.Signer, session BoundedSession) (map[string]any, error) {
	confirm := map[string]any{
		"type":          CONFIRM,
		"from":          s.DID(),
		"to":            session.Responder,
		"sessionId":     session.SessionID,
		"nonce":         session.Nonce,
		"acceptedScope": strsToAny(session.Scope),
	}
	return s.AttachProof(confirm)
}

// VerifyConfirm verifies A's CONFIRM closes the agreed session (responder B):
// the signature, and that the session id and nonce match what B accepted.
func VerifyConfirm(confirm map[string]any, confirmPublicKey ed25519.PublicKey, sessionID, expectedNonce string) bool {
	if t, _ := confirm["type"].(string); t != CONFIRM {
		return false
	}
	if ok, err := signer.VerifyDataIntegrityProof(confirm, confirmPublicKey); err != nil || !ok {
		return false
	}
	sid, _ := confirm["sessionId"].(string)
	nonce, _ := confirm["nonce"].(string)
	return sid == sessionID && nonce == expectedNonce
}
