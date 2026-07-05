// Bystander-consent evidence for robot capture, Go.
//
// Mirrors vouch/robotics/consent.py and the other SDKs. A robot working in a
// shared or public space captures people incidentally through its cameras and
// microphones. This lets the robot record, at capture time, the basis on which a
// capture was permitted, bound to the specific capture and to the robot's
// identity, and lets a bystander (or their device) sign a consent token bound to
// that one capture. Only hashes and a consent basis are stored, never an image or
// a bystander's identifying data, so the evidence is verifiable without retaining
// anyone's biometrics.
//
// A bystander consent token is signed by the bystander over the hash of the
// capture and the robot's DID, so it verifies only against the capture it was
// given for and cannot be replayed to a different recording. A bystander-consent
// evidence credential is signed by the robot, binding the capture hash to a
// consent basis (an explicit token, posted notice, a legitimate interest, or a
// redaction that was applied) and, when the basis is explicit consent, to the
// tokens that cover it.
//
// This is the open layer: the cryptographic binding of a consent basis to a
// capture, and its verification, holding only hashes. On-device biometric
// detection and redaction, and managed consent-registry orchestration, are out of
// scope for the open layer.
package robotics

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// ConsentEvidenceType is the bystander-consent evidence credential type.
const ConsentEvidenceType = "BystanderConsentEvidence"

// ConsentTokenType is the bystander consent token credential type.
const ConsentTokenType = "BystanderConsentToken"

// ConsentBases are the accepted consent bases. Implementers MAY use additional
// values, but these are the interoperable set a verifier can rely on.
var ConsentBases = []string{
	"explicit-consent",
	"posted-notice",
	"legitimate-interest",
	"redacted",
}

// HashCapture returns the multibase (base64url) SHA-256 of a raw capture.
func HashCapture(capture []byte) string {
	sum := sha256.Sum256(capture)
	return mb64(sum[:])
}

// ---------------------------------------------------------------------------
// Bystander consent token (signed by the bystander, bound to one capture)
// ---------------------------------------------------------------------------

// BuildConsentTokenOptions configures BuildConsentToken. An empty Scope omits the
// field; a zero GrantedAt uses now; a zero ValidSeconds omits validUntil.
type BuildConsentTokenOptions struct {
	BystanderDID string
	CaptureHash  string
	RobotDID     string
	Scope        string
	GrantedAt    time.Time
	ValidSeconds int
}

// BuildConsentToken builds a signed BystanderConsentToken: a bystander grants
// consent for a specific capture (named by CaptureHash) by a specific robot
// (RobotDID), signed by the bystander. Binding the token to the capture hash
// means it cannot be replayed to a different recording. Scope optionally records
// what the consent covers. The issuer is BystanderDID.
func BuildConsentToken(bystanderSigner *signer.Signer, opts BuildConsentTokenOptions) (map[string]any, error) {
	if opts.BystanderDID == "" || opts.CaptureHash == "" || opts.RobotDID == "" {
		return nil, errors.New("robotics: bystander_did, capture_hash, and robot_did are required")
	}

	issued := opts.GrantedAt
	if issued.IsZero() {
		issued = time.Now().UTC()
	}

	subject := map[string]any{
		"id":          opts.BystanderDID,
		"captureHash": opts.CaptureHash,
		"robotDid":    opts.RobotDID,
	}
	if opts.Scope != "" {
		subject["scope"] = opts.Scope
	}

	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", ConsentTokenType},
		"issuer":            opts.BystanderDID,
		"validFrom":         iso(issued),
		"credentialSubject": subject,
	}
	if opts.ValidSeconds > 0 {
		cred["validUntil"] = iso(issued.Add(time.Duration(opts.ValidSeconds) * time.Second))
	}
	return bystanderSigner.AttachProof(cred)
}

// VerifyConsentToken verifies a BystanderConsentToken: the bystander's proof,
// that the issuer is the bystander, and that the token is bound to this capture
// and this robot and is within its window. Returns (ok, credentialSubject).
func VerifyConsentToken(token map[string]any, bystanderPub ed25519.PublicKey, captureHash, robotDID string, now time.Time) (bool, map[string]any) {
	ok, subject := verifyTyped(token, bystanderPub, ConsentTokenType)
	if !ok || subject == nil {
		return false, nil
	}
	issuer, _ := token["issuer"].(string)
	id, _ := subject["id"].(string)
	if issuer != id {
		return false, nil
	}
	subjectHash, _ := subject["captureHash"].(string)
	subjectRobot, _ := subject["robotDid"].(string)
	if subjectHash != captureHash || subjectRobot != robotDID {
		return false, nil
	}
	if !withinWindow(token, now) {
		return false, nil
	}
	return true, subject
}

// ---------------------------------------------------------------------------
// Bystander-consent evidence (signed by the robot)
// ---------------------------------------------------------------------------

// BuildConsentEvidenceOptions configures BuildConsentEvidence. ConsentTokens and
// RedactionHash are optional; an empty RedactionHash omits the field. A zero
// AttestedAt and ValidFrom use now; a zero ValidSeconds omits validUntil.
type BuildConsentEvidenceOptions struct {
	RobotDID      string
	CaptureHash   string
	Basis         string
	ConsentTokens []map[string]any // nil omits the refs
	RedactionHash string           // "" omits the field
	AttestedAt    time.Time
	ValidSeconds  int
	ValidFrom     time.Time
}

// BuildConsentEvidence builds a signed BystanderConsentEvidence credential: the
// robot records that a capture (named by CaptureHash) was permitted on Basis, one
// of ConsentBases. When the basis is explicit consent, ConsentTokens are the
// bystander tokens that cover it, and the evidence commits to them by their proof
// value (never embedding a bystander's identifying data). RedactionHash
// optionally records that a redacted output was produced. Signed by the robot.
// The issuer is RobotDID.
func BuildConsentEvidence(robotSigner *signer.Signer, opts BuildConsentEvidenceOptions) (map[string]any, error) {
	if opts.RobotDID == "" || opts.CaptureHash == "" {
		return nil, errors.New("robotics: robot_did and capture_hash are required")
	}
	if !isConsentBasis(opts.Basis) {
		return nil, errors.New("robotics: basis must be one of the accepted consent bases")
	}
	if opts.Basis == "explicit-consent" && len(opts.ConsentTokens) == 0 {
		return nil, errors.New("robotics: explicit-consent basis requires at least one consent token")
	}

	subject := map[string]any{
		"id":          opts.RobotDID,
		"captureHash": opts.CaptureHash,
		"basis":       opts.Basis,
	}
	if len(opts.ConsentTokens) > 0 {
		refs := make([]any, len(opts.ConsentTokens))
		for i, tok := range opts.ConsentTokens {
			ref, err := tokenRef(tok)
			if err != nil {
				return nil, err
			}
			refs[i] = ref
		}
		subject["consentTokenRefs"] = refs
	}
	if opts.RedactionHash != "" {
		subject["redactionHash"] = opts.RedactionHash
	}

	issued := opts.ValidFrom
	if issued.IsZero() {
		issued = opts.AttestedAt
	}
	if issued.IsZero() {
		issued = time.Now().UTC()
	}

	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", ConsentEvidenceType},
		"issuer":            opts.RobotDID,
		"validFrom":         iso(issued),
		"credentialSubject": subject,
	}
	if opts.ValidSeconds > 0 {
		cred["validUntil"] = iso(issued.Add(time.Duration(opts.ValidSeconds) * time.Second))
	}
	return robotSigner.AttachProof(cred)
}

// VerifyConsentEvidenceOptions configures VerifyConsentEvidence. When Capture is
// supplied, its hash must reproduce the attested capture hash. When ConsentTokens
// and BystanderKeys (a map of bystander DID to key) are supplied, every token
// must verify, be bound to this capture and this robot, and match a committed
// reference. A zero Now uses the current time.
type VerifyConsentEvidenceOptions struct {
	Capture       []byte
	ConsentTokens []map[string]any
	BystanderKeys map[string]ed25519.PublicKey
	Now           time.Time
}

// VerifyConsentEvidence verifies a BystanderConsentEvidence credential: the
// robot's proof, that the issuer is the robot, and that the basis is accepted.
// When Capture is supplied, its hash must reproduce the attested capture hash.
// When ConsentTokens and BystanderKeys are supplied, every token must verify, be
// bound to this capture and this robot, and match a committed reference, and an
// explicit-consent evidence must carry at least one token. Returns
// (ok, credentialSubject).
func VerifyConsentEvidence(evidence map[string]any, robotPub ed25519.PublicKey, opts VerifyConsentEvidenceOptions) (bool, map[string]any) {
	ok, subject := verifyTyped(evidence, robotPub, ConsentEvidenceType)
	if !ok || subject == nil {
		return false, nil
	}
	issuer, _ := evidence["issuer"].(string)
	id, _ := subject["id"].(string)
	if issuer != id {
		return false, nil
	}
	basis, _ := subject["basis"].(string)
	if !isConsentBasis(basis) {
		return false, nil
	}
	captureHash, _ := subject["captureHash"].(string)
	if captureHash == "" {
		return false, nil
	}

	if opts.Capture != nil && HashCapture(opts.Capture) != captureHash {
		return false, nil
	}

	refs := toStrSlice(subject["consentTokenRefs"])
	if basis == "explicit-consent" && len(refs) == 0 {
		return false, nil
	}

	if opts.ConsentTokens != nil && opts.BystanderKeys != nil {
		for _, token := range opts.ConsentTokens {
			tokenIssuer, _ := token["issuer"].(string)
			key, keyOK := opts.BystanderKeys[tokenIssuer]
			if !keyOK {
				return false, nil
			}
			tokOK, _ := VerifyConsentToken(token, key, captureHash, id, opts.Now)
			if !tokOK {
				return false, nil
			}
			ref, err := tokenRef(token)
			if err != nil || !containsString(refs, ref) {
				return false, nil
			}
		}
	}

	return true, subject
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// tokenRef returns a privacy-preserving reference to a token: its proof value.
func tokenRef(token map[string]any) (string, error) {
	proof, _ := token["proof"].(map[string]any)
	ref, _ := proof["proofValue"].(string)
	if ref == "" {
		return "", errors.New("robotics: consent token is missing a proof value")
	}
	return ref, nil
}

func isConsentBasis(basis string) bool {
	return containsString(ConsentBases, basis)
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
