// Scannable robot passport (Phase 5.6), Go.
//
// Mirrors vouch/robotics/passport.py and the TypeScript SDK. A compact, signed
// RobotPassport that anyone can scan (QR or NFC) to check a robot's owner,
// authorized actions, certification, and current standing, offline. The QR/NFC
// payload is a vouch-passport: URI carrying the multibase JCS bytes of the
// credential, so an offline reader verifies the signature with no network call.
// The URI encoding is deterministic, so a passport encoded by any language
// decodes and verifies in the others.
package robotics

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// Passport constants.
const (
	RobotPassportType    = "RobotPassport"
	PassportURIScheme    = "vouch-passport:"
	StatusActive         = "active"
	StatusSuspended      = "suspended"
	StatusDecommissioned = "decommissioned"
)

// PassportError is returned for malformed passport URIs.
type PassportError struct{ Msg string }

func (e *PassportError) Error() string { return e.Msg }

// BuildPassportOptions configures BuildPassport.
type BuildPassportOptions struct {
	RobotDID          string
	Make              string
	Model             string
	Owner             string
	AuthorizedActions []string
	Certification     string // "" omits the field
	Status            string // "" defaults to active
	ValidSeconds      int    // 0 omits validUntil
	ValidFrom         time.Time
}

// BuildPassport builds a signed RobotPassport credential (issued by the robot or
// an authority).
func BuildPassport(s *signer.Signer, opts BuildPassportOptions) (map[string]any, error) {
	issued := opts.ValidFrom
	if issued.IsZero() {
		issued = time.Now().UTC()
	}
	status := opts.Status
	if status == "" {
		status = StatusActive
	}
	subject := map[string]any{
		"id":                opts.RobotDID,
		"make":              opts.Make,
		"model":             opts.Model,
		"owner":             opts.Owner,
		"authorizedActions": strsToAny(opts.AuthorizedActions),
		"status":            status,
	}
	if opts.Certification != "" {
		subject["certification"] = opts.Certification
	}
	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", RobotPassportType},
		"issuer":            s.DID(),
		"validFrom":         iso(issued),
		"credentialSubject": subject,
	}
	if opts.ValidSeconds > 0 {
		cred["validUntil"] = iso(issued.Add(time.Duration(opts.ValidSeconds) * time.Second))
	}
	return s.AttachProof(cred)
}

// EncodePassport encodes a passport into a compact vouch-passport: URI for a QR
// or NFC tag.
func EncodePassport(passport map[string]any) (string, error) {
	canon, err := signer.Canonicalize(passport)
	if err != nil {
		return "", err
	}
	return PassportURIScheme + mb64(canon), nil
}

// DecodePassport decodes a vouch-passport: URI back into the passport credential.
func DecodePassport(uri string) (map[string]any, error) {
	if !strings.HasPrefix(uri, PassportURIScheme) {
		return nil, &PassportError{"not a " + PassportURIScheme + " URI"}
	}
	body := uri[len(PassportURIScheme):]
	raw, err := unmb64(body)
	if err != nil {
		return nil, &PassportError{"expected multibase 'u' payload"}
	}
	var p map[string]any
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, &PassportError{"passport decode failed: " + err.Error()}
	}
	return p, nil
}

// PassportSummary is the human-readable result of a successful verification.
type PassportSummary struct {
	Robot             string
	Make              string
	Model             string
	Owner             string
	AuthorizedActions []string
	Certification     string
	Status            string
}

// VerifyPassport verifies a passport credential object. A suspended or
// decommissioned status still verifies but is surfaced in the summary so a
// scanner can refuse cooperation; an expired passport fails. A zero now uses the
// current time.
func VerifyPassport(passport map[string]any, publicKey ed25519.PublicKey, now time.Time) (bool, *PassportSummary) {
	if !hasType(passport["type"], RobotPassportType) {
		return false, nil
	}
	if ok, err := signer.VerifyDataIntegrityProof(passport, publicKey); err != nil || !ok {
		return false, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if vu, _ := passport["validUntil"].(string); vu != "" {
		if t, err := time.Parse(time.RFC3339, vu); err == nil && now.After(t) {
			return false, nil
		}
	}

	s, _ := passport["credentialSubject"].(map[string]any)
	robot, _ := s["id"].(string)
	mk, _ := s["make"].(string)
	model, _ := s["model"].(string)
	owner, _ := s["owner"].(string)
	cert, _ := s["certification"].(string)
	status, _ := s["status"].(string)
	return true, &PassportSummary{
		Robot:             robot,
		Make:              mk,
		Model:             model,
		Owner:             owner,
		AuthorizedActions: toStrSlice(s["authorizedActions"]),
		Certification:     cert,
		Status:            status,
	}
}

// VerifyPassportURI decodes a vouch-passport: URI and verifies it. Returns
// (false, nil) if the URI is malformed.
func VerifyPassportURI(uri string, publicKey ed25519.PublicKey, now time.Time) (bool, *PassportSummary) {
	p, err := DecodePassport(uri)
	if err != nil {
		return false, nil
	}
	return VerifyPassport(p, publicKey, now)
}
