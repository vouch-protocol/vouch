// Package robotics ports the Vouch robotics primitives to Go, byte-identical
// with the Python vouch.robotics package and the TypeScript SDK. This file
// covers hardware-rooted robot identity (Phase 5.1): a RobotIdentityCredential
// is an eddsa-jcs-2022 VC whose subject carries make, model, serial, a lifecycle
// history, and a hardwareRoot block. The hardware root signs a binding over
// (robot DID, robot key), so the software identity key is provably bound to a
// specific piece of hardware. Verification checks both the credential proof and
// the hardware attestation.
package robotics

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

const (
	vcContextV2       = "https://www.w3.org/ns/credentials/v2"
	vouchContextV1    = "https://vouch-protocol.com/contexts/v1"
	RobotIdentityType = "RobotIdentityCredential"
)

// HardwareRootOfTrust is a hardware-resident key that attests the robot's
// software identity key. A TPM or secure-element backend satisfies it.
type HardwareRootOfTrust interface {
	Kind() string
	PublicKeyRaw() []byte
	Sign(data []byte) []byte
	PublicKeyMultibase() (string, error)
}

// SoftwareRootOfTrust is the reference root backed by a local Ed25519 key. It
// stands in for a TPM or secure element in development and tests. NOT a hardware
// root: a real deployment MUST use a hardware-backed implementation.
type SoftwareRootOfTrust struct {
	priv ed25519.PrivateKey
	kind string
}

// NewSoftwareRoot builds a SoftwareRootOfTrust. A nil seed generates a fresh
// key; a non-nil seed must be 32 bytes. An empty kind defaults to "Software".
func NewSoftwareRoot(seed []byte, kind string) (*SoftwareRootOfTrust, error) {
	if kind == "" {
		kind = "Software"
	}
	var priv ed25519.PrivateKey
	if seed != nil {
		if len(seed) != ed25519.SeedSize {
			return nil, errors.New("robotics: Ed25519 seed must be 32 bytes")
		}
		priv = ed25519.NewKeyFromSeed(seed)
	} else {
		_, p, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, err
		}
		priv = p
	}
	return &SoftwareRootOfTrust{priv: priv, kind: kind}, nil
}

func (r *SoftwareRootOfTrust) Kind() string            { return r.kind }
func (r *SoftwareRootOfTrust) PublicKeyRaw() []byte    { return r.priv.Public().(ed25519.PublicKey) }
func (r *SoftwareRootOfTrust) Sign(data []byte) []byte { return ed25519.Sign(r.priv, data) }
func (r *SoftwareRootOfTrust) PublicKeyMultibase() (string, error) {
	return signer.EncodeEd25519Public(r.PublicKeyRaw())
}

func mb64(b []byte) string {
	return "u" + base64.RawURLEncoding.EncodeToString(b)
}

func unmb64(s string) ([]byte, error) {
	if len(s) == 0 || s[0] != 'u' {
		return nil, errors.New("robotics: expected multibase 'u' prefix")
	}
	return base64.RawURLEncoding.DecodeString(s[1:])
}

// bindingBytes returns the canonical bytes the hardware root signs to bind the
// identity key.
func bindingBytes(robotDID, robotKeyMultibase string) ([]byte, error) {
	return signer.Canonicalize(map[string]any{"key": robotKeyMultibase, "robotDid": robotDID})
}

func iso(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// MintOptions configures MintRobotIdentity.
type MintOptions struct {
	Make         string
	Model        string
	Serial       string
	Owner        string           // optional; "" omits the field
	Lifecycle    []map[string]any // optional; nil uses a default "commissioned" entry
	ValidSeconds int              // 0 omits validUntil
	ValidFrom    time.Time        // zero uses now
}

// MintRobotIdentity mints a hardware-attested RobotIdentityCredential. The robot
// self-issues with its Vouch key (robotSigner); the hardware root signs a
// binding over the robot DID and key, embedded as hardwareRoot.attestation.
func MintRobotIdentity(robotSigner *signer.Signer, root HardwareRootOfTrust, opts MintOptions) (map[string]any, error) {
	robotDID := robotSigner.DID()
	robotKeyMB, err := robotSigner.PublicKeyMultikey()
	if err != nil {
		return nil, err
	}
	binding, err := bindingBytes(robotDID, robotKeyMB)
	if err != nil {
		return nil, err
	}
	attestation := root.Sign(binding)
	rootMB, err := root.PublicKeyMultibase()
	if err != nil {
		return nil, err
	}

	issued := opts.ValidFrom
	if issued.IsZero() {
		issued = time.Now().UTC()
	}

	lifecycle := opts.Lifecycle
	if lifecycle == nil {
		lifecycle = []map[string]any{{"event": "commissioned", "timestamp": iso(issued)}}
	}
	lifecycleAny := make([]any, len(lifecycle))
	for i, e := range lifecycle {
		lifecycleAny[i] = e
	}

	subject := map[string]any{
		"id":     robotDID,
		"make":   opts.Make,
		"model":  opts.Model,
		"serial": opts.Serial,
		"hardwareRoot": map[string]any{
			"kind":               root.Kind(),
			"publicKeyMultibase": rootMB,
			"attestation":        mb64(attestation),
		},
		"lifecycle": lifecycleAny,
	}
	if opts.Owner != "" {
		subject["owner"] = opts.Owner
	}

	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", RobotIdentityType},
		"issuer":            robotDID,
		"validFrom":         iso(issued),
		"credentialSubject": subject,
	}
	if opts.ValidSeconds > 0 {
		cred["validUntil"] = iso(issued.Add(time.Duration(opts.ValidSeconds) * time.Second))
	}
	return robotSigner.AttachProof(cred)
}

// VerifyRobotIdentity verifies a RobotIdentityCredential: the credential proof
// (robot key) AND the hardware-root attestation binding the robot key to the
// hardware. Returns (ok, credentialSubject).
//
// The credential proof is verified by shape, so a robot credential signed with
// SignPq (a proof set) verifies here too. Pass the robot's ML-DSA-44 public
// key, raw bytes or a Multikey string, as the trailing optional argument to
// check one; without it a post-quantum credential is reported invalid rather
// than passing on its Ed25519 proof alone.
func VerifyRobotIdentity(cred map[string]any, robotPub ed25519.PublicKey, mldsa44PublicKey ...any) (bool, map[string]any) {
	if !hasType(cred["type"], RobotIdentityType) {
		return false, nil
	}

	var mlPub *mldsa44.PublicKey
	if len(mldsa44PublicKey) > 0 && mldsa44PublicKey[0] != nil {
		resolved, err := coerceMLDSA44Public(mldsa44PublicKey[0])
		if err != nil {
			return false, nil
		}
		mlPub = resolved
	}

	ok, err := signer.VerifyProof(cred, robotPub, mlPub)
	if err != nil || !ok {
		return false, nil
	}

	subject, _ := cred["credentialSubject"].(map[string]any)
	hw, _ := subject["hardwareRoot"].(map[string]any)
	hwMB, _ := hw["publicKeyMultibase"].(string)
	att, _ := hw["attestation"].(string)
	if hwMB == "" || att == "" {
		return false, nil
	}

	alg, hwRaw, err := signer.MultikeyDecode(hwMB)
	if err != nil || alg != "Ed25519" || len(hwRaw) != ed25519.PublicKeySize {
		return false, nil
	}
	attBytes, err := unmb64(att)
	if err != nil {
		return false, nil
	}
	robotKeyMB, err := signer.EncodeEd25519Public(robotPub)
	if err != nil {
		return false, nil
	}
	id, _ := subject["id"].(string)
	binding, err := bindingBytes(id, robotKeyMB)
	if err != nil {
		return false, nil
	}
	if !ed25519.Verify(ed25519.PublicKey(hwRaw), binding, attBytes) {
		return false, nil
	}
	return true, subject
}

func hasType(field any, want string) bool {
	switch v := field.(type) {
	case string:
		return v == want
	case []any:
		for _, t := range v {
			if s, ok := t.(string); ok && s == want {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if s == want {
				return true
			}
		}
	}
	return false
}
