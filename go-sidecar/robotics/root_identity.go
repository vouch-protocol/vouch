// Root of Trust for robot identity (Vouch Protocol): bind a hardware-rooted
// robot to a recognized manufacturer, anchored to one pinned Vouch Protocol
// root. Mirrors vouch/robotics/root_identity.py.
//
// The Root of Trust for Machine Identity lets a pinned Vouch root recognize
// issuers, and a recognized issuer bind a subject DID to attributes, verified
// offline against the one pinned root. This extends that to robots. A recognized
// manufacturer (an issuer the root granted the issueRobotIdentity action) issues
// an identity that binds a robot's DID and its hardware-rooted key to attributes
// such as make, model, serial, and owner. The robot separately holds a
// hardware-attested RobotIdentityCredential (see identity.go) proving its key is
// bound to a secure element.
//
// VerifyRobotIdentityChain closes the loop: from one pinned root, a verifier
// confirms both that the robot is a legitimate robot from a recognized
// manufacturer (the authority chain) and that the key the manufacturer vouched
// for is genuinely hardware-rooted (the secure-element attestation), and that
// the two name the same robot and the same key. It follows the anchor-once model
// and the reason-code style of the underlying root_of_trust layer.
//
// This is the open layer: a single recognized manufacturer issues the identity
// and a single pinned root anchors it. Quorum issuance across multiple
// recognized manufacturers and continuous behavioral binding of the robot to its
// identity are out of scope for the open layer.
package robotics

import (
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// ActionIssueRobotIdentity is the recognized-issuer action a manufacturer must
// hold to bind a robot identity. Re-exported from the signer authority layer so
// callers can pin it without importing that package directly.
const ActionIssueRobotIdentity = signer.ActionIssueRobotIdentity

// RobotIdentityChainResult is the outcome of VerifyRobotIdentityChain.
//
// Ok is true only if the authority chain verified against the pinned root AND
// the vouched key is hardware-rooted for the same robot.
// Reason carries a structured failure reason when Ok is false, else "".
// RobotDID is the robot the identity describes.
// IssuerDID is the recognized manufacturer that issued the identity.
// RootDID is the pinned Vouch root the chain anchored to.
// Attributes are the identity attributes the manufacturer bound.
// HardwareRooted is true when the vouched key is secure-element-rooted.
type RobotIdentityChainResult struct {
	Ok             bool
	Reason         string
	RobotDID       string
	IssuerDID      string
	RootDID        string
	Attributes     map[string]any
	HardwareRooted bool
}

// BuildRobotIdentityOptions configures BuildRobotIdentity.
type BuildRobotIdentityOptions struct {
	// RobotDID is the robot's DID (the subject of this credential). Required.
	RobotDID string
	// HardwareKeyMultibase is the robot's hardware-rooted Ed25519 key as a
	// multikey, the key the manufacturer vouches for. Required.
	HardwareKeyMultibase string
	// Attributes are the identity attributes to bind (make, model, serial,
	// owner, and so on). Required and non-empty.
	Attributes map[string]any
	// ValidSeconds is the validity window. Defaults to one year.
	ValidSeconds int
	// ValidFrom overrides the issued-at moment (default: now).
	ValidFrom time.Time
	// Created overrides the proof timestamp (default: now).
	Created time.Time
	// CredentialStatus is an optional W3C credentialStatus entry for revocation.
	CredentialStatus map[string]any
	// CredentialID overrides the auto-generated UUID URN.
	CredentialID string
}

// BuildRobotIdentity issues an authority robot identity: a recognized
// manufacturer binds RobotDID, its hardware-rooted key (HardwareKeyMultibase,
// the robot's Ed25519 key as a multikey), and identity Attributes (make, model,
// serial, owner). The manufacturer must be a recognized issuer for the
// issueRobotIdentity action. The credential is an AgentIdentityCredential so the
// shared identity-chain verification applies, with the hardware key and a robot
// marker carried in the bound identity attributes.
func BuildRobotIdentity(issuerSigner *signer.Signer, opts BuildRobotIdentityOptions) (map[string]any, error) {
	if opts.RobotDID == "" {
		return nil, errors.New("robotics: robot DID is required")
	}
	if opts.HardwareKeyMultibase == "" {
		return nil, errors.New("robotics: hardware key multibase is required")
	}
	if len(opts.Attributes) == 0 {
		return nil, errors.New("robotics: attributes must be a non-empty map")
	}

	bound := make(map[string]any, len(opts.Attributes)+2)
	for k, v := range opts.Attributes {
		bound[k] = v
	}
	bound["kind"] = "robot"
	bound["hardwareKey"] = opts.HardwareKeyMultibase

	return signer.BuildAgentIdentity(issuerSigner, signer.AgentIdentityOptions{
		SubjectDID:       opts.RobotDID,
		Attributes:       bound,
		ValidSeconds:     opts.ValidSeconds,
		ValidFrom:        opts.ValidFrom,
		Created:          opts.Created,
		CredentialStatus: opts.CredentialStatus,
		CredentialID:     opts.CredentialID,
	})
}

// VerifyRobotIdentityChainOptions configures VerifyRobotIdentityChain.
type VerifyRobotIdentityChainOptions struct {
	// TrustedRoot is the Vouch Protocol root DID the verifier pins. Required.
	TrustedRoot string
	// RobotPublicKey is the robot's Ed25519 public key, used to verify the
	// hardware-attested RobotIdentityCredential. Required.
	RobotPublicKey ed25519.PublicKey
	// RootCredential is an optional Root of Trust credential to check for
	// self-consistency against TrustedRoot.
	RootCredential map[string]any
	// TrustedRoots is an optional map of DID -> Ed25519 public key for offline
	// pinning of non-did:key issuers.
	TrustedRoots map[string]ed25519.PublicKey
	// ClockSkewSeconds is the allowed clock drift for temporal checks.
	// Defaults to 30.
	ClockSkewSeconds int64
}

// VerifyRobotIdentityChain verifies a robot's identity against a single pinned
// Vouch root, confirming both provenance and hardware-rooting.
//
// From opts.TrustedRoot, the pinned root DID:
//
//  1. The authority chain: the recognized manufacturer must be recognized by the
//     pinned root for the issueRobotIdentity action, and the authority identity
//     must be signed by that manufacturer (via the shared identity-chain verify).
//  2. The vouched key: the authority identity must carry a hardware key.
//  3. The hardware root: the robot's own RobotIdentityCredential must verify
//     under RobotPublicKey and its secure-element attestation, name the same
//     robot, and its key must equal the key the manufacturer vouched for.
//
// Returns a RobotIdentityChainResult with a reason code on any failure, matching
// the anchor-once, reason-code style of the underlying root_of_trust layer.
func VerifyRobotIdentityChain(
	authorityIdentity map[string]any,
	recognizedIssuer map[string]any,
	robotHardwareCredential map[string]any,
	opts VerifyRobotIdentityChainOptions,
) RobotIdentityChainResult {
	chain := signer.VerifyIdentityChain(signer.VerifyIdentityChainOptions{
		IdentityCredential:         authorityIdentity,
		RecognizedIssuerCredential: recognizedIssuer,
		TrustedRoot:                opts.TrustedRoot,
		RequiredAction:             ActionIssueRobotIdentity,
		RootCredential:             opts.RootCredential,
		TrustedRoots:               opts.TrustedRoots,
		ClockSkewSeconds:           opts.ClockSkewSeconds,
	})
	if !chain.Ok {
		return RobotIdentityChainResult{Ok: false, Reason: chain.Reason, RootDID: opts.TrustedRoot}
	}

	attributes := chain.Attributes
	if attributes == nil {
		attributes = map[string]any{}
	}
	hardwareKey, _ := attributes["hardwareKey"].(string)
	if hardwareKey == "" {
		return RobotIdentityChainResult{Ok: false, Reason: "identity_no_hardware_key", RootDID: opts.TrustedRoot}
	}

	hwOk, hwSubject := VerifyRobotIdentity(robotHardwareCredential, opts.RobotPublicKey)
	if !hwOk || hwSubject == nil {
		return RobotIdentityChainResult{Ok: false, Reason: "hardware_root_invalid", RootDID: opts.TrustedRoot}
	}
	if hwID, _ := hwSubject["id"].(string); hwID != chain.AgentDID {
		return RobotIdentityChainResult{Ok: false, Reason: "hardware_subject_mismatch", RootDID: opts.TrustedRoot}
	}

	robotKeyMB, err := signer.EncodeEd25519Public(opts.RobotPublicKey)
	if err != nil {
		return RobotIdentityChainResult{Ok: false, Reason: "hardware_key_unresolvable", RootDID: opts.TrustedRoot}
	}
	if robotKeyMB != hardwareKey {
		return RobotIdentityChainResult{Ok: false, Reason: "hardware_key_mismatch", RootDID: opts.TrustedRoot}
	}

	return RobotIdentityChainResult{
		Ok:             true,
		RobotDID:       chain.AgentDID,
		IssuerDID:      chain.IssuerDID,
		RootDID:        opts.TrustedRoot,
		Attributes:     attributes,
		HardwareRooted: true,
	}
}
