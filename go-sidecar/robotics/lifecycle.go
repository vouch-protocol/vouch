// Robot lifecycle (Phase 5.x), Go.
//
// Mirrors vouch/robotics/lifecycle.py and the TypeScript SDK. A robot outlives
// its first owner: it is commissioned, resold, repurposed, and eventually
// scrapped, and each of those transitions needs to be cryptographically
// accountable so the chain of custody, the key history, and the end of life are
// verifiable.
//
//   - Ownership transfer: the current owner signs a transfer of the robot to a
//     new owner. Linking each transfer to the previous one forms a chain of
//     custody.
//   - Key rotation: the robot's current key authorizes a new key, forming a key
//     history (for a routine rotation or after a compromise).
//   - Decommission: an owner or authority signs the retirement of the robot,
//     after which a verifier should refuse to trust it.
//
// This is the open layer: plain, signed lifecycle credentials. Hosted ownership
// registries, managed rotation pipelines, and fleet decommissioning services are
// out of scope for the open layer.
package robotics

import (
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// Lifecycle credential types.
const (
	OwnershipTransferType = "RobotOwnershipTransferCredential"
	KeyRotationType       = "RobotKeyRotationCredential"
	DecommissionType      = "RobotDecommissionCredential"
)

// ---------------------------------------------------------------------------
// Ownership transfer (chain of custody)
// ---------------------------------------------------------------------------

// BuildOwnershipTransferOptions configures BuildOwnershipTransfer. An empty
// FromOwner defaults to the signer's DID; an empty PrevTransferID omits the
// field (set it when linking to the previous transfer); a zero TransferredAt
// uses now.
type BuildOwnershipTransferOptions struct {
	RobotDID       string
	ToOwner        string
	FromOwner      string
	PrevTransferID string
	TransferredAt  time.Time
}

// BuildOwnershipTransfer builds a signed transfer of RobotDID from the current
// owner to ToOwner. The signer is the current owner; FromOwner defaults to the
// signer's DID. PrevTransferID links this transfer to the previous one, forming
// a chain.
func BuildOwnershipTransfer(s *signer.Signer, opts BuildOwnershipTransferOptions) (map[string]any, error) {
	if opts.RobotDID == "" || opts.ToOwner == "" {
		return nil, errors.New("robotics: robot_did and to_owner are required")
	}

	issued := opts.TransferredAt
	if issued.IsZero() {
		issued = time.Now().UTC()
	}

	seller := opts.FromOwner
	if seller == "" {
		seller = s.DID()
	}

	subject := map[string]any{
		"id":        opts.RobotDID,
		"fromOwner": seller,
		"toOwner":   opts.ToOwner,
	}
	if opts.PrevTransferID != "" {
		subject["prevTransferId"] = opts.PrevTransferID
	}

	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", OwnershipTransferType},
		"issuer":            s.DID(),
		"validFrom":         iso(issued),
		"credentialSubject": subject,
	}
	return s.AttachProof(cred)
}

// VerifyOwnershipTransfer verifies a transfer: the current owner's proof and that
// the issuer is the fromOwner (only the current owner can transfer the robot).
// Returns (ok, subject).
func VerifyOwnershipTransfer(cred map[string]any, currentOwnerPub ed25519.PublicKey) (bool, map[string]any) {
	ok, subject := verifyTyped(cred, currentOwnerPub, OwnershipTransferType)
	if !ok {
		return false, nil
	}
	to, _ := subject["toOwner"].(string)
	from, _ := subject["fromOwner"].(string)
	if to == "" || from == "" {
		return false, nil
	}
	if iss, _ := cred["issuer"].(string); iss != from {
		return false, nil
	}
	return true, subject
}

// VerifyCustodyChainOptions configures VerifyCustodyChain. An empty OriginOwner
// skips the first-fromOwner check.
type VerifyCustodyChainOptions struct {
	OriginOwner string
}

// VerifyCustodyChain verifies an ordered list of transfer credentials forms a
// valid chain of custody: each transfer's proof verifies under the owner who
// signed it, every link's toOwner matches the next link's fromOwner, and (when
// given) the first fromOwner is OriginOwner. publicKeys maps an owner DID to its
// key. Returns (ok, currentOwner).
func VerifyCustodyChain(transfers []map[string]any, publicKeys map[string]ed25519.PublicKey, opts VerifyCustodyChainOptions) (bool, string) {
	expectedFrom := opts.OriginOwner
	currentOwner := opts.OriginOwner
	for _, transfer := range transfers {
		issuer, _ := transfer["issuer"].(string)
		pub, ok := publicKeys[issuer]
		if !ok {
			return false, ""
		}
		ok, subject := VerifyOwnershipTransfer(transfer, pub)
		if !ok {
			return false, ""
		}
		if expectedFrom != "" {
			if from, _ := subject["fromOwner"].(string); from != expectedFrom {
				return false, ""
			}
		}
		currentOwner, _ = subject["toOwner"].(string)
		expectedFrom = currentOwner
	}
	return true, currentOwner
}

// ---------------------------------------------------------------------------
// Key rotation (key history)
// ---------------------------------------------------------------------------

// BuildKeyRotationOptions configures BuildKeyRotation. An empty Reason omits the
// field; a zero RotatedAt uses now.
type BuildKeyRotationOptions struct {
	RobotDID        string
	NewKeyMultibase string
	Reason          string
	RotatedAt       time.Time
}

// BuildKeyRotation builds a key-rotation credential in which the robot's current
// (old) key authorizes a new key. Signed by the old key, so anyone trusting the
// old key can trust the new one. The issuer is the robot DID.
func BuildKeyRotation(oldKeySigner *signer.Signer, opts BuildKeyRotationOptions) (map[string]any, error) {
	if opts.NewKeyMultibase == "" {
		return nil, errors.New("robotics: new_key_multibase is required")
	}

	issued := opts.RotatedAt
	if issued.IsZero() {
		issued = time.Now().UTC()
	}

	previousKey, err := oldKeySigner.PublicKeyMultikey()
	if err != nil {
		return nil, err
	}

	subject := map[string]any{
		"id":          opts.RobotDID,
		"previousKey": previousKey,
		"newKey":      opts.NewKeyMultibase,
	}
	if opts.Reason != "" {
		subject["reason"] = opts.Reason
	}

	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", KeyRotationType},
		"issuer":            opts.RobotDID,
		"validFrom":         iso(issued),
		"credentialSubject": subject,
	}
	return oldKeySigner.AttachProof(cred)
}

// VerifyKeyRotation verifies a key rotation: the OLD key signed it, binding the
// new key. Returns (ok, subject) with newKey the authorized successor.
func VerifyKeyRotation(cred map[string]any, oldPub ed25519.PublicKey) (bool, map[string]any) {
	ok, subject := verifyTyped(cred, oldPub, KeyRotationType)
	if !ok {
		return false, nil
	}
	prev, _ := subject["previousKey"].(string)
	next, _ := subject["newKey"].(string)
	if prev == "" || next == "" {
		return false, nil
	}
	return true, subject
}

// VerifyKeyHistory verifies an ordered list of key rotations forms a valid key
// history starting from originKeyMultibase: each rotation's previousKey matches
// the current key, and each is signed by the key it rotates from. publicKeys maps
// a key multibase to the corresponding public key. Returns (ok, currentKey).
func VerifyKeyHistory(rotations []map[string]any, originKeyMultibase string, publicKeys map[string]ed25519.PublicKey) (bool, string) {
	currentKey := originKeyMultibase
	for _, rotation := range rotations {
		subject, _ := rotation["credentialSubject"].(map[string]any)
		if prev, _ := subject["previousKey"].(string); prev != currentKey {
			return false, ""
		}
		pub, ok := publicKeys[currentKey]
		if !ok {
			return false, ""
		}
		ok, verified := VerifyKeyRotation(rotation, pub)
		if !ok {
			return false, ""
		}
		currentKey, _ = verified["newKey"].(string)
	}
	return true, currentKey
}

// ---------------------------------------------------------------------------
// Decommission (retirement)
// ---------------------------------------------------------------------------

// BuildDecommissionOptions configures BuildDecommission. An empty FinalDisposition
// omits the field; a zero DecommissionedAt uses now; a zero ValidSeconds omits
// validUntil.
type BuildDecommissionOptions struct {
	RobotDID         string
	Reason           string
	FinalDisposition string
	DecommissionedAt time.Time
	ValidSeconds     int
}

// BuildDecommission builds a signed decommission credential retiring RobotDID.
// After decommissioning, a verifier should refuse to trust the robot. The signer
// is the owner or an authority; FinalDisposition records the outcome (for example
// recycled, destroyed, or transferred to parts).
func BuildDecommission(s *signer.Signer, opts BuildDecommissionOptions) (map[string]any, error) {
	if opts.Reason == "" {
		return nil, errors.New("robotics: reason is required")
	}

	issued := opts.DecommissionedAt
	if issued.IsZero() {
		issued = time.Now().UTC()
	}

	subject := map[string]any{
		"id":               opts.RobotDID,
		"reason":           opts.Reason,
		"decommissionedBy": s.DID(),
	}
	if opts.FinalDisposition != "" {
		subject["finalDisposition"] = opts.FinalDisposition
	}

	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", DecommissionType},
		"issuer":            s.DID(),
		"validFrom":         iso(issued),
		"credentialSubject": subject,
	}
	if opts.ValidSeconds > 0 {
		cred["validUntil"] = iso(issued.Add(time.Duration(opts.ValidSeconds) * time.Second))
	}
	return s.AttachProof(cred)
}

// VerifyDecommissionOptions configures VerifyDecommission. A nil TrustedAuthorities
// skips the authority check; when supplied, the issuer DID MUST be in it.
type VerifyDecommissionOptions struct {
	TrustedAuthorities map[string]bool
}

// VerifyDecommission verifies a decommission credential. When TrustedAuthorities
// is supplied, the issuer DID MUST be in it, so only an attested authority can
// retire the robot. Returns (ok, subject).
func VerifyDecommission(cred map[string]any, pub ed25519.PublicKey, opts VerifyDecommissionOptions) (bool, map[string]any) {
	ok, subject := verifyTyped(cred, pub, DecommissionType)
	if !ok {
		return false, nil
	}
	if opts.TrustedAuthorities != nil {
		iss, _ := cred["issuer"].(string)
		if !opts.TrustedAuthorities[iss] {
			return false, nil
		}
	}
	return true, subject
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// verifyTyped checks the credential carries expectedType and that its proof
// verifies under pub, then returns (ok, credentialSubject).
func verifyTyped(cred map[string]any, pub ed25519.PublicKey, expectedType string) (bool, map[string]any) {
	if !hasType(cred["type"], expectedType) {
		return false, nil
	}
	if pub == nil {
		return false, nil
	}
	if ok, err := signer.VerifyDataIntegrityProof(cred, pub); err != nil || !ok {
		return false, nil
	}
	subject, _ := cred["credentialSubject"].(map[string]any)
	return true, subject
}
