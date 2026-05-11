// Vouch Credential issuance using W3C Verifiable Credentials with
// Data Integrity proofs (eddsa-jcs-2022).
//
// This file extends Signer with a credential-issuance path that coexists
// with the legacy composite-JWS path in signer.go. Both paths share the
// same Ed25519 signing key. Existing callers using Signer.Sign() continue
// to work unchanged. New callers should prefer SignCredential().

package signer

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

const maxDelegationDepth = 5

// SignCredentialOptions configures Signer.SignCredential.
type SignCredentialOptions struct {
	// Intent is the action being authorized. Must contain action, target,
	// resource (W3C CG Report §5.4.1).
	Intent map[string]any

	// ValidSeconds overrides the default validity window (Signer.defaultExpiry).
	ValidSeconds int

	// ReputationScore optionally records the agent's self-reported score
	// in [0, 100]. Use a pointer so the caller can omit it cleanly.
	ReputationScore *int

	// ValidFrom overrides the issued-at moment (default: now).
	ValidFrom time.Time

	// CredentialID overrides the auto-generated UUID URN.
	CredentialID string

	// DelegationChain is a pre-built chain to attach as-is (advanced).
	DelegationChain []map[string]any

	// ParentCredential, if non-nil, indicates this signer is acting as a
	// sub-agent. The chain is extended by appending a new link from the
	// parent's subject to this signer's DID, enforcing the 5-hop depth
	// limit (§9.4) and the resource-narrowing rule (§9.3 step 5).
	ParentCredential map[string]any

	// CredentialStatus is an optional W3C credentialStatus entry, typically
	// built via BuildStatusListEntry to reference a BitstringStatusListCredential
	// (W3C CG Report §11.2). When non-nil, it is attached to the credential
	// as the `credentialStatus` property.
	CredentialStatus map[string]any
}

// SignCredential issues a W3C Verifiable Credential with a Data Integrity
// proof using the eddsa-jcs-2022 cryptosuite (W3C CG Report §5, §7.1).
// Returns the credential as a map suitable for JSON serialization.
func (s *Signer) SignCredential(opts SignCredentialOptions) (map[string]any, error) {
	chain := opts.DelegationChain
	if opts.ParentCredential != nil {
		extended, err := s.extendDelegationChain(opts.ParentCredential, opts.Intent)
		if err != nil {
			return nil, err
		}
		chain = extended
	}

	validSeconds := opts.ValidSeconds
	if validSeconds <= 0 {
		validSeconds = s.defaultExpiry
	}

	cred, err := BuildVouchCredential(BuildVouchCredentialOptions{
		IssuerDID:        s.did,
		Intent:           opts.Intent,
		ValidSeconds:     validSeconds,
		ReputationScore:  opts.ReputationScore,
		DelegationChain:  chain,
		CredentialID:     opts.CredentialID,
		ValidFrom:        opts.ValidFrom,
		CredentialStatus: opts.CredentialStatus,
	})
	if err != nil {
		return nil, err
	}

	proof, err := BuildDataIntegrityProof(cred, BuildProofOptions{
		PrivateKey:         s.ed25519Private,
		VerificationMethod: s.VerificationMethodID(),
	})
	if err != nil {
		return nil, fmt.Errorf("build proof: %w", err)
	}

	cred["proof"] = proofToMap(proof)
	return cred, nil
}

// SignCredentialJSON returns the credential as a JSON-serialized byte slice
// suitable for transmission over HTTP.
func (s *Signer) SignCredentialJSON(opts SignCredentialOptions) ([]byte, error) {
	cred, err := s.SignCredential(opts)
	if err != nil {
		return nil, err
	}
	return json.Marshal(cred)
}

// VerificationMethodID returns the canonical verification method identifier
// for this signer (W3C CG Report §5.5).
func (s *Signer) VerificationMethodID() string {
	return s.did + "#key-1"
}

// PublicKeyMultikey returns the Ed25519 public key in W3C Multikey format
// (z-prefixed base58btc with the Ed25519 multicodec prefix). Used in
// modern DID Documents per W3C CG Report §4.3.
func (s *Signer) PublicKeyMultikey() (string, error) {
	return EncodeEd25519Public(s.ed25519Public)
}

// PublicKeyMLDSA44Multikey returns the ML-DSA-44 public key in W3C Multikey
// format. Used in DID Documents alongside the Ed25519 entry when the
// hybrid post-quantum profile is active (W3C CG Report §13.2).
func (s *Signer) PublicKeyMLDSA44Multikey() (string, error) {
	pubBytes, err := s.mldsa44Public.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("marshal ML-DSA-44 public: %w", err)
	}
	return EncodeMLDSA44Public(pubBytes)
}

// PublicKeyEd25519 returns the raw Ed25519 public key bytes (32 bytes).
func (s *Signer) PublicKeyEd25519() ed25519.PublicKey {
	return s.ed25519Public
}

// PublicKeyMLDSA44 returns the ML-DSA-44 public key for hybrid verification.
func (s *Signer) PublicKeyMLDSA44() *mldsa44.PublicKey {
	return s.mldsa44Public
}

// DID returns the DID of this signer.
func (s *Signer) DID() string {
	return s.did
}

// SignCredentialHybrid issues a Vouch Credential under the hybrid
// post-quantum profile (W3C CG Report §13.2). The credential carries a
// hybrid-eddsa-mldsa44-jcs-2026 Data Integrity proof containing both an
// Ed25519 signature and an ML-DSA-44 signature over the same canonical form.
// Verification REQUIRES both signatures to validate.
//
// Note: this profile produces credentials roughly 2.5 KB larger than the
// eddsa-jcs-2022 default. Implementations using this profile SHOULD
// transmit credentials in the HTTP request body (§5.6).
func (s *Signer) SignCredentialHybrid(opts SignCredentialOptions) (map[string]any, error) {
	chain := opts.DelegationChain
	if opts.ParentCredential != nil {
		extended, err := s.extendDelegationChain(opts.ParentCredential, opts.Intent)
		if err != nil {
			return nil, err
		}
		chain = extended
	}

	validSeconds := opts.ValidSeconds
	if validSeconds <= 0 {
		validSeconds = s.defaultExpiry
	}

	cred, err := BuildVouchCredential(BuildVouchCredentialOptions{
		IssuerDID:        s.did,
		Intent:           opts.Intent,
		ValidSeconds:     validSeconds,
		ReputationScore:  opts.ReputationScore,
		DelegationChain:  chain,
		CredentialID:     opts.CredentialID,
		ValidFrom:        opts.ValidFrom,
		CredentialStatus: opts.CredentialStatus,
	})
	if err != nil {
		return nil, err
	}

	proof, err := BuildHybridDataIntegrityProof(cred, BuildHybridProofOptions{
		Ed25519PrivateKey:  s.ed25519Private,
		MLDSA44PrivateKey:  s.mldsa44Private,
		VerificationMethod: s.VerificationMethodID(),
	})
	if err != nil {
		return nil, fmt.Errorf("build hybrid proof: %w", err)
	}

	cred["proof"] = proofToMap(proof)
	return cred, nil
}

// extendDelegationChain builds a delegation link from parentCredential to
// this signer, validating depth and the resource-narrowing rule.
func (s *Signer) extendDelegationChain(
	parentCredential map[string]any,
	currentIntent map[string]any,
) ([]map[string]any, error) {
	parentSubject, _ := parentCredential["credentialSubject"].(map[string]any)
	if parentSubject == nil {
		return nil, fmt.Errorf("parent credential has no credentialSubject")
	}
	parentIntent, _ := parentSubject["intent"].(map[string]any)

	var parentChain []map[string]any
	switch raw := parentSubject["delegationChain"].(type) {
	case []any:
		for _, item := range raw {
			if m, ok := item.(map[string]any); ok {
				parentChain = append(parentChain, m)
			}
		}
	case []map[string]any:
		parentChain = raw
	}

	if len(parentChain) >= maxDelegationDepth {
		return nil, fmt.Errorf(
			"delegation chain exceeds max depth of %d",
			maxDelegationDepth,
		)
	}

	parentResource, _ := parentIntent["resource"].(string)
	childResource, _ := currentIntent["resource"].(string)
	if parentResource != "" && childResource != "" {
		if !isSubResource(childResource, parentResource) {
			return nil, fmt.Errorf(
				"delegation violates resource-narrowing rule: child resource %q is not a sub-resource of parent %q",
				childResource, parentResource,
			)
		}
	}

	parentProof, _ := parentCredential["proof"].(map[string]any)
	parentProofValue, _ := parentProof["proofValue"].(string)
	if len(parentProofValue) > 64 {
		parentProofValue = parentProofValue[:64]
	}

	parentIssuer, _ := parentCredential["issuer"].(string)
	parentValidFrom, _ := parentCredential["validFrom"].(string)
	parentValidUntil, _ := parentCredential["validUntil"].(string)

	newLink := map[string]any{
		"issuer":           parentIssuer,
		"subject":          s.did,
		"intent":           currentIntent,
		"validFrom":        parentValidFrom,
		"validUntil":       parentValidUntil,
		"parentProofValue": parentProofValue,
	}

	return append(parentChain, newLink), nil
}

func isSubResource(child, parent string) bool {
	if child == parent {
		return true
	}
	trimmed := strings.TrimRight(parent, "/")
	return strings.HasPrefix(child, trimmed+"/")
}
