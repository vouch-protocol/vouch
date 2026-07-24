// Vouch Credential issuance using Verifiable Credentials with
// Data Integrity proofs (eddsa-jcs-2022).
//
// This file extends Signer with a credential-issuance path that coexists
// with the legacy composite-JWS path in signer.go. Both paths share the
// same Ed25519 signing key. Existing callers using Signer.Sign() continue
// to work unchanged. New callers should prefer Sign().

package signer

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

// v1.7 removes the fixed delegation depth limit (was 5).

// SignOptions configures Signer.Sign.
type SignOptions struct {
	// Intent is the action being authorized. Must contain action, target,
	// resource (Specification §5.4.1). The intent can also be supplied via the
	// Action/Target/Resource fields below; when both are set, the named fields
	// override the matching keys in Intent.
	Intent map[string]any

	// Action, Target, Resource are a convenience alternative to building the
	// Intent map by hand. Any that are non-empty are folded into Intent.
	Action   string
	Target   string
	Resource string

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
	// (Specification §11.2). When non-nil, it is attached to the credential
	// as the `credentialStatus` property.
	CredentialStatus map[string]any
}

// Sign issues a Verifiable Credential with a Data Integrity
// proof using the eddsa-jcs-2022 cryptosuite (Specification §5, §7.1).
// Returns the credential as a map suitable for JSON serialization.
// parentProofBindingValue returns the proof value a delegation link binds to
// its parent. When the parent carries a proof set (a proof array), it binds to
// the classical eddsa-jcs-2022 member, whose value is deterministic, falling
// back to the first proof. For a single proof object it uses that proof's value.
func parentProofBindingValue(parentCredential map[string]any) string {
	switch proof := parentCredential["proof"].(type) {
	case map[string]any:
		v, _ := proof["proofValue"].(string)
		return v
	case []any:
		var first string
		for _, entry := range proof {
			pm, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			pv, _ := pm["proofValue"].(string)
			if first == "" {
				first = pv
			}
			if cs, _ := pm["cryptosuite"].(string); cs == CryptosuiteEddsaJcs2022 {
				return pv
			}
		}
		return first
	default:
		return ""
	}
}

func (s *Signer) Sign(opts SignOptions) (map[string]any, error) {
	opts.Intent = mergeIntent(opts.Intent, opts.Action, opts.Target, opts.Resource)
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

	proofOpts := BuildProofOptions{VerificationMethod: s.VerificationMethodID()}
	if s.signFunc != nil {
		proofOpts.Sign = s.signFunc
	} else {
		proofOpts.PrivateKey = s.ed25519Private
	}
	proof, err := BuildDataIntegrityProof(cred, proofOpts)
	if err != nil {
		return nil, fmt.Errorf("build proof: %w", err)
	}

	cred["proof"] = proofToMap(proof)
	return cred, nil
}

// SignJSON returns the credential as a JSON-serialized byte slice
// suitable for transmission over HTTP.
func (s *Signer) SignJSON(opts SignOptions) ([]byte, error) {
	cred, err := s.Sign(opts)
	if err != nil {
		return nil, err
	}
	return json.Marshal(cred)
}

// VerificationMethodID returns the canonical verification method identifier
// for this signer (Specification §5.5).
func (s *Signer) VerificationMethodID() string {
	return s.did + "#key-1"
}

// PublicKeyMultikey returns the Ed25519 public key in Multikey format
// (z-prefixed base58btc with the Ed25519 multicodec prefix). Used in
// modern DID Documents per Specification §4.3.
func (s *Signer) PublicKeyMultikey() (string, error) {
	return EncodeEd25519Public(s.ed25519Public)
}

// PublicKeyMLDSA44Multikey returns the ML-DSA-44 public key in Multikey
// format. Used in DID Documents alongside the Ed25519 entry when the
// hybrid post-quantum profile is active (Specification §13.2).
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

// AttachProof attaches an eddsa-jcs-2022 Data Integrity proof to a pre-built
// credential map, for custom credential types (for example robotics
// credentials) the caller assembles directly rather than from an intent.
// Mirrors the signing step of Sign; returns the credential with its
// "proof" set.
func (s *Signer) AttachProof(credential map[string]any) (map[string]any, error) {
	proof, err := BuildDataIntegrityProof(credential, BuildProofOptions{
		PrivateKey:         s.ed25519Private,
		VerificationMethod: s.VerificationMethodID(),
	})
	if err != nil {
		return nil, fmt.Errorf("attach proof: %w", err)
	}
	credential["proof"] = proofToMap(proof)
	return credential, nil
}

// MLDSA44VerificationMethodID returns the verification method identifier for
// this signer's ML-DSA-44 key, the #key-2 slot parallel to the Ed25519 #key-1
// entry on the same DID.
func (s *Signer) MLDSA44VerificationMethodID() string {
	_, mldsaVM := HybridVerificationMethodPair(s.VerificationMethodID())
	return mldsaVM
}

// AttachHybridProof attaches a post-quantum proof set (an eddsa-jcs-2022 proof
// alongside an mldsa44-jcs-2024 proof) to a pre-built credential map, for
// custom credential types (for example robotics credentials) the caller
// assembles directly rather than from an intent. Mirrors AttachProof; both keys
// live in this process, so it is not available for a backend Signer. Returns
// the credential with its "proof" set to the two-proof array.
func (s *Signer) AttachHybridProof(credential map[string]any) (map[string]any, error) {
	if s.signFunc != nil {
		return nil, errors.New("vouch: AttachHybridProof needs the raw keys and is not available for a backend Signer")
	}
	proof, err := BuildDualProof(credential, BuildDualProofOptions{
		Ed25519PrivateKey:         s.ed25519Private,
		MLDSA44PrivateKey:         s.mldsa44Private,
		Ed25519VerificationMethod: s.VerificationMethodID(),
		MLDSA44VerificationMethod: s.MLDSA44VerificationMethodID(),
	})
	if err != nil {
		return nil, fmt.Errorf("attach hybrid proof: %w", err)
	}
	credential["proof"] = proof
	return credential, nil
}

// SignHybrid issues a Vouch Credential under the post-quantum profile. The
// credential carries a `proof` ARRAY of two independent Data Integrity proofs,
// an eddsa-jcs-2022 proof and an mldsa44-jcs-2024 proof, over the same
// unsecured document. Verification REQUIRES both signatures to validate.
//
// Note: this profile produces credentials roughly 2.5 KB larger than the
// eddsa-jcs-2022 default. Implementations using this profile SHOULD
// transmit credentials in the HTTP request body (§5.6).
func (s *Signer) SignHybrid(opts SignOptions) (map[string]any, error) {
	if s.signFunc != nil {
		// The hybrid profile needs both an Ed25519 and an ML-DSA-44 signature.
		// A backend Signer only exposes the Ed25519 callback, so this path is
		// not available there.
		return nil, errors.New("vouch: SignHybrid is not supported for a backend Signer")
	}
	opts.Intent = mergeIntent(opts.Intent, opts.Action, opts.Target, opts.Resource)
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

	proof, err := BuildDualProof(cred, BuildDualProofOptions{
		Ed25519PrivateKey:         s.ed25519Private,
		MLDSA44PrivateKey:         s.mldsa44Private,
		Ed25519VerificationMethod: s.VerificationMethodID(),
		MLDSA44VerificationMethod: s.MLDSA44VerificationMethodID(),
	})
	if err != nil {
		return nil, fmt.Errorf("build hybrid proof: %w", err)
	}

	cred["proof"] = proof
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

	// v1.7 removes the fixed depth limit; the non-expansion rule is enforced at
	// verification by the shared attenuation validator, and cost is a
	// verifier-side budget. The resource-narrowing guard below stays as a fast
	// build-time check.

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

	parentProofValue := parentProofBindingValue(parentCredential)
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

// mergeIntent folds the named action/target/resource into a copy of the intent
// map. Named values override matching keys; the caller's map is not mutated.
// Required-field validation is left to BuildVouchCredential.
func mergeIntent(intent map[string]any, action, target, resource string) map[string]any {
	merged := make(map[string]any, len(intent)+3)
	for k, v := range intent {
		merged[k] = v
	}
	if action != "" {
		merged["action"] = action
	}
	if target != "" {
		merged["target"] = target
	}
	if resource != "" {
		merged["resource"] = resource
	}
	return merged
}
