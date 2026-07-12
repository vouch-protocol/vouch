// Root of Trust for Machine Identity (Vouch Protocol).
//
// Mirrors vouch/root_of_trust.py. Lets Vouch Protocol act as the trust
// anchor for AI agent and robot identity. A verifier pins ONE Vouch Protocol
// root, then verifies any agent offline by walking:
//
//	action credential  ->  authority-issued identity credential
//	    ->  recognized-issuer credential  ->  Vouch Protocol root
//
// Three credential types compose this chain, all secured with the same
// eddsa-jcs-2022 Data Integrity proof used elsewhere in Vouch Protocol:
//
//  1. Root of Trust credential      self-issued by the root (issuer == subject)
//  2. Recognized-issuer credential  issued by the root, naming an issuer that
//     may attest agent or robot identity
//  3. Agent identity credential     issued by a recognized issuer, binding an
//     agent key to real attributes (issuer != subject)
//
// This adds the authority layer that turns a self-asserted DID into an
// identity anchored to a trust root, with no external certificate authority
// and no central per-agent lookup. Anyone can stand up their own root and
// recognize their own issuers, so the model stays self-sovereign.

package signer

import (
	"crypto/ed25519"
	"fmt"
	"time"
)

// Credential type identifiers (the second entry in each type array).
const (
	RootOfTrustType      = "VouchRootOfTrust"
	RecognizedIssuerType = "RecognizedIssuerCredential"
	AgentIdentityType    = "AgentIdentityCredential"
)

// Actions an issuer can be recognized to perform.
const (
	ActionIssueAgentIdentity = "issueAgentIdentity"
	ActionIssueRobotIdentity = "issueRobotIdentity"
)

// Default validity windows. Roots are long lived; issuer and identity
// credentials rotate more often. All are overridable per call.
const (
	rootValidSeconds     = 10 * 365 * 24 * 3600
	issuerValidSeconds   = 365 * 24 * 3600
	identityValidSeconds = 365 * 24 * 3600
)

// trustTypes is the set of the three trust-layer credential types. A single
// credential must carry exactly one of these, otherwise one signed object
// could be replayed into a different slot of the chain (type confusion).
var trustTypes = map[string]struct{}{
	RootOfTrustType:      {},
	RecognizedIssuerType: {},
	AgentIdentityType:    {},
}

// IdentityChainResult is the outcome of VerifyIdentityChain.
//
// Ok is true only if every link verified and anchored to the pinned root.
// Reason carries a structured failure reason when Ok is false, else "".
// AgentDID is the subject DID of the identity credential (the agent).
// IssuerDID is the recognized issuer that attested the agent identity.
// RootDID is the pinned Vouch Protocol root the chain anchored to.
// Attributes are the identity attributes bound to the agent.
// Action is the verified action passport when an action credential was
// supplied and bound to the agent, else nil.
type IdentityChainResult struct {
	Ok         bool
	Reason     string
	AgentDID   string
	IssuerDID  string
	RootDID    string
	Attributes map[string]any
	Action     *CredentialPassport
}

// ---------------------------------------------------------------------------
// Credential builders
// ---------------------------------------------------------------------------

// RootOfTrustOptions configures BuildRootOfTrust.
type RootOfTrustOptions struct {
	// Name is the human-readable name of the root
	// (e.g. "Vouch Machine Identity Root"). Required.
	Name string
	// Scope is what the root anchors. Defaults to ["ai-agent", "robot"].
	Scope []string
	// ValidSeconds is the validity window. Defaults to ten years.
	ValidSeconds int
	// ValidFrom overrides the issued-at moment (default: now). Set together
	// with Created to produce reproducible vectors.
	ValidFrom time.Time
	// Created overrides the proof timestamp (default: now).
	Created time.Time
	// CredentialID overrides the auto-generated UUID URN.
	CredentialID string
}

// BuildRootOfTrust self-issues the Vouch Protocol Root of Trust credential.
//
// Issuer and subject are both the root's own DID. Verifiers pin the root DID
// and MAY keep this credential to display what the root anchors. It is not
// required for verification (the pinned DID is the anchor), but it makes the
// root self-describing.
func BuildRootOfTrust(rootSigner *Signer, opts RootOfTrustOptions) (map[string]any, error) {
	if opts.Name == "" {
		return nil, fmt.Errorf("vouch: root of trust name is required")
	}
	scope := opts.Scope
	if scope == nil {
		scope = []string{"ai-agent", "robot"}
	}
	rootDID := rootSigner.did
	subject := map[string]any{
		"id":           rootDID,
		"vouchVersion": ProtocolVersion,
		"rootOfTrust": map[string]any{
			"name":  opts.Name,
			"scope": toAnySlice(scope),
		},
	}
	validSeconds := opts.ValidSeconds
	if validSeconds <= 0 {
		validSeconds = rootValidSeconds
	}
	cred := trustEnvelope(
		opts.CredentialID,
		[]any{VCType, RootOfTrustType},
		rootDID,
		subject,
		validSeconds,
		opts.ValidFrom,
		nil,
	)
	return signTrustCredential(rootSigner, cred, opts.Created)
}

// RecognizedIssuerOptions configures BuildRecognizedIssuer.
type RecognizedIssuerOptions struct {
	// IssuerDID is the DID being recognized as an issuer. Required.
	IssuerDID string
	// RecognizedActions are the actions the issuer may perform. Defaults to
	// [ActionIssueAgentIdentity].
	RecognizedActions []string
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

// BuildRecognizedIssuer issues a recognized-issuer credential from the root.
//
// The root attests that IssuerDID may issue the given identity actions.
// recognizedIn chains back to the root DID so a verifier can trace the
// recognition to the anchor it pinned. The holder staples this credential to
// what it presents, so the verifier needs no central lookup.
func BuildRecognizedIssuer(rootSigner *Signer, opts RecognizedIssuerOptions) (map[string]any, error) {
	if opts.IssuerDID == "" {
		return nil, fmt.Errorf("vouch: issuer DID is required")
	}
	actions := opts.RecognizedActions
	if actions == nil {
		actions = []string{ActionIssueAgentIdentity}
	}
	rootDID := rootSigner.did
	subject := map[string]any{
		"id":                opts.IssuerDID,
		"recognizedActions": toAnySlice(actions),
		"recognizedIn":      rootDID,
	}
	validSeconds := opts.ValidSeconds
	if validSeconds <= 0 {
		validSeconds = issuerValidSeconds
	}
	cred := trustEnvelope(
		opts.CredentialID,
		[]any{VCType, RecognizedIssuerType},
		rootDID,
		subject,
		validSeconds,
		opts.ValidFrom,
		opts.CredentialStatus,
	)
	return signTrustCredential(rootSigner, cred, opts.Created)
}

// AgentIdentityOptions configures BuildAgentIdentity.
type AgentIdentityOptions struct {
	// SubjectDID is the agent's DID (the subject of this credential). Required.
	SubjectDID string
	// Attributes are the identity attributes to bind (owner, model,
	// capabilityClass, and so on). Required and non-empty.
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

// BuildAgentIdentity issues an authority-issued identity credential for an
// agent.
//
// Here the issuer differs from the subject: a recognized issuer binds the
// agent's DID to real attributes (owner, model, capability class, creation
// time). This is the piece that turns a self-asserted agent DID into an
// identity a third party stands behind.
func BuildAgentIdentity(issuerSigner *Signer, opts AgentIdentityOptions) (map[string]any, error) {
	if opts.SubjectDID == "" {
		return nil, fmt.Errorf("vouch: subject DID is required")
	}
	if len(opts.Attributes) == 0 {
		return nil, fmt.Errorf("vouch: attributes must be a non-empty map")
	}
	subject := map[string]any{
		"id":       opts.SubjectDID,
		"identity": copyMap(opts.Attributes),
	}
	validSeconds := opts.ValidSeconds
	if validSeconds <= 0 {
		validSeconds = identityValidSeconds
	}
	cred := trustEnvelope(
		opts.CredentialID,
		[]any{VCType, AgentIdentityType},
		issuerSigner.did,
		subject,
		validSeconds,
		opts.ValidFrom,
		opts.CredentialStatus,
	)
	return signTrustCredential(issuerSigner, cred, opts.Created)
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

// VerifyIdentityChainOptions configures VerifyIdentityChain.
type VerifyIdentityChainOptions struct {
	// IdentityCredential is the authority-issued identity for the agent.
	IdentityCredential map[string]any
	// RecognizedIssuerCredential is the root's recognition of the issuer.
	RecognizedIssuerCredential map[string]any
	// TrustedRoot is the Vouch Protocol root DID the verifier pins.
	TrustedRoot string
	// ActionCredential is an optional agent action credential to bind to the
	// identity (the agent's own signed action).
	ActionCredential map[string]any
	// RootCredential is an optional Root of Trust credential to check for
	// self-consistency against TrustedRoot.
	RootCredential map[string]any
	// RequiredAction is the action the issuer must be recognized for.
	// Defaults to ActionIssueAgentIdentity.
	RequiredAction string
	// TrustedRoots is an optional map of DID -> Ed25519 public key for offline
	// pinning of non-did:key issuers.
	TrustedRoots map[string]ed25519.PublicKey
	// ClockSkewSeconds is the allowed clock drift for temporal checks.
	// Defaults to 30.
	ClockSkewSeconds int64
}

// VerifyIdentityChain verifies an agent identity against a pinned Vouch
// Protocol root.
//
// It walks the chain: the recognized-issuer credential must be signed by the
// pinned root and grant the required action; the identity credential must be
// signed by that recognized issuer; the optional action credential must be
// signed by the agent the identity describes. Everything anchors at
// TrustedRoot, which is the ONE DID the verifier trusts up front.
//
// With did:key identities this runs fully offline.
func VerifyIdentityChain(opts VerifyIdentityChainOptions) IdentityChainResult {
	trustedRoot := opts.TrustedRoot
	if trustedRoot == "" {
		return IdentityChainResult{Ok: false, Reason: "no_trusted_root"}
	}
	requiredAction := opts.RequiredAction
	if requiredAction == "" {
		requiredAction = ActionIssueAgentIdentity
	}
	clockSkew := opts.ClockSkewSeconds
	if clockSkew == 0 {
		clockSkew = 30
	}

	// 1. The recognition must be signed by the pinned root.
	if ok, reason := verifyTrustCredential(
		opts.RecognizedIssuerCredential, RecognizedIssuerType, opts.TrustedRoots, clockSkew,
	); !ok {
		return IdentityChainResult{Ok: false, Reason: "recognized_issuer_" + reason}
	}
	if issuerOf(opts.RecognizedIssuerCredential) != trustedRoot {
		return IdentityChainResult{Ok: false, Reason: "recognized_issuer_not_from_root"}
	}

	recSubject, ok := opts.RecognizedIssuerCredential["credentialSubject"].(map[string]any)
	if !ok {
		return IdentityChainResult{Ok: false, Reason: "recognized_issuer_bad_subject"}
	}
	recognizedDID := asString(recSubject["id"])
	if recognizedDID == "" {
		return IdentityChainResult{Ok: false, Reason: "recognized_issuer_no_subject"}
	}
	actions, ok := recSubject["recognizedActions"].([]any)
	if !ok || !containsString(actions, requiredAction) {
		return IdentityChainResult{Ok: false, Reason: "issuer_not_recognized_for_action"}
	}

	// 2. The identity must be signed by the recognized issuer.
	if ok, reason := verifyTrustCredential(
		opts.IdentityCredential, AgentIdentityType, opts.TrustedRoots, clockSkew,
	); !ok {
		return IdentityChainResult{Ok: false, Reason: "identity_" + reason}
	}
	if issuerOf(opts.IdentityCredential) != recognizedDID {
		return IdentityChainResult{Ok: false, Reason: "identity_not_from_recognized_issuer"}
	}

	idSubject, ok := opts.IdentityCredential["credentialSubject"].(map[string]any)
	if !ok {
		return IdentityChainResult{Ok: false, Reason: "identity_bad_subject"}
	}
	agentDID := asString(idSubject["id"])
	if agentDID == "" {
		return IdentityChainResult{Ok: false, Reason: "identity_no_subject"}
	}
	attributes, _ := idSubject["identity"].(map[string]any)

	// 3. Optional: confirm the root credential is genuinely self-issued.
	if opts.RootCredential != nil {
		if ok, reason := verifyTrustCredential(
			opts.RootCredential, RootOfTrustType, opts.TrustedRoots, clockSkew,
		); !ok {
			return IdentityChainResult{Ok: false, Reason: "root_" + reason}
		}
		rootSub, ok := opts.RootCredential["credentialSubject"].(map[string]any)
		if !ok {
			return IdentityChainResult{Ok: false, Reason: "root_bad_subject"}
		}
		if issuerOf(opts.RootCredential) != trustedRoot || asString(rootSub["id"]) != trustedRoot {
			return IdentityChainResult{Ok: false, Reason: "root_not_self_issued"}
		}
	}

	// 4. Optional: bind the agent's own action to this identity.
	var actionPassport *CredentialPassport
	if opts.ActionCredential != nil {
		ok, passport, err := Verify(opts.ActionCredential, nil, clockSkew)
		if err != nil || !ok || passport == nil {
			return IdentityChainResult{Ok: false, Reason: "action_proof_invalid"}
		}
		if passport.Issuer != agentDID {
			return IdentityChainResult{Ok: false, Reason: "action_not_from_agent"}
		}
		actionPassport = passport
	}

	return IdentityChainResult{
		Ok:         true,
		AgentDID:   agentDID,
		IssuerDID:  recognizedDID,
		RootDID:    trustedRoot,
		Attributes: attributes,
		Action:     actionPassport,
	}
}

// ---------------------------------------------------------------------------
// Package-private helpers
// ---------------------------------------------------------------------------

// trustEnvelope builds the unsigned VC envelope shared by all three
// credential types. Mirrors _envelope in root_of_trust.py.
func trustEnvelope(
	credentialID string,
	types []any,
	issuer string,
	subject map[string]any,
	validSeconds int,
	validFrom time.Time,
	credentialStatus map[string]any,
) map[string]any {
	issuedAt := validFrom
	if issuedAt.IsZero() {
		issuedAt = time.Now().UTC()
	} else {
		issuedAt = issuedAt.UTC()
	}
	expiresAt := issuedAt.Add(time.Duration(validSeconds) * time.Second)

	id := credentialID
	if id == "" {
		if generated, err := newUUIDURN(); err == nil {
			id = generated
		}
	}

	cred := map[string]any{
		"@context":          []any{VCContextV2, VouchContextV1},
		"id":                id,
		"type":              types,
		"issuer":            issuer,
		"validFrom":         formatISO8601(issuedAt),
		"validUntil":        formatISO8601(expiresAt),
		"credentialSubject": subject,
	}
	if credentialStatus != nil {
		cred["credentialStatus"] = credentialStatus
	}
	return cred
}

// signTrustCredential attaches an eddsa-jcs-2022 Data Integrity proof using the
// signer's key. Handles both in-process signers (raw Ed25519 key) and backend
// signers (a sign callback). created overrides the proof timestamp, which is
// used to produce reproducible test vectors. Mirrors _sign in
// root_of_trust.py.
func signTrustCredential(s *Signer, cred map[string]any, created time.Time) (map[string]any, error) {
	proofOpts := BuildProofOptions{
		VerificationMethod: s.VerificationMethodID(),
		Created:            created,
	}
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

// verifyTrustCredential verifies a trust-layer credential (root,
// recognized-issuer, or identity). It checks the proof, the proof purpose,
// that the verification method belongs to the issuer, the credential type, and
// the validity window. Returns (ok, reason). Mirrors _verify_trust_credential.
func verifyTrustCredential(
	credential map[string]any,
	expectedType string,
	trustedRoots map[string]ed25519.PublicKey,
	clockSkewSeconds int64,
) (bool, string) {
	if credential == nil {
		return false, "not_a_credential"
	}

	types, ok := credential["type"].([]any)
	if !ok || !containsString(types, expectedType) {
		return false, "wrong_type"
	}
	// Exactly one trust-layer type, so the credential cannot double as another
	// link in the chain.
	if countTrustTypes(types) != 1 {
		return false, "ambiguous_type"
	}

	issuer := issuerOf(credential)
	if issuer == "" {
		return false, "no_issuer"
	}

	proof, ok := credential["proof"].(map[string]any)
	if !ok {
		return false, "no_proof"
	}
	if asString(proof["proofPurpose"]) != "assertionMethod" {
		return false, "bad_proof_purpose"
	}
	vm := asString(proof["verificationMethod"])
	if vm == "" || vmController(vm) != issuer {
		return false, "vm_mismatch"
	}

	publicKey := resolveTrustKey(issuer, trustedRoots)
	if publicKey == nil {
		return false, "unresolved_key"
	}

	verified, err := VerifyDataIntegrityProof(credential, publicKey)
	if err != nil {
		return false, "proof_malformed"
	}
	if !verified {
		return false, "proof_invalid"
	}

	validFrom, vfErr := parseISO8601(asString(credential["validFrom"]))
	validUntil, vuErr := parseISO8601(asString(credential["validUntil"]))
	if vfErr != nil || vuErr != nil {
		return false, "no_validity_window"
	}
	now := time.Now().UTC()
	skew := time.Duration(clockSkewSeconds) * time.Second
	if now.Sub(validUntil) > skew {
		return false, "expired"
	}
	if validFrom.Sub(now) > skew {
		return false, "not_yet_valid"
	}

	return true, ""
}

// resolveTrustKey resolves an issuer's Ed25519 public key. did:key resolves
// offline from the identifier; pinned keys come from trustedRoots.
func resolveTrustKey(did string, trustedRoots map[string]ed25519.PublicKey) ed25519.PublicKey {
	if trustedRoots != nil {
		if key, ok := trustedRoots[did]; ok {
			return key
		}
	}
	if IsDIDKey(did) {
		if key, err := Ed25519FromDIDKey(did); err == nil {
			return key
		}
	}
	return nil
}

// vmController returns the controller DID of a verification method id, the part
// before the first '#'.
func vmController(vm string) string {
	for i := 0; i < len(vm); i++ {
		if vm[i] == '#' {
			return vm[:i]
		}
	}
	return vm
}

// countTrustTypes counts how many of the three trust-layer types appear in the
// type array.
func countTrustTypes(types []any) int {
	count := 0
	for _, t := range types {
		if s, ok := t.(string); ok {
			if _, isTrust := trustTypes[s]; isTrust {
				count++
			}
		}
	}
	return count
}

// toAnySlice converts a []string to a []any for the JSON/JCS shape.
func toAnySlice(items []string) []any {
	out := make([]any, len(items))
	for i, s := range items {
		out[i] = s
	}
	return out
}
