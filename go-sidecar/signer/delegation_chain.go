package signer

import (
	"crypto/ed25519"
	"strings"

	"github.com/vouch-protocol/vouch/go-sidecar/attenuation"
)

// VerifyDelegationChain verifies a credential's embedded delegationChain
// (Specification 9.3). It returns "" when the chain is valid (or absent),
// otherwise a reason code. It is a faithful port of
// vouch.verifier.verify_delegation_chain (Python is the reference); the shared
// vectors in test-vectors/delegation-chain are the contract.
//
// rootKeys supplies keys for non-did:key grant issuers. rootDIDs, when non-nil,
// is the set of trusted root DIDs the chain must start from. did:key issuers
// always resolve offline.
func VerifyDelegationChain(
	credential map[string]any,
	nowISO string,
	clockSkewSeconds int64,
	rootKeys map[string]ed25519.PublicKey,
	rootDIDs []string,
) string {
	subject, _ := credential["credentialSubject"].(map[string]any)
	if subject == nil {
		return ""
	}
	raw, present := subject["delegationChain"]
	if !present || raw == nil {
		return ""
	}
	var chain []map[string]any
	switch v := raw.(type) {
	case []any:
		for _, item := range v {
			m, ok := item.(map[string]any)
			if !ok {
				return "malformed_delegation"
			}
			chain = append(chain, m)
		}
	case []map[string]any:
		chain = v
	default:
		return "malformed_delegation"
	}
	if len(chain) == 0 {
		return ""
	}
	now, err := parseISO8601(nowISO)
	if err != nil {
		return "malformed_delegation"
	}
	skew := clockSkewSeconds

	grants := make([]map[string]any, 0, len(chain))
	for _, link := range chain {
		linkIssuer, ok1 := link["issuer"].(string)
		linkSubject, ok2 := link["subject"].(string)
		if !ok1 || !ok2 {
			return "malformed_delegation"
		}
		grant, _ := link["parentCredential"].(map[string]any)
		if grant == nil {
			return "delegation_link_unsigned"
		}
		switch grant["proof"].(type) {
		case map[string]any, []any, []map[string]any:
		default:
			return "delegation_link_unsigned"
		}
		if issuerOf(grant) != linkIssuer {
			return "delegation_link_issuer_mismatch"
		}
		key := resolveChainKey(linkIssuer, rootKeys)
		if key == nil {
			return "delegation_issuer_key_unresolved"
		}
		if !verifyGrantProof(grant, linkIssuer, key) {
			return "delegation_signature_invalid"
		}
		if bound, ok := link["parentProofValue"]; ok && bound != nil {
			binding := parentProofBindingValue(grant)
			if len(binding) > 64 {
				binding = binding[:64]
			}
			if s, _ := bound.(string); s != binding {
				return "delegation_link_tampered"
			}
		}
		grantSubject, _ := grant["credentialSubject"].(map[string]any)
		grantIntent, _ := grantSubject["intent"].(map[string]any)
		delegatee, _ := grantIntent["delegatee"].(string)
		if delegatee == "" {
			return "delegation_no_delegatee"
		}
		if delegatee != linkSubject {
			return "delegation_subject_mismatch"
		}
		from, fErr := parseISO8601(asString(grant["validFrom"]))
		until, uErr := parseISO8601(asString(grant["validUntil"]))
		if fErr != nil || uErr != nil {
			return "malformed_delegation"
		}
		if int64(now.Sub(until).Seconds()) > skew {
			return "delegation_expired"
		}
		if int64(from.Sub(now).Seconds()) > skew {
			return "delegation_not_yet_valid"
		}
		grants = append(grants, grant)
	}

	for i := 1; i < len(chain); i++ {
		if asString(chain[i-1]["subject"]) != asString(chain[i]["issuer"]) {
			return "delegation_subject_issuer_mismatch"
		}
	}
	if asString(chain[len(chain)-1]["subject"]) != issuerOf(credential) {
		return "delegation_subject_issuer_mismatch"
	}

	if rootDIDs != nil {
		root := asString(chain[0]["issuer"])
		trusted := false
		for _, d := range rootDIDs {
			if d == root {
				trusted = true
				break
			}
		}
		if !trusted {
			return "untrusted_principal"
		}
	}

	views := make([]map[string]interface{}, 0, len(grants)+1)
	for _, g := range grants {
		views = append(views, attenuation.CapabilityView(g, true))
	}
	views = append(views, attenuation.CapabilityView(credential, true))
	for i := 1; i < len(views); i++ {
		if dim := attenuation.NonExpansion(views[i-1], views[i]); dim != "" {
			return "scope_exceeds_parent:" + dim
		}
	}
	return ""
}

func resolveChainKey(did string, rootKeys map[string]ed25519.PublicKey) ed25519.PublicKey {
	if k, ok := rootKeys[did]; ok {
		return k
	}
	if IsDIDKey(did) {
		if k, err := Ed25519FromDIDKey(did); err == nil {
			return k
		}
	}
	return nil
}

// verifyGrantProof checks a grant's eddsa-jcs-2022 proof (the classical member
// of a proof set), made by the issuer for assertionMethod.
func verifyGrantProof(grant map[string]any, issuer string, key ed25519.PublicKey) bool {
	var proofs []map[string]any
	switch p := grant["proof"].(type) {
	case map[string]any:
		proofs = []map[string]any{p}
	case []any:
		for _, item := range p {
			if m, ok := item.(map[string]any); ok {
				proofs = append(proofs, m)
			}
		}
	case []map[string]any:
		proofs = p
	}
	for _, proof := range proofs {
		if cs, present := proof["cryptosuite"]; present && cs != nil && cs != CryptosuiteEddsaJcs2022 {
			continue
		}
		if proof["proofPurpose"] != "assertionMethod" {
			continue
		}
		vm, _ := proof["verificationMethod"].(string)
		if vm == "" || strings.SplitN(vm, "#", 2)[0] != issuer {
			continue
		}
		candidate := make(map[string]any, len(grant))
		for k, v := range grant {
			if k != "proof" {
				candidate[k] = v
			}
		}
		candidate["proof"] = proof
		if ok, err := VerifyDataIntegrityProof(candidate, key); err == nil && ok {
			return true
		}
	}
	return false
}
