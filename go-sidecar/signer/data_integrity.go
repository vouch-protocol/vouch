// Data Integrity proof builder and verifier, eddsa-jcs-2022 cryptosuite.
//
// Mirrors vouch/data_integrity.py and typescript/src/data-integrity.ts.
// Implements §3.1 of [VC-DI-EDDSA]:
//
//	https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022
//
// The cryptosuite produces a DataIntegrityProof object that attaches alongside
// the credential payload as a sibling proof property. No JWS, no JOSE,
// no Base64 wrapping of the payload, the credential remains human-readable
// JSON.
//
// Signing flow (Specification §7.1):
//
//	1. Build credential with unsigned proof (no proofValue).
//	2. JCS-canonicalize the entire object.
//	3. SHA-256 the canonical bytes.
//	4. Ed25519-sign the digest.
//	5. Multibase-encode the signature into proof.proofValue.

package signer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	CryptosuiteEddsaJcs2022 = "eddsa-jcs-2022"
	ProofTypeDataIntegrity = "DataIntegrityProof"
)

// DataIntegrityProof represents a Data Integrity proof object.
type DataIntegrityProof struct {
	Type        string `json:"type"`
	Cryptosuite    string `json:"cryptosuite"`
	Created      string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose    string `json:"proofPurpose"`
	ProofValue     string `json:"proofValue,omitempty"`
}

// BuildProofOptions configures BuildDataIntegrityProof.
type BuildProofOptions struct {
	PrivateKey     ed25519.PrivateKey
	VerificationMethod string
	ProofPurpose    string // defaults to "assertionMethod"
	Created      time.Time
}

// BuildDataIntegrityProof generates a Data Integrity proof for the given
// credential map. The caller is responsible for attaching the returned
// proof to the credential (e.g. credential["proof"] = proof).
//
// Conforms to eddsa-jcs-2022 §3.1.
func BuildDataIntegrityProof(
	credential map[string]any,
	opts BuildProofOptions,
) (DataIntegrityProof, error) {
	purpose := opts.ProofPurpose
	if purpose == "" {
		purpose = "assertionMethod"
	}

	created := opts.Created
	if created.IsZero() {
		created = time.Now().UTC()
	}

	proof := DataIntegrityProof{
		Type:        ProofTypeDataIntegrity,
		Cryptosuite:    CryptosuiteEddsaJcs2022,
		Created:      formatISO8601(created),
		VerificationMethod: opts.VerificationMethod,
		ProofPurpose:    purpose,
	}

	// Build proof representation as a plain map matching the JSON shape
	// (proof without proofValue).
	proofForCanon := proofToMap(proof)

	// Attach the unsigned proof to a copy of the credential.
	credCopy := copyMap(credential)
	credCopy["proof"] = proofForCanon

	canonical, err := Canonicalize(credCopy)
	if err != nil {
		return DataIntegrityProof{}, fmt.Errorf("canonicalize: %w", err)
	}
	digest := sha256.Sum256(canonical)

	signature := ed25519.Sign(opts.PrivateKey, digest[:])
	proof.ProofValue = "z" + b58Encode(signature)
	return proof, nil
}

// VerifyDataIntegrityProof verifies the proof attached to the given
// credential against the public key. Returns true on success, false on
// signature failure. Returns an error on malformed proof structure.
func VerifyDataIntegrityProof(
	credential map[string]any,
	publicKey ed25519.PublicKey,
) (bool, error) {
	rawProof, ok := credential["proof"]
	if !ok || rawProof == nil {
		return false, errors.New("credential has no proof object")
	}
	proofMap, ok := rawProof.(map[string]any)
	if !ok {
		return false, errors.New("proof must be an object")
	}
	if t, _ := proofMap["type"].(string); t != ProofTypeDataIntegrity {
		return false, fmt.Errorf("unexpected proof type: %v", proofMap["type"])
	}
	if c, _ := proofMap["cryptosuite"].(string); c != CryptosuiteEddsaJcs2022 {
		return false, fmt.Errorf("unexpected cryptosuite: %v", proofMap["cryptosuite"])
	}

	// Bind the proof to the issuer and enforce its purpose. A signature only
	// means something if the key that made it is the issuer's key, used for
	// the assertion purpose. Without this, a key trusted for issuer A could
	// sign a credential claiming issuer B, and a proof made for another purpose
	// could be replayed as an assertion.
	if pp, _ := proofMap["proofPurpose"].(string); pp != "assertionMethod" {
		return false, fmt.Errorf("unexpected proofPurpose: %v", proofMap["proofPurpose"])
	}
	if issuerDID := issuerDIDOf(credential); issuerDID != "" {
		vm, _ := proofMap["verificationMethod"].(string)
		if vm == "" {
			return false, errors.New("proof missing verificationMethod")
		}
		if didPart(vm) != issuerDID {
			return false, errors.New("verificationMethod does not belong to issuer")
		}
	}

	pv, _ := proofMap["proofValue"].(string)
	if pv == "" || pv[0] != 'z' {
		return false, errors.New("missing or malformed proofValue")
	}
	signature, err := b58Decode(pv[1:])
	if err != nil {
		return false, fmt.Errorf("decode proofValue: %w", err)
	}

	// Reconstruct canonical form by removing proofValue from proof.
	proofWithoutValue := copyMap(proofMap)
	delete(proofWithoutValue, "proofValue")
	credCopy := copyMap(credential)
	credCopy["proof"] = proofWithoutValue

	canonical, err := Canonicalize(credCopy)
	if err != nil {
		return false, fmt.Errorf("canonicalize: %w", err)
	}
	digest := sha256.Sum256(canonical)

	return ed25519.Verify(publicKey, digest[:], signature), nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func proofToMap(p DataIntegrityProof) map[string]any {
	m := map[string]any{
		"type":        p.Type,
		"cryptosuite":    p.Cryptosuite,
		"created":      p.Created,
		"verificationMethod": p.VerificationMethod,
		"proofPurpose":    p.ProofPurpose,
	}
	if p.ProofValue != "" {
		m["proofValue"] = p.ProofValue
	}
	return m
}

// issuerDIDOf extracts the issuer DID from a credential. The issuer may be a
// string or an array whose first element is the DID. Returns "" if absent.
func issuerDIDOf(credential map[string]any) string {
	switch v := credential["issuer"].(type) {
	case string:
		return v
	case []any:
		if len(v) > 0 {
			if s, ok := v[0].(string); ok {
				return s
			}
		}
	}
	return ""
}

// didPart returns the DID portion of a verificationMethod, i.e. everything
// before the first '#'.
func didPart(verificationMethod string) string {
	if i := strings.IndexByte(verificationMethod, '#'); i >= 0 {
		return verificationMethod[:i]
	}
	return verificationMethod
}

func copyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func formatISO8601(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}
