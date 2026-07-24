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
// Signing flow, the W3C Data Integrity hashing algorithm:
//
//	1. Build the proof configuration: the unsigned proof (no proofValue) plus
//	   the document's @context, and JCS-canonicalize it.
//	2. JCS-canonicalize the unsecured document (the credential with no proof).
//	3. hashData = SHA-256(canonical proof configuration)
//	              || SHA-256(canonical document)   (64 bytes, config first).
//	4. Ed25519-sign hashData.
//	5. Multibase-encode the signature into proof.proofValue ("z" + base58btc).
//
// Verification also accepts the pre-alignment signing input, a single SHA-256
// over the JCS form of the credential with the unsigned proof attached, so
// credentials issued before this alignment keep verifying. See
// LegacyProofDigest.

package signer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
)

const (
	CryptosuiteEddsaJcs2022 = "eddsa-jcs-2022"
	ProofTypeDataIntegrity  = "DataIntegrityProof"
)

// DataIntegrityProof represents a Data Integrity proof object.
type DataIntegrityProof struct {
	Type               string `json:"type"`
	Cryptosuite        string `json:"cryptosuite"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	ProofValue         string `json:"proofValue,omitempty"`
}

// BuildProofOptions configures BuildDataIntegrityProof.
//
// Provide either PrivateKey (signed in process) or Sign, a callback that takes
// the 64-byte signing input and returns the 64-byte Ed25519 signature. The Sign
// form lets the key live where this process cannot read it (an OS secure
// element, a sidecar, a cloud KMS/HSM, or an MPC quorum). If both are set, Sign
// wins.
type BuildProofOptions struct {
	PrivateKey         ed25519.PrivateKey
	Sign               func(digest []byte) []byte
	VerificationMethod string
	ProofPurpose       string // defaults to "assertionMethod"
	Created            time.Time
}

// unsecuredDocument returns a shallow copy of the credential with any proof
// member removed.
func unsecuredDocument(credential map[string]any) map[string]any {
	doc := copyMap(credential)
	delete(doc, "proof")
	return doc
}

// proofConfiguration builds the Data Integrity proof configuration: the
// unsigned proof (proofValue removed) carrying the document's @context.
func proofConfiguration(document, unsignedProof map[string]any) map[string]any {
	config := copyMap(unsignedProof)
	delete(config, "proofValue")
	if ctx, ok := document["@context"]; ok {
		config["@context"] = ctx
	}
	return config
}

// HashData computes the 64-byte W3C Data Integrity signing input for a JCS
// cryptosuite: SHA-256 of the canonical proof configuration joined with SHA-256
// of the canonical unsecured document, proof configuration hash first. This is
// the value that gets signed.
func HashData(credential, unsignedProof map[string]any) ([]byte, error) {
	document := unsecuredDocument(credential)
	config := proofConfiguration(document, unsignedProof)

	canonicalConfig, err := Canonicalize(config)
	if err != nil {
		return nil, fmt.Errorf("canonicalize proof configuration: %w", err)
	}
	canonicalDocument, err := Canonicalize(document)
	if err != nil {
		return nil, fmt.Errorf("canonicalize document: %w", err)
	}

	configHash := sha256.Sum256(canonicalConfig)
	documentHash := sha256.Sum256(canonicalDocument)

	out := make([]byte, 0, sha256.Size*2)
	out = append(out, configHash[:]...)
	out = append(out, documentHash[:]...)
	return out, nil
}

// LegacyProofDigest computes the pre-alignment signing input: a single SHA-256
// over the JCS canonical form of the credential with the unsigned proof
// attached under "proof". Retained so credentials issued before the Data
// Integrity alignment continue to verify. Never used for new proofs.
func LegacyProofDigest(credential, unsignedProof map[string]any) ([]byte, error) {
	unsigned := copyMap(unsignedProof)
	delete(unsigned, "proofValue")

	withProof := copyMap(credential)
	withProof["proof"] = unsigned

	canonical, err := Canonicalize(withProof)
	if err != nil {
		return nil, fmt.Errorf("canonicalize: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return digest[:], nil
}

// BuildDataIntegrityProof generates a Data Integrity proof for the given
// credential map. The caller is responsible for attaching the returned
// proof to the credential (e.g. credential["proof"] = proof).
//
// Conforms to eddsa-jcs-2022.
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
		Type:               ProofTypeDataIntegrity,
		Cryptosuite:        CryptosuiteEddsaJcs2022,
		Created:            formatISO8601(created),
		VerificationMethod: opts.VerificationMethod,
		ProofPurpose:       purpose,
	}

	// Build proof representation as a plain map matching the JSON shape
	// (proof without proofValue).
	proofForCanon := proofToMap(proof)

	signingInput, err := HashData(credential, proofForCanon)
	if err != nil {
		return DataIntegrityProof{}, err
	}

	var signature []byte
	switch {
	case opts.Sign != nil:
		signature = opts.Sign(signingInput)
	case opts.PrivateKey != nil:
		signature = ed25519.Sign(opts.PrivateKey, signingInput)
	default:
		return DataIntegrityProof{}, errors.New("BuildProofOptions needs a PrivateKey or a Sign callback")
	}
	proof.ProofValue = "z" + b58Encode(signature)
	return proof, nil
}

// VerifyDataIntegrityProof verifies the proof attached to the given
// credential against the public key. Returns true on success, false on
// signature failure. Returns an error on malformed proof structure.
//
// The aligned 64-byte signing input is tried first. If the signature does not
// match, the pre-alignment 32-byte digest is tried, so credentials issued
// before the Data Integrity alignment still verify.
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
	pv, _ := proofMap["proofValue"].(string)
	if pv == "" || pv[0] != 'z' {
		return false, errors.New("missing or malformed proofValue")
	}
	signature, err := b58Decode(pv[1:])
	if err != nil {
		return false, fmt.Errorf("decode proofValue: %w", err)
	}

	// Reconstruct the unsigned proof by removing proofValue.
	proofWithoutValue := copyMap(proofMap)
	delete(proofWithoutValue, "proofValue")

	signingInput, err := HashData(credential, proofWithoutValue)
	if err != nil {
		return false, err
	}
	if ed25519.Verify(publicKey, signingInput, signature) {
		return true, nil
	}

	// Fall back to the pre-alignment signing input.
	legacy, err := LegacyProofDigest(credential, proofWithoutValue)
	if err != nil {
		return false, err
	}
	return ed25519.Verify(publicKey, legacy, signature), nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func proofToMap(p DataIntegrityProof) map[string]any {
	m := map[string]any{
		"type":               p.Type,
		"cryptosuite":        p.Cryptosuite,
		"created":            p.Created,
		"verificationMethod": p.VerificationMethod,
		"proofPurpose":       p.ProofPurpose,
	}
	if p.ProofValue != "" {
		m["proofValue"] = p.ProofValue
	}
	return m
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
