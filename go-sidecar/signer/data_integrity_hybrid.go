// Post-quantum credentials as a Data Integrity proof set.
//
// The credential carries a `proof` ARRAY of two independent proofs,
// `eddsa-jcs-2022` and `mldsa44-jcs-2024`. Each proof is computed over the same
// unsecured document with only its own proof configuration, and each verifies
// on its own, so a verifier that understands only one of the two cryptosuites
// can still check that proof. Both must verify for VerifyDualProof to succeed.
//
// Two pre-alignment shapes are accepted on verification and never emitted:
// the `mldsa44-jcs-2026` identifier, and the v1.6.x composite
// `hybrid-eddsa-mldsa44-jcs-2026` whose single proofValue was
// base58btc(ed25519_sig || mldsa44_sig).
//
// Encodings differ by cryptosuite and are not interchangeable:
//   - eddsa-jcs-2022 proofValue is "z" + base58btc(signature).
//   - mldsa44-jcs-2024 proofValue is "u" + base64url-nopad(signature). The
//     pre-alignment "z" + base58btc form is accepted on verification.
//
// DID Document layout:
//
//	verificationMethod[]:
//	 - id: did:..#key-1, type: Multikey, publicKeyMultibase: z<Ed25519>
//	 - id: did:..#key-2, type: Multikey, publicKeyMultibase: z<ML-DSA-44>
//
// The Ed25519 proof's verificationMethod points at the #key-1 entry and the
// ML-DSA-44 proof's at #key-2.

package signer

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

const (
	// CryptosuiteMLDSA44Jcs2024 is the Quantum-Resistant Cryptosuites
	// identifier for ML-DSA-44 over JCS. This is the identifier emitted for
	// the post-quantum half of a dual proof.
	CryptosuiteMLDSA44Jcs2024 = "mldsa44-jcs-2024"

	// CryptosuiteMLDSA44JcsLegacy is the pre-alignment ML-DSA-44 identifier.
	// Accepted on verification only; never emitted.
	CryptosuiteMLDSA44JcsLegacy = "mldsa44-jcs-2026"

	// CryptosuiteHybridEddsaMldsa44 names the v1.6.x composite cryptosuite,
	// a single proof whose proofValue is the concatenation of both
	// signatures. Accepted on verification only; never emitted.
	CryptosuiteHybridEddsaMldsa44 = "hybrid-eddsa-mldsa44-jcs-2026"

	// Fixed signature sizes for splitting the concatenated proofValue.
	ed25519SignatureSize = 64
	mldsa44SignatureSize = 2420
	hybridSignatureSize  = ed25519SignatureSize + mldsa44SignatureSize
)

// BuildDualProofOptions configures BuildDualProof and SignDual.
type BuildDualProofOptions struct {
	Ed25519PrivateKey ed25519.PrivateKey
	MLDSA44PrivateKey *mldsa44.PrivateKey

	// Ed25519VerificationMethod points to the Ed25519 entry in the DID
	// Document (conventionally the #key-1 slot).
	Ed25519VerificationMethod string

	// MLDSA44VerificationMethod points to the ML-DSA-44 entry. When empty it
	// is derived from Ed25519VerificationMethod via
	// HybridVerificationMethodPair (the #key-2 slot on the same DID).
	MLDSA44VerificationMethod string

	ProofPurpose string // defaults to "assertionMethod"
	Created      time.Time
}

// BuildDualProof builds the two-proof set for a credential: an eddsa-jcs-2022
// proof and an mldsa44-jcs-2024 proof, each over the same unsecured document
// with its own proof configuration. The caller attaches the returned slice as
// the credential's "proof", or uses SignDual.
func BuildDualProof(credential map[string]any, opts BuildDualProofOptions) ([]any, error) {
	if opts.Ed25519PrivateKey == nil {
		return nil, errors.New("Ed25519PrivateKey is required")
	}
	if opts.MLDSA44PrivateKey == nil {
		return nil, errors.New("MLDSA44PrivateKey is required")
	}
	if opts.Ed25519VerificationMethod == "" {
		return nil, errors.New("Ed25519VerificationMethod is required")
	}

	mldsaVM := opts.MLDSA44VerificationMethod
	if mldsaVM == "" {
		_, mldsaVM = HybridVerificationMethodPair(opts.Ed25519VerificationMethod)
	}

	purpose := opts.ProofPurpose
	if purpose == "" {
		purpose = "assertionMethod"
	}
	created := opts.Created
	if created.IsZero() {
		created = time.Now().UTC()
	}

	base := unsecuredDocument(credential)

	edProof, err := BuildDataIntegrityProof(base, BuildProofOptions{
		PrivateKey:         opts.Ed25519PrivateKey,
		VerificationMethod: opts.Ed25519VerificationMethod,
		ProofPurpose:       purpose,
		Created:            created,
	})
	if err != nil {
		return nil, fmt.Errorf("build eddsa-jcs-2022 proof: %w", err)
	}

	mlProof := map[string]any{
		"type":               ProofTypeDataIntegrity,
		"cryptosuite":        CryptosuiteMLDSA44Jcs2024,
		"created":            formatISO8601(created),
		"verificationMethod": mldsaVM,
		"proofPurpose":       purpose,
	}
	signingInput, err := HashData(base, mlProof)
	if err != nil {
		return nil, err
	}
	// crypto.Hash(0) tells CIRCL the message is unhashed; ML-DSA itself
	// internally hashes. We pass the 64-byte signing input as the message.
	mlSig, err := opts.MLDSA44PrivateKey.Sign(rand.Reader, signingInput, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("ML-DSA-44 sign: %w", err)
	}
	if len(mlSig) != mldsa44SignatureSize {
		return nil, fmt.Errorf("unexpected ML-DSA-44 sig size %d", len(mlSig))
	}
	mlProof["proofValue"] = "u" + base64.RawURLEncoding.EncodeToString(mlSig)

	return []any{proofToMap(edProof), mlProof}, nil
}

// SignDual builds the two-proof set and returns the credential with "proof"
// set to it. Any existing proof on the input is replaced.
func SignDual(credential map[string]any, opts BuildDualProofOptions) (map[string]any, error) {
	proof, err := BuildDualProof(credential, opts)
	if err != nil {
		return nil, err
	}
	signed := unsecuredDocument(credential)
	signed["proof"] = proof
	return signed, nil
}

// VerifyDualProof verifies a proof set: both the Ed25519 and the ML-DSA-44
// proof in the array MUST validate. Returns true only when both are present
// and valid.
func VerifyDualProof(
	credential map[string]any,
	ed25519Public ed25519.PublicKey,
	mldsa44Public *mldsa44.PublicKey,
) (bool, error) {
	proofs, ok := proofSet(credential["proof"])
	if !ok {
		return false, errors.New("dual proof requires a proof array")
	}
	base := unsecuredDocument(credential)

	// Every recognized proof in the set must verify, rather than one of each
	// kind, so a set carrying a good proof next to a bad one is rejected.
	edOK := false
	mlOK := false
	for _, p := range proofs {
		switch cs, _ := p["cryptosuite"].(string); cs {
		case CryptosuiteEddsaJcs2022:
			candidate := copyMap(base)
			candidate["proof"] = p
			verified, err := VerifyDataIntegrityProof(candidate, ed25519Public)
			if err != nil {
				return false, err
			}
			if !verified {
				return false, nil
			}
			edOK = true
		case CryptosuiteMLDSA44Jcs2024, CryptosuiteMLDSA44JcsLegacy:
			verified, err := verifyMLDSA44Proof(base, p, mldsa44Public)
			if err != nil {
				return false, err
			}
			if !verified {
				return false, nil
			}
			mlOK = true
		}
	}
	return edOK && mlOK, nil
}

// ErrMissingMLDSA44Key is returned when a credential carries an ML-DSA-44
// proof but no ML-DSA-44 public key was supplied to check it with. Verification
// reports this rather than passing on the strength of the Ed25519 proof alone.
var ErrMissingMLDSA44Key = errors.New(
	"vouch: credential carries an ML-DSA-44 proof but no ML-DSA-44 public key was supplied",
)

// verifyMLDSA44Proof checks a single mldsa44-jcs proof against the unsecured
// document. The specified base64url-nopad proofValue ("u") and the
// pre-alignment base58btc form ("z") are both accepted, as are the aligned
// 64-byte signing input and the pre-alignment 32-byte digest.
func verifyMLDSA44Proof(
	base map[string]any,
	proof map[string]any,
	mldsa44Public *mldsa44.PublicKey,
) (bool, error) {
	if mldsa44Public == nil {
		return false, ErrMissingMLDSA44Key
	}
	pv, _ := proof["proofValue"].(string)
	if pv == "" {
		return false, errors.New("ml-dsa proof missing proofValue")
	}

	var (
		signature []byte
		err       error
	)
	switch pv[0] {
	case 'u':
		signature, err = base64.RawURLEncoding.DecodeString(pv[1:])
	case 'z':
		signature, err = b58Decode(pv[1:])
	default:
		return false, errors.New("proofValue must be multibase base64url (u) or base58btc (z)")
	}
	if err != nil {
		return false, fmt.Errorf("decode proofValue: %w", err)
	}

	unsigned := copyMap(proof)
	delete(unsigned, "proofValue")

	signingInput, err := HashData(base, unsigned)
	if err != nil {
		return false, err
	}
	if mldsa44.Verify(mldsa44Public, signingInput, nil, signature) {
		return true, nil
	}
	legacy, err := LegacyProofDigest(base, unsigned)
	if err != nil {
		return false, err
	}
	return mldsa44.Verify(mldsa44Public, legacy, nil, signature), nil
}

// VerifyProof verifies whichever proof shape a credential carries, so callers
// that do not know in advance whether a credential is classical or
// post-quantum have one entry point:
//
//   - a `proof` ARRAY takes the proof-set path (VerifyDualProof): both the
//     Ed25519 and the ML-DSA-44 proof must verify;
//   - a `proof` OBJECT carrying the pre-alignment composite cryptosuite takes
//     the composite path;
//   - any other `proof` OBJECT takes the single eddsa-jcs-2022 path.
//
// Every path keeps the pre-alignment signing-input fallback. When the
// credential carries an ML-DSA-44 proof and mldsa44Public is nil, this returns
// ErrMissingMLDSA44Key rather than passing on the Ed25519 proof alone.
func VerifyProof(
	credential map[string]any,
	ed25519Public ed25519.PublicKey,
	mldsa44Public *mldsa44.PublicKey,
) (bool, error) {
	switch proof := credential["proof"].(type) {
	case []any, []map[string]any:
		if mldsa44Public == nil {
			return false, ErrMissingMLDSA44Key
		}
		return VerifyDualProof(credential, ed25519Public, mldsa44Public)
	case map[string]any:
		if cs, _ := proof["cryptosuite"].(string); cs == CryptosuiteHybridEddsaMldsa44 {
			if mldsa44Public == nil {
				return false, ErrMissingMLDSA44Key
			}
			return VerifyHybridDataIntegrityProof(credential, ed25519Public, mldsa44Public)
		}
		return VerifyDataIntegrityProof(credential, ed25519Public)
	default:
		return VerifyDataIntegrityProof(credential, ed25519Public)
	}
}

// proofSet normalizes a credential's proof member into a slice of proof
// objects. Returns false when the member is not an array.
func proofSet(raw any) ([]map[string]any, bool) {
	switch v := raw.(type) {
	case []any:
		out := make([]map[string]any, 0, len(v))
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out, true
	case []map[string]any:
		return v, true
	default:
		return nil, false
	}
}

// ---------------------------------------------------------------------------
// Pre-alignment composite wire format (verify-only)
// ---------------------------------------------------------------------------

// BuildHybridProofOptions configures BuildHybridDataIntegrityProof.
type BuildHybridProofOptions struct {
	Ed25519PrivateKey ed25519.PrivateKey
	MLDSA44PrivateKey *mldsa44.PrivateKey

	// VerificationMethod points to the Ed25519 entry in the DID Document.
	VerificationMethod string

	ProofPurpose string // defaults to "assertionMethod"
	Created      time.Time
}

// BuildHybridDataIntegrityProof generates a v1.6.x composite proof, a single
// proof whose proofValue is base58btc(ed25519_sig || mldsa44_sig), over the
// pre-alignment signing input that format was issued under.
//
// Deprecated: the composite wire format is verify-only and retained so the
// older wire format can be reproduced for regression checks. New credentials
// use BuildDualProof, which emits a proof set.
func BuildHybridDataIntegrityProof(
	credential map[string]any,
	opts BuildHybridProofOptions,
) (DataIntegrityProof, error) {
	if opts.Ed25519PrivateKey == nil {
		return DataIntegrityProof{}, errors.New("Ed25519PrivateKey is required")
	}
	if opts.MLDSA44PrivateKey == nil {
		return DataIntegrityProof{}, errors.New("MLDSA44PrivateKey is required")
	}
	if opts.VerificationMethod == "" {
		return DataIntegrityProof{}, errors.New("VerificationMethod is required")
	}

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
		Cryptosuite:        CryptosuiteHybridEddsaMldsa44,
		Created:            formatISO8601(created),
		VerificationMethod: opts.VerificationMethod,
		ProofPurpose:       purpose,
	}

	digest, err := LegacyProofDigest(unsecuredDocument(credential), proofToMap(proof))
	if err != nil {
		return DataIntegrityProof{}, err
	}

	edSig := ed25519.Sign(opts.Ed25519PrivateKey, digest)
	if len(edSig) != ed25519SignatureSize {
		return DataIntegrityProof{}, fmt.Errorf("unexpected Ed25519 sig size %d", len(edSig))
	}

	// crypto.Hash(0) tells CIRCL the message is unhashed; ML-DSA itself
	// internally hashes. We pass the SHA-256 digest as the message.
	mlSig, err := opts.MLDSA44PrivateKey.Sign(rand.Reader, digest, crypto.Hash(0))
	if err != nil {
		return DataIntegrityProof{}, fmt.Errorf("ML-DSA-44 sign: %w", err)
	}
	if len(mlSig) != mldsa44SignatureSize {
		return DataIntegrityProof{}, fmt.Errorf("unexpected ML-DSA-44 sig size %d", len(mlSig))
	}

	combined := make([]byte, 0, hybridSignatureSize)
	combined = append(combined, edSig...)
	combined = append(combined, mlSig...)
	proof.ProofValue = "z" + b58Encode(combined)
	return proof, nil
}

// VerifyHybridDataIntegrityProof verifies a v1.6.x composite proof (single
// proof, concatenated proofValue) against the pre-alignment signing input.
// Both signatures MUST validate. Returns true on success, false on failure.
// Returns an error on malformed proof structure.
func VerifyHybridDataIntegrityProof(
	credential map[string]any,
	ed25519Public ed25519.PublicKey,
	mldsa44Public *mldsa44.PublicKey,
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
	if c, _ := proofMap["cryptosuite"].(string); c != CryptosuiteHybridEddsaMldsa44 {
		return false, fmt.Errorf("unexpected cryptosuite: %v", proofMap["cryptosuite"])
	}
	pv, _ := proofMap["proofValue"].(string)
	if pv == "" || pv[0] != 'z' {
		return false, errors.New("missing or malformed proofValue")
	}
	combined, err := b58Decode(pv[1:])
	if err != nil {
		return false, fmt.Errorf("decode proofValue: %w", err)
	}
	if len(combined) != hybridSignatureSize {
		return false, fmt.Errorf(
			"hybrid signature length %d, expected %d",
			len(combined), hybridSignatureSize,
		)
	}

	edSig := combined[:ed25519SignatureSize]
	mlSig := combined[ed25519SignatureSize:]

	proofWithoutValue := copyMap(proofMap)
	delete(proofWithoutValue, "proofValue")

	digest, err := LegacyProofDigest(unsecuredDocument(credential), proofWithoutValue)
	if err != nil {
		return false, err
	}

	if !ed25519.Verify(ed25519Public, digest, edSig) {
		return false, nil
	}
	if !mldsa44.Verify(mldsa44Public, digest, nil, mlSig) {
		return false, nil
	}
	return true, nil
}

// HybridVerificationMethodPair returns the (#key-1, #key-2) DID URL pair
// derived from a single verificationMethod identifier. The convention is
// that the Ed25519 key sits at #key-1 and the ML-DSA-44 key at the parallel
// #key-2 slot on the same DID. If the input does not end with "#key-1" it is
// returned unchanged as the Ed25519 slot, with "#key-2" appended for the
// ML-DSA-44 slot when a fragment is present, or the input again if no
// fragment.
func HybridVerificationMethodPair(verificationMethod string) (ed25519VM, mldsa44VM string) {
	if strings.HasSuffix(verificationMethod, "#key-1") {
		base := strings.TrimSuffix(verificationMethod, "#key-1")
		return verificationMethod, base + "#key-2"
	}
	if strings.Contains(verificationMethod, "#") {
		// Best-effort: replace fragment with "#key-2"
		idx := strings.Index(verificationMethod, "#")
		return verificationMethod, verificationMethod[:idx] + "#key-2"
	}
	return verificationMethod, verificationMethod + "#key-2"
}
