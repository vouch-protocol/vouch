// Hybrid Ed25519 + ML-DSA-44 Data Integrity proofs.
//
// NOTE (2026-05-16): This file implements the v1.6.x transitional
// composite cryptosuite `hybrid-eddsa-mldsa44-jcs-2026`. Per Manu Sporny's
// review feedback on the W3C CG Report, v1.7 of the specification
// reformulates the hybrid profile as TWO independent Data Integrity
// proofs on the same credential (`eddsa-jcs-2022` and `mldsa44-jcs-2026`),
// rather than a single composite cryptosuite with a concatenated
// proofValue. See PAD-040 §3.3a for the dual-proof carrier embodiment
// and the Editor Review Queue at the top of docs/specs/w3c-cg-report.md
// (entries 9-10) for the spec changes.
//
// This file remains the reference implementation while the dual-proof
// rewrite waits on Digital Bazaar's forthcoming JCS variant of the
// `mldsa44-rdfc-2024-cryptosuite` family and W3C registration of the
// `mldsa44-jcs-*` cryptosuite identifier.
//
// Wire format (composite, v1.6.x transitional):
//  proofValue = "z" + base58btc( ed25519_sig (64 bytes) || mldsa44_sig (2420 bytes) )
//
// DID Document layout:
//  verificationMethod[]:
//   - id: did:..#key-1, type: Multikey, publicKeyMultibase: z<Ed25519>
//   - id: did:..#key-2, type: Multikey, publicKeyMultibase: z<ML-DSA-44>
//
// The proof's verificationMethod field points at the Ed25519 entry. The
// verifier infers the ML-DSA-44 entry by replacing the trailing "key-1"
// fragment with "key-2" on the same DID.

package signer

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

const (
	// CryptosuiteHybridEddsaMldsa44 names the Specification §13.2 hybrid
	// cryptosuite. Provisional identifier; final identifier will be
	// coordinated with the Data Integrity WG.
	CryptosuiteHybridEddsaMldsa44 = "hybrid-eddsa-mldsa44-jcs-2026"

	// Fixed signature sizes for splitting the concatenated proofValue.
	ed25519SignatureSize = 64
	mldsa44SignatureSize = 2420
	hybridSignatureSize  = ed25519SignatureSize + mldsa44SignatureSize
)

// BuildHybridProofOptions configures BuildHybridDataIntegrityProof.
type BuildHybridProofOptions struct {
	Ed25519PrivateKey ed25519.PrivateKey
	MLDSA44PrivateKey *mldsa44.PrivateKey

	// VerificationMethod points to the Ed25519 entry in the DID Document.
	// The verifier derives the ML-DSA-44 entry by replacing "key-1" with
	// "key-2" on the same DID URL fragment.
	VerificationMethod string

	ProofPurpose string // defaults to "assertionMethod"
	Created   time.Time
}

// BuildHybridDataIntegrityProof generates a hybrid composite proof over the
// given credential. Both Ed25519 and ML-DSA-44 sign the same SHA-256 of the
// JCS-canonicalized credential (with the unsigned proof attached).
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
		Type:        ProofTypeDataIntegrity,
		Cryptosuite:    CryptosuiteHybridEddsaMldsa44,
		Created:      formatISO8601(created),
		VerificationMethod: opts.VerificationMethod,
		ProofPurpose:    purpose,
	}

	proofForCanon := proofToMap(proof)
	credCopy := copyMap(credential)
	credCopy["proof"] = proofForCanon

	canonical, err := Canonicalize(credCopy)
	if err != nil {
		return DataIntegrityProof{}, fmt.Errorf("canonicalize: %w", err)
	}
	digest := sha256.Sum256(canonical)

	edSig := ed25519.Sign(opts.Ed25519PrivateKey, digest[:])
	if len(edSig) != ed25519SignatureSize {
		return DataIntegrityProof{}, fmt.Errorf("unexpected Ed25519 sig size %d", len(edSig))
	}

	// crypto.Hash(0) tells CIRCL the message is unhashed; ML-DSA itself
	// internally hashes. We pass the SHA-256 digest as the message.
	mlSig, err := opts.MLDSA44PrivateKey.Sign(rand.Reader, digest[:], crypto.Hash(0))
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

// VerifyHybridDataIntegrityProof verifies a hybrid composite proof. Both
// signatures MUST validate. Returns true on success, false on failure.
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

	// Bind the proof to the issuer and enforce its purpose (same rationale as
	// VerifyDataIntegrityProof).
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
	credCopy := copyMap(credential)
	credCopy["proof"] = proofWithoutValue

	canonical, err := Canonicalize(credCopy)
	if err != nil {
		return false, fmt.Errorf("canonicalize: %w", err)
	}
	digest := sha256.Sum256(canonical)

	if !ed25519.Verify(ed25519Public, digest[:], edSig) {
		return false, nil
	}
	if !mldsa44.Verify(mldsa44Public, digest[:], nil, mlSig) {
		return false, nil
	}
	return true, nil
}

// HybridVerificationMethodPair returns the (#key-1, #key-2) DID URL pair
// derived from a single verificationMethod identifier. The convention is
// that the proof's verificationMethod points at the Ed25519 key (#key-1)
// and the ML-DSA-44 key sits at the parallel slot (#key-2) on the same
// DID. If the input does not end with "#key-1" it is returned unchanged
// as the Ed25519 slot, with "#key-2" appended for the ML-DSA-44 slot when
// a fragment is present, or the input again if no fragment.
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
