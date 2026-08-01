// Reasoned Action Proofs: bind an agent's justification to the action it takes.
//
// A pure-Go port of core/vouch-core/src/reasoning.rs (and the Python reference
// vouch/reasoning.py). Before executing, an agent states a structured
// justification: an intent plus a set of evidence anchors, each a claim tied to a
// real artifact by that artifact's hash. The justification is committed by digest,
// optionally deposited with a neutral escrow that timestamps it, and the executed
// action credential carries the commitment. The digest algorithm and every stable
// reason string match the core byte for byte, so a seal built in one language
// verifies in another. Everything here is an ordinary eddsa-jcs-2022 Verifiable
// Credential, built on the package's existing JCS and Data Integrity primitives.
package signer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

const (
	// VCContextV2 and VouchContextV1 are declared in vc.go and reused here.
	ReasonedActionType = "ReasonedActionCredential"
	EscrowReceiptType  = "JustificationEscrowReceipt"

	JustificationAlgorithm = "sha-256-jcs"
)

// Structured verification reasons (stable strings, mirrored by every SDK).
const (
	ReasonInvalidProof                = "invalid_proof"
	ReasonNotReasonedAction           = "not_reasoned_action"
	ReasonMissingCommitment           = "missing_commitment"
	ReasonMissingEscrow               = "missing_escrow"
	ReasonEscrowInvalid               = "escrow_receipt_invalid"
	ReasonEscrowDigestMismatch        = "escrow_digest_mismatch"
	ReasonEscrowAfterExecution        = "escrow_after_execution"
	ReasonJustificationDigestMismatch = "justification_digest_mismatch"
	ReasonEvidenceUnresolved          = "evidence_unresolved"
	ReasonEvidenceHashMismatch        = "evidence_hash_mismatch"
	ReasonUnanchoredClaim             = "unanchored_claim"
)

// mb64 is multibase base64url-no-pad, matching the Python "_mb64" helper.
func mb64(b []byte) string {
	return "u" + base64.RawURLEncoding.EncodeToString(b)
}

// artifactBytes returns the canonical bytes of an evidence artifact. A string is
// hashed as its UTF-8 bytes; a JSON object (map) is JCS-canonicalized.
func artifactBytes(artifact any) ([]byte, error) {
	switch v := artifact.(type) {
	case string:
		return []byte(v), nil
	case []byte:
		return v, nil
	case map[string]any:
		return Canonicalize(v)
	default:
		return nil, errors.New("evidence artifact must be a JSON object, string, or bytes")
	}
}

// ArtifactDigest returns the multibase SHA-256 of an evidence artifact.
func ArtifactDigest(artifact any) (string, error) {
	b, err := artifactBytes(artifact)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return mb64(sum[:]), nil
}

// EvidenceAnchor builds one evidence anchor: a claim tied to a verifiable
// artifact. Supply evidence (its hash is computed) OR a precomputed evidenceHash.
func EvidenceAnchor(claim, ref string, evidence any, evidenceHash, anchorType string) (map[string]any, error) {
	if claim == "" || ref == "" {
		return nil, errors.New("an evidence anchor needs a claim and a ref")
	}
	hash := evidenceHash
	if hash == "" {
		if evidence == nil {
			return nil, errors.New("supply evidence or evidenceHash for the anchor")
		}
		var err error
		if hash, err = ArtifactDigest(evidence); err != nil {
			return nil, err
		}
	}
	return map[string]any{
		"type":         anchorType,
		"claim":        claim,
		"ref":          ref,
		"evidenceHash": hash,
	}, nil
}

// BuildJustification assembles a justification: the intent plus its evidence
// anchors. intent must carry at least action and target; at least one anchor is
// required. Pass a non-nil commitmentLevel to record an impact level (0..4).
func BuildJustification(intent map[string]any, anchors []map[string]any, commitmentLevel *int) (map[string]any, error) {
	if !hasActionTarget(intent) {
		return nil, errors.New("intent must be an object with at least action and target")
	}
	if len(anchors) == 0 {
		return nil, errors.New("a justification needs at least one evidence anchor")
	}
	anchorList := make([]any, len(anchors))
	for i, a := range anchors {
		anchorList[i] = a
	}
	just := map[string]any{
		"intent":          intent,
		"evidenceAnchors": anchorList,
	}
	if commitmentLevel != nil {
		just["commitmentLevel"] = *commitmentLevel
	}
	return just, nil
}

// JustificationDigest returns the multibase SHA-256 over the JCS-canonical
// justification.
func JustificationDigest(justification map[string]any) (string, error) {
	canonical, err := Canonicalize(justification)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return mb64(sum[:]), nil
}

// BuildEscrowReceipt issues a signed JustificationEscrowReceipt fixing a
// commitment in time. The escrow sees only the digest, never the plaintext.
func BuildEscrowReceipt(escrowKey ed25519.PrivateKey, escrowDID, escrowVerificationMethod, agentDID, committedDigest, depositedAt, credentialID string) (map[string]any, error) {
	receipt := map[string]any{
		"@context":  []any{VCContextV2, VouchContextV1},
		"type":      []any{"VerifiableCredential", EscrowReceiptType},
		"id":        credentialID,
		"issuer":    escrowDID,
		"validFrom": depositedAt,
		"credentialSubject": map[string]any{
			"agent":           agentDID,
			"committedDigest": committedDigest,
			"depositedAt":     depositedAt,
		},
	}
	if err := attachProof(receipt, escrowKey, escrowVerificationMethod, depositedAt); err != nil {
		return nil, err
	}
	return receipt, nil
}

// VerifyEscrowReceipt verifies an escrow receipt's proof and structure. Returns
// (ok, subject).
func VerifyEscrowReceipt(receipt map[string]any, escrowPublicKey ed25519.PublicKey) (bool, map[string]any) {
	if !typeContains(receipt, EscrowReceiptType) {
		return false, nil
	}
	if escrowPublicKey == nil {
		return false, nil
	}
	ok, err := VerifyDataIntegrityProof(receipt, escrowPublicKey)
	if err != nil || !ok {
		return false, nil
	}
	subject, _ := receipt["credentialSubject"].(map[string]any)
	if subject == nil {
		return false, nil
	}
	if str(subject["committedDigest"]) == "" || str(subject["depositedAt"]) == "" {
		return false, nil
	}
	return true, subject
}

// SignReasonedActionOptions configures SignReasonedAction.
type SignReasonedActionOptions struct {
	// IncludeReasoning publishes the evidence anchors in the credential. When
	// false, only the digest is published (private reasoning).
	IncludeReasoning bool
	// EscrowReceipt, if set, is attached as proof the commitment was fixed before
	// this action.
	EscrowReceipt map[string]any
	// SealedAt, if set, records the moment the intent was sealed, read by the
	// intent recheck. When escrow is used it SHOULD equal the receipt depositedAt.
	SealedAt string
}

// SignReasonedAction issues a ReasonedActionCredential: the action bound to its
// justification. validFrom is the execution time and the proof created time.
func SignReasonedAction(key ed25519.PrivateKey, issuerDID, verificationMethod string, intent, justification map[string]any, validFrom, credentialID string, opts SignReasonedActionOptions) (map[string]any, error) {
	if !hasActionTarget(intent) {
		return nil, errors.New("intent must be an object with at least action and target")
	}
	digest, err := JustificationDigest(justification)
	if err != nil {
		return nil, err
	}

	jblock := map[string]any{
		"commitment": map[string]any{"algorithm": JustificationAlgorithm, "digest": digest},
	}
	if opts.SealedAt != "" {
		jblock["sealedAt"] = opts.SealedAt
	}
	if lvl, ok := justification["commitmentLevel"]; ok {
		jblock["commitmentLevel"] = lvl
	}
	if opts.EscrowReceipt != nil {
		jblock["escrowReceipt"] = opts.EscrowReceipt
	}
	if opts.IncludeReasoning {
		if anchors, ok := justification["evidenceAnchors"]; ok {
			jblock["evidenceAnchors"] = anchors
		} else {
			jblock["evidenceAnchors"] = []any{}
		}
	}

	credential := map[string]any{
		"@context":  []any{VCContextV2, VouchContextV1},
		"type":      []any{"VerifiableCredential", ReasonedActionType},
		"id":        credentialID,
		"issuer":    issuerDID,
		"validFrom": validFrom,
		"credentialSubject": map[string]any{
			"intent":        intent,
			"justification": jblock,
		},
	}
	if err := attachProof(credential, key, verificationMethod, validFrom); err != nil {
		return nil, err
	}
	return credential, nil
}

// CheckReasonedAction verifies a reasoned-action credential. Returns "" on
// success or a stable reason string on failure. Pass a nil escrowPublicKey when
// no escrow is required. Does not resolve evidence anchors.
func CheckReasonedAction(credential map[string]any, publicKey, escrowPublicKey ed25519.PublicKey, requireEscrow bool) string {
	if !typeContains(credential, ReasonedActionType) {
		return ReasonNotReasonedAction
	}
	ok, err := VerifyDataIntegrityProof(credential, publicKey)
	if err != nil || !ok {
		return ReasonInvalidProof
	}

	jblock := justificationBlock(credential)
	commitment, _ := jblock["commitment"].(map[string]any)
	digest := str(commitment["digest"])
	if digest == "" {
		return ReasonMissingCommitment
	}

	rawReceipt, hasReceipt := jblock["escrowReceipt"]
	receipt, _ := rawReceipt.(map[string]any)
	if !hasReceipt || receipt == nil {
		if requireEscrow {
			return ReasonMissingEscrow
		}
		return ""
	}

	ok, rsubject := VerifyEscrowReceipt(receipt, escrowPublicKey)
	if !ok {
		return ReasonEscrowInvalid
	}
	if str(rsubject["committedDigest"]) != digest {
		return ReasonEscrowDigestMismatch
	}
	deposited, err1 := isoEpoch(str(rsubject["depositedAt"]))
	executed, err2 := isoEpoch(str(credential["validFrom"]))
	if err1 != nil || err2 != nil {
		return ReasonEscrowInvalid
	}
	if deposited > executed {
		return ReasonEscrowAfterExecution
	}
	return ""
}

// VerifyReasonedAction is a convenience wrapper over CheckReasonedAction
// returning (ok, credentialSubject).
func VerifyReasonedAction(credential map[string]any, publicKey, escrowPublicKey ed25519.PublicKey, requireEscrow bool) (bool, map[string]any) {
	if CheckReasonedAction(credential, publicKey, escrowPublicKey, requireEscrow) != "" {
		return false, nil
	}
	subject, _ := credential["credentialSubject"].(map[string]any)
	return true, subject
}

// VerifyJustification checks a revealed justification against a verified
// credential's commitment: the justification must recompute to the committed
// digest, and every anchor must resolve (via resolver) to an artifact whose hash
// matches. resolver returns the artifact for a ref, or nil if unresolved. Returns
// "" on success, else a stable reason string.
func VerifyJustification(presentedJustification, credentialSubject map[string]any, resolver func(ref string) any) string {
	jblock, _ := credentialSubject["justification"].(map[string]any)
	commitment, _ := jblock["commitment"].(map[string]any)
	committed := str(commitment["digest"])
	if committed == "" {
		return ReasonMissingCommitment
	}
	digest, err := JustificationDigest(presentedJustification)
	if err != nil || digest != committed {
		return ReasonJustificationDigestMismatch
	}
	anchors, _ := presentedJustification["evidenceAnchors"].([]any)
	if len(anchors) == 0 {
		return ReasonUnanchoredClaim
	}
	for _, raw := range anchors {
		anchor, _ := raw.(map[string]any)
		ref := str(anchor["ref"])
		var artifact any
		if ref != "" {
			artifact = resolver(ref)
		}
		if artifact == nil {
			return ReasonEvidenceUnresolved
		}
		actual, err := ArtifactDigest(artifact)
		if err != nil || actual != str(anchor["evidenceHash"]) {
			return ReasonEvidenceHashMismatch
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func attachProof(credential map[string]any, key ed25519.PrivateKey, verificationMethod, created string) error {
	t, err := parseISO(created)
	if err != nil {
		return err
	}
	proof, err := BuildDataIntegrityProof(credential, BuildProofOptions{
		PrivateKey:         key,
		VerificationMethod: verificationMethod,
		Created:            t,
	})
	if err != nil {
		return err
	}
	credential["proof"] = proofToMap(proof)
	return nil
}

func hasActionTarget(intent map[string]any) bool {
	return intent != nil && str(intent["action"]) != "" && str(intent["target"]) != ""
}

func justificationBlock(credential map[string]any) map[string]any {
	subject, _ := credential["credentialSubject"].(map[string]any)
	jblock, _ := subject["justification"].(map[string]any)
	return jblock
}

func typeContains(credential map[string]any, want string) bool {
	switch t := credential["type"].(type) {
	case string:
		return t == want
	case []any:
		for _, v := range t {
			if s, ok := v.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func parseISO(s string) (time.Time, error) {
	t, err := time.Parse("2006-01-02T15:04:05Z", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("malformed timestamp: %q", s)
	}
	return t, nil
}

func isoEpoch(s string) (int64, error) {
	t, err := parseISO(s)
	if err != nil {
		return 0, err
	}
	return t.Unix(), nil
}
