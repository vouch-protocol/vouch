// Model-and-config provenance attestation for robots (Phase 5.2), Go.
//
// Mirrors vouch/robotics/provenance.py and the TypeScript SDK with byte-identical
// output. A ModelProvenanceAttestation is an eddsa-jcs-2022 VC recording the VLA
// model name, weights hash, safety policy, and a configHash computed over the
// JCS-canonical config so any verifier reproduces it. It is re-signable on an OTA
// update via supersedes, forming a tamper-evident chain.
package robotics

import (
	"crypto/ed25519"
	"crypto/sha256"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// ModelProvenanceType is the credential type for a provenance attestation.
const ModelProvenanceType = "ModelProvenanceAttestation"

// ConfigHash returns the multibase SHA-256 of the JCS-canonical config object.
// Python, TypeScript, and Go all canonicalize identically, so the digest is the
// same byte string in every language.
func ConfigHash(config map[string]any) (string, error) {
	canon, err := signer.Canonicalize(config)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return mb64(sum[:]), nil
}

// BuildProvenanceOptions configures BuildProvenanceAttestation. RobotDID names
// the robot the attestation is about; the issuer is the signer (the robot itself
// or an authority attesting on its behalf).
type BuildProvenanceOptions struct {
	RobotDID     string
	ModelName    string
	WeightsHash  string
	SafetyPolicy string
	Config       map[string]any // optional; nil omits configHash
	Version      string         // optional; "" omits the field
	Supersedes   string         // optional; "" omits the field (prior attestation id)
	ValidSeconds int            // 0 omits validUntil
	ValidFrom    time.Time      // zero uses now
}

// BuildProvenanceAttestation builds a signed ModelProvenanceAttestation for the
// software running on a robot.
func BuildProvenanceAttestation(s *signer.Signer, opts BuildProvenanceOptions) (map[string]any, error) {
	issued := opts.ValidFrom
	if issued.IsZero() {
		issued = time.Now().UTC()
	}

	vla := map[string]any{
		"modelName":    opts.ModelName,
		"weightsHash":  opts.WeightsHash,
		"safetyPolicy": opts.SafetyPolicy,
	}
	if opts.Version != "" {
		vla["version"] = opts.Version
	}
	if opts.Config != nil {
		ch, err := ConfigHash(opts.Config)
		if err != nil {
			return nil, err
		}
		vla["configHash"] = ch
	}

	subject := map[string]any{"id": opts.RobotDID, "vla": vla}
	if opts.Supersedes != "" {
		subject["supersedes"] = opts.Supersedes
	}

	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", ModelProvenanceType},
		"issuer":            s.DID(),
		"validFrom":         iso(issued),
		"credentialSubject": subject,
	}
	if opts.ValidSeconds > 0 {
		cred["validUntil"] = iso(issued.Add(time.Duration(opts.ValidSeconds) * time.Second))
	}
	return s.AttachProof(cred)
}

// VerifyProvenanceAttestation verifies a ModelProvenanceAttestation proof. When
// config is non-nil, it also checks that the recorded configHash reproduces from
// that config. Returns (ok, credentialSubject).
func VerifyProvenanceAttestation(att map[string]any, pub ed25519.PublicKey, config map[string]any) (bool, map[string]any) {
	if !hasType(att["type"], ModelProvenanceType) {
		return false, nil
	}
	ok, err := signer.VerifyDataIntegrityProof(att, pub)
	if err != nil || !ok {
		return false, nil
	}

	subject, _ := att["credentialSubject"].(map[string]any)
	if config != nil {
		vla, _ := subject["vla"].(map[string]any)
		want, err := ConfigHash(config)
		if err != nil {
			return false, nil
		}
		if got, _ := vla["configHash"].(string); got != want {
			return false, nil
		}
	}
	return true, subject
}
