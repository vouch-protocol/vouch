// Fused-sensor provenance: signed provenance for a robot's fused world model, Go.
//
// Mirrors vouch/robotics/fusion.py and the other SDKs. Perception provenance
// signs individual sensor frames. A robot rarely acts on one frame, though: it
// fuses many frames, from cameras, lidar, radar, and other sensors, into a
// single world model, an object set, an occupancy grid, or a pose estimate, and
// acts on that. This module binds a fused output to the exact set of input
// frames that produced it and the fusion method that produced it, signed by the
// robot, so a manipulated fusion result or a silently dropped or substituted
// input is detectable at the provenance layer.
//
// A fused-perception attestation carries the hash of the fused output, an
// ordered list of the input frame hashes, a digest over those inputs, and a
// fusion method identifier, signed by the robot. A verifier reproduces the input
// digest from the listed inputs and, when it holds the raw fused output,
// reproduces its hash, so the attestation commits to exactly those inputs and
// that output. Checking each listed input against the robot's signed perception
// log confirms every fused input traces to a frame the robot actually recorded.
//
// The fused output and the frames themselves are not carried here, only their
// hashes, so the attestation stays small and the raw data can live wherever the
// deployment keeps it. This is the open layer: the robot signs the binding of a
// fused output to its inputs in software, reusing the perception frame hashes.
// Hardware sensor attestation and managed sensor-fusion orchestration are out of
// scope for the open layer.
package robotics

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"strings"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// FusedPerceptionType is the fused-sensor provenance attestation credential type.
const FusedPerceptionType = "FusedPerceptionAttestation"

// HashFusedOutput returns the multibase (base64url) SHA-256 of a raw fused output.
func HashFusedOutput(output []byte) string {
	sum := sha256.Sum256(output)
	return mb64(sum[:])
}

// FusionInputsDigest returns a deterministic multibase digest over an ordered
// list of input frame hashes. The digest commits to the exact inputs and their
// order, so adding, removing, or reordering an input changes it. Reproduced
// byte-identically across language SDKs: the SHA-256 is taken over the UTF-8
// bytes of the hashes joined by "\n".
func FusionInputsDigest(inputFrameHashes []string) (string, error) {
	if len(inputFrameHashes) == 0 {
		return "", errors.New("robotics: input_frame_hashes must be a non-empty list")
	}
	for _, h := range inputFrameHashes {
		if h == "" {
			return "", errors.New("robotics: each input frame hash must be a non-empty string")
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(inputFrameHashes, "\n")))
	return mb64(sum[:]), nil
}

// BuildFusedAttestationOptions configures BuildFusedAttestation. Provide either
// FusedOutput (it is hashed) or a precomputed FusedOutputHash, not both. A zero
// CapturedAt uses the issue time; a zero ValidFrom uses now; a zero ValidSeconds
// omits validUntil.
type BuildFusedAttestationOptions struct {
	RobotDID         string
	FusionMethod     string
	InputFrameHashes []string
	FusedOutput      []byte // nil uses FusedOutputHash
	FusedOutputHash  string // ignored when FusedOutput is non-nil
	CapturedAt       time.Time
	ValidSeconds     int
	ValidFrom        time.Time
}

// BuildFusedAttestation builds a signed FusedPerceptionAttestation: the robot
// attests that a fused output was produced by FusionMethod from the frames named
// in InputFrameHashes. The attestation carries a digest over the ordered inputs,
// so the set of inputs is tamper-evident. Signed by the robot. The issuer is
// RobotDID.
func BuildFusedAttestation(robotSigner *signer.Signer, opts BuildFusedAttestationOptions) (map[string]any, error) {
	if opts.RobotDID == "" {
		return nil, errors.New("robotics: robot_did is required")
	}
	if opts.FusionMethod == "" {
		return nil, errors.New("robotics: fusion_method is required")
	}
	if len(opts.InputFrameHashes) == 0 {
		return nil, errors.New("robotics: input_frame_hashes must be a non-empty list")
	}
	if opts.FusedOutput != nil && opts.FusedOutputHash != "" {
		return nil, errors.New("robotics: provide either fused_output or fused_output_hash, not both")
	}
	fusedOutputHash := opts.FusedOutputHash
	if opts.FusedOutput != nil {
		fusedOutputHash = HashFusedOutput(opts.FusedOutput)
	}
	if fusedOutputHash == "" {
		return nil, errors.New("robotics: fused_output or fused_output_hash is required")
	}

	inputsDigest, err := FusionInputsDigest(opts.InputFrameHashes)
	if err != nil {
		return nil, err
	}

	issued := opts.ValidFrom
	if issued.IsZero() {
		issued = time.Now().UTC()
	}
	captured := opts.CapturedAt
	if captured.IsZero() {
		captured = issued
	}

	inputHashes := make([]any, len(opts.InputFrameHashes))
	for i, h := range opts.InputFrameHashes {
		inputHashes[i] = h
	}
	subject := map[string]any{
		"id":               opts.RobotDID,
		"fusionMethod":     opts.FusionMethod,
		"fusedOutputHash":  fusedOutputHash,
		"inputFrameHashes": inputHashes,
		"inputsDigest":     inputsDigest,
		"capturedAt":       iso(captured),
	}

	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", FusedPerceptionType},
		"issuer":            opts.RobotDID,
		"validFrom":         iso(issued),
		"credentialSubject": subject,
	}
	if opts.ValidSeconds > 0 {
		cred["validUntil"] = iso(issued.Add(time.Duration(opts.ValidSeconds) * time.Second))
	}
	return robotSigner.AttachProof(cred)
}

// VerifyFusedAttestation verifies a FusedPerceptionAttestation: the robot's
// proof, that the digest over the listed inputs reproduces the attested
// inputsDigest (so the inputs are internally consistent and tamper-evident),
// and, when the raw fusedOutput is supplied, that its hash reproduces the
// attested fusedOutputHash. Returns (ok, credentialSubject).
func VerifyFusedAttestation(cred map[string]any, pub ed25519.PublicKey, fusedOutput []byte) (bool, map[string]any) {
	ok, subject := verifyTyped(cred, pub, FusedPerceptionType)
	if !ok || subject == nil {
		return false, nil
	}

	fusedOutputHash, _ := subject["fusedOutputHash"].(string)
	inputs := stringSlice(subject["inputFrameHashes"])
	if fusedOutputHash == "" || len(inputs) == 0 {
		return false, nil
	}

	digest, err := FusionInputsDigest(inputs)
	if err != nil {
		return false, nil
	}
	attested, _ := subject["inputsDigest"].(string)
	if digest != attested {
		return false, nil
	}

	if fusedOutput != nil && HashFusedOutput(fusedOutput) != fusedOutputHash {
		return false, nil
	}
	return true, subject
}

// VerifyFusionInputs confirms every input frame the attestation names was
// actually recorded in the robot's perception log. Returns (ok, missing), where
// missing lists the input frame hashes that do not appear as a recorded frame,
// so a dropped or substituted fused input is named rather than hidden.
func VerifyFusionInputs(cred map[string]any, logEntries []map[string]any) (bool, []string) {
	recorded := make(map[string]struct{}, len(logEntries))
	for _, e := range logEntries {
		if h, ok := e["frameHash"].(string); ok && h != "" {
			recorded[h] = struct{}{}
		}
	}
	subject, _ := cred["credentialSubject"].(map[string]any)
	inputs := stringSlice(subject["inputFrameHashes"])
	missing := []string{}
	for _, h := range inputs {
		if _, ok := recorded[h]; !ok {
			missing = append(missing, h)
		}
	}
	return len(missing) == 0, missing
}

// stringSlice coerces a credential field to a []string, accepting either a
// native []string or the []any that survives a JSON round-trip.
func stringSlice(v any) []string {
	switch xs := v.(type) {
	case []string:
		return xs
	case []any:
		out := make([]string, 0, len(xs))
		for _, x := range xs {
			s, ok := x.(string)
			if !ok {
				return nil
			}
			out = append(out, s)
		}
		return out
	default:
		return nil
	}
}
