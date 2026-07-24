// Post-quantum signing for robot credentials, Go.
//
// Mirrors vouch/robotics/pq.py. A robot fielded today lives for ten to twenty
// years, longer than classical Ed25519 is expected to stay safe, so a robot
// identity signed now could be forged once a quantum computer arrives. This
// file makes the post-quantum proof set (an eddsa-jcs-2022 proof alongside an
// mldsa44-jcs-2024 proof, carried as a `proof` array) the recommended default
// for robot credentials, so they stay unforgeable across the robot's whole
// service life. The pre-alignment composite cryptosuite
// (hybrid-eddsa-mldsa44-jcs-2026) is still accepted on verification.
//
//   - SignPq: attach a hybrid proof to a robot credential.
//   - VerifyRobotCredential: verify a robot credential whether it carries a
//     classical or a hybrid proof, auto-detected from the proof, so a fleet can
//     move to PQ gradually without breaking the classical credentials already
//     in the field.
//   - MigrateToPq: re-sign a fielded robot's classical credential under PQ.
//
// This is the open layer: hybrid signing, backward-compatible verification, and
// a software re-signing migration path. Managed PQ key custody and fleet-wide
// PQ migration orchestration are out of scope for the open layer.
package robotics

import (
	"crypto/ed25519"
	"errors"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// The cryptosuite identifiers a robot credential can carry.
const (
	// ClassicalCryptosuite is the Ed25519 proof, present on its own in a
	// classical credential and as one half of a post-quantum proof set.
	ClassicalCryptosuite = "eddsa-jcs-2022"

	// PostQuantumCryptosuite is the ML-DSA-44 proof emitted as the
	// post-quantum half of a proof set.
	PostQuantumCryptosuite = signer.CryptosuiteMLDSA44Jcs2024

	// HybridCryptosuite is the pre-alignment composite proof. Accepted on
	// verification only; never emitted.
	HybridCryptosuite = signer.CryptosuiteHybridEddsaMldsa44
)

// coerceMLDSA44Public resolves an ML-DSA-44 public key given either raw key
// bytes or a Multikey string (z-prefixed base58btc). Decoding of the Multikey
// reuses the existing signer.MultikeyDecode helper.
func coerceMLDSA44Public(publicKey any) (*mldsa44.PublicKey, error) {
	var raw []byte
	switch v := publicKey.(type) {
	case *mldsa44.PublicKey:
		return v, nil
	case []byte:
		raw = v
	case string:
		alg, decoded, err := signer.MultikeyDecode(v)
		if err != nil {
			return nil, err
		}
		if alg != "ML-DSA-44" {
			return nil, errors.New("robotics: expected an ML-DSA-44 multikey, got " + alg)
		}
		raw = decoded
	default:
		return nil, errors.New("robotics: ML-DSA-44 public key must be raw bytes or a Multikey string")
	}
	pub := new(mldsa44.PublicKey)
	if err := pub.UnmarshalBinary(raw); err != nil {
		return nil, err
	}
	return pub, nil
}

// SignPq attaches a post-quantum proof set (a classical Ed25519 proof plus an
// ML-DSA-44 proof) to a pre-built robot credential. Any existing proof is
// replaced.
func SignPq(credential map[string]any, s *signer.Signer) (map[string]any, error) {
	body := make(map[string]any, len(credential))
	for k, v := range credential {
		if k == "proof" {
			continue
		}
		body[k] = v
	}
	return s.AttachHybridProof(body)
}

// IsPq reports whether credential carries a post-quantum proof, either the
// current proof set (an array holding an ML-DSA-44 proof) or the pre-alignment
// composite proof object.
func IsPq(credential map[string]any) bool {
	switch proof := credential["proof"].(type) {
	case map[string]any:
		c, _ := proof["cryptosuite"].(string)
		return c == HybridCryptosuite
	case []any:
		for _, item := range proof {
			p, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if isMLDSA44Cryptosuite(p) {
				return true
			}
		}
	case []map[string]any:
		for _, p := range proof {
			if isMLDSA44Cryptosuite(p) {
				return true
			}
		}
	}
	return false
}

func isMLDSA44Cryptosuite(proof map[string]any) bool {
	switch c, _ := proof["cryptosuite"].(string); c {
	case signer.CryptosuiteMLDSA44Jcs2024, signer.CryptosuiteMLDSA44JcsLegacy:
		return true
	}
	return false
}

// VerifyPq verifies a post-quantum robot credential. Both the Ed25519 and the
// ML-DSA-44 signature must validate. The current proof set and the
// pre-alignment composite proof are both accepted. mldsa44PublicKey is raw
// bytes or a Multikey string.
func VerifyPq(credential map[string]any, ed25519PublicKey ed25519.PublicKey, mldsa44PublicKey any) bool {
	if ed25519PublicKey == nil {
		return false
	}
	mlPub, err := coerceMLDSA44Public(mldsa44PublicKey)
	if err != nil {
		return false
	}
	if _, isComposite := credential["proof"].(map[string]any); isComposite {
		ok, err := signer.VerifyHybridDataIntegrityProof(credential, ed25519PublicKey, mlPub)
		if err != nil {
			return false
		}
		return ok
	}
	ok, err := signer.VerifyDualProof(credential, ed25519PublicKey, mlPub)
	if err != nil {
		return false
	}
	return ok
}

// VerifyRobotCredentialOptions configures VerifyRobotCredential. Mldsa44PublicKey
// is required to verify a post-quantum credential (raw bytes or a Multikey
// string) and ignored for a classical credential.
type VerifyRobotCredentialOptions struct {
	Mldsa44PublicKey any
}

// VerifyRobotCredential verifies a robot credential whether it carries a
// classical or a hybrid proof, auto-detected from the proof cryptosuite. A
// hybrid credential requires opts.Mldsa44PublicKey; a classical credential
// ignores it. This is the backward-compatible verify a fleet uses while
// migrating to PQ.
func VerifyRobotCredential(credential map[string]any, ed25519PublicKey ed25519.PublicKey, opts VerifyRobotCredentialOptions) bool {
	if IsPq(credential) {
		if opts.Mldsa44PublicKey == nil {
			return false
		}
		return VerifyPq(credential, ed25519PublicKey, opts.Mldsa44PublicKey)
	}
	// Supplying an ML-DSA-44 key means the caller requires the post-quantum
	// proof. A credential that is not a post-quantum proof set is rejected
	// rather than verified under Ed25519 alone, so a stripped proof set cannot
	// be accepted as classical. A caller that accepts classical credentials
	// passes no ML-DSA key.
	if opts.Mldsa44PublicKey != nil {
		return false
	}
	if ed25519PublicKey == nil {
		return false
	}
	ok, err := signer.VerifyDataIntegrityProof(credential, ed25519PublicKey)
	if err != nil {
		return false
	}
	return ok
}

// MigrateToPq re-signs a fielded robot's classical credential under the
// post-quantum proof set, preserving its body. The signer holds the robot's
// current key.
func MigrateToPq(credential map[string]any, s *signer.Signer) (map[string]any, error) {
	return SignPq(credential, s)
}
