// Post-quantum signing for robot credentials, Go.
//
// Mirrors vouch/robotics/pq.py. A robot fielded today lives for ten to twenty
// years, longer than classical Ed25519 is expected to stay safe, so a robot
// identity signed now could be forged once a quantum computer arrives. This
// file makes the hybrid post-quantum cryptosuite
// (hybrid-eddsa-mldsa44-jcs-2026, a classical Ed25519 signature alongside an
// ML-DSA-44 signature) the recommended default for robot credentials, so they
// stay unforgeable across the robot's whole service life.
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

// ClassicalCryptosuite and HybridCryptosuite name the two proof cryptosuites a
// robot credential can carry.
const (
	ClassicalCryptosuite = "eddsa-jcs-2022"
	HybridCryptosuite    = signer.CryptosuiteHybridEddsaMldsa44
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

// SignPq attaches a hybrid (classical Ed25519 plus post-quantum ML-DSA-44) Data
// Integrity proof to a pre-built robot credential. Any existing proof is
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

// IsPq reports whether credential carries a hybrid post-quantum proof.
func IsPq(credential map[string]any) bool {
	proof, _ := credential["proof"].(map[string]any)
	if proof == nil {
		return false
	}
	c, _ := proof["cryptosuite"].(string)
	return c == HybridCryptosuite
}

// VerifyPq verifies a hybrid robot credential. Both the Ed25519 and the
// ML-DSA-44 signature must validate. mldsa44PublicKey is raw bytes or a
// Multikey string.
func VerifyPq(credential map[string]any, ed25519PublicKey ed25519.PublicKey, mldsa44PublicKey any) bool {
	if ed25519PublicKey == nil {
		return false
	}
	mlPub, err := coerceMLDSA44Public(mldsa44PublicKey)
	if err != nil {
		return false
	}
	ok, err := signer.VerifyHybridDataIntegrityProof(credential, ed25519PublicKey, mlPub)
	if err != nil {
		return false
	}
	return ok
}

// VerifyRobotCredentialOptions configures VerifyRobotCredential. Mldsa44PublicKey
// is required to verify a hybrid credential (raw bytes or a Multikey string) and
// ignored for a classical credential.
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
	if ed25519PublicKey == nil {
		return false
	}
	ok, err := signer.VerifyDataIntegrityProof(credential, ed25519PublicKey)
	if err != nil {
		return false
	}
	return ok
}

// MigrateToPq re-signs a fielded robot's classical credential under the hybrid
// PQ cryptosuite, preserving its body. The signer holds the robot's current key.
func MigrateToPq(credential map[string]any, s *signer.Signer) (map[string]any, error) {
	return SignPq(credential, s)
}
