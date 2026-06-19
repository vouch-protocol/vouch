// Multikey encoding for verification methods.
//
// Mirrors vouch/multikey.py and typescript/src/multikey.ts. Per 
// Controlled Identifiers specification, public keys in DID Documents are
// encoded as a Multikey:
//
//	publicKeyMultibase = base58btc( multicodec_prefix || raw_public_key_bytes )
//
// The leading 'z' character indicates base58btc encoding. Cross-implementation
// interop with the Python and TypeScript modules is REQUIRED.
//
// Supported algorithms (Specification §13.5):
//
//	Ed25519    multicodec prefix 0xed01  (32-byte key)
//	ML-DSA-44   multicodec prefix 0x1207  (1312-byte key, provisional)

package signer

import (
	"errors"
	"fmt"
	"math/big"
)

// Multicodec prefixes as 2-byte sequences.
var (
	Ed25519PubPrefix = []byte{0xed, 0x01}
	Ed25519PrivPrefix = []byte{0x80, 0x26}
	MLDSA44PubPrefix = []byte{0x87, 0x24}
	MLDSA44PrivPrefix = []byte{0x88, 0x24}
)

const b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// EncodeEd25519Public encodes a 32-byte Ed25519 public key as a Multikey
// string (z-prefixed base58btc).
func EncodeEd25519Public(rawKey []byte) (string, error) {
	if len(rawKey) != 32 {
		return "", fmt.Errorf("Ed25519 public key must be 32 bytes, got %d", len(rawKey))
	}
	buf := append([]byte{}, Ed25519PubPrefix...)
	buf = append(buf, rawKey...)
	return "z" + b58Encode(buf), nil
}

// EncodeMLDSA44Public encodes a 1312-byte ML-DSA-44 public key as a Multikey
// string. Used in the hybrid post-quantum profile (Specification §13.2).
func EncodeMLDSA44Public(rawKey []byte) (string, error) {
	if len(rawKey) != 1312 {
		return "", fmt.Errorf("ML-DSA-44 public key must be 1312 bytes, got %d", len(rawKey))
	}
	buf := append([]byte{}, MLDSA44PubPrefix...)
	buf = append(buf, rawKey...)
	return "z" + b58Encode(buf), nil
}

// MultikeyDecode decodes a Multikey string into algorithm name and raw key bytes.
func MultikeyDecode(multikey string) (algorithm string, rawKey []byte, err error) {
	if len(multikey) == 0 || multikey[0] != 'z' {
		return "", nil, errors.New("Multikey must use base58btc encoding (z-prefix)")
	}
	decoded, err := b58Decode(multikey[1:])
	if err != nil {
		return "", nil, err
	}
	if len(decoded) < 2 {
		return "", nil, errors.New("Multikey too short")
	}
	prefix := decoded[:2]
	switch {
	case prefix[0] == Ed25519PubPrefix[0] && prefix[1] == Ed25519PubPrefix[1]:
		return "Ed25519", decoded[2:], nil
	case prefix[0] == Ed25519PrivPrefix[0] && prefix[1] == Ed25519PrivPrefix[1]:
		return "Ed25519", decoded[2:], nil
	case prefix[0] == MLDSA44PubPrefix[0] && prefix[1] == MLDSA44PubPrefix[1]:
		return "ML-DSA-44", decoded[2:], nil
	case prefix[0] == MLDSA44PrivPrefix[0] && prefix[1] == MLDSA44PrivPrefix[1]:
		return "ML-DSA-44", decoded[2:], nil
	}
	return "", nil, fmt.Errorf("unknown multicodec prefix: %02x%02x", prefix[0], prefix[1])
}

// MultikeyAlgorithm returns the algorithm name encoded in a Multikey
// without exposing raw key bytes.
func MultikeyAlgorithm(multikey string) (string, error) {
	alg, _, err := MultikeyDecode(multikey)
	return alg, err
}

// ---------------------------------------------------------------------------
// base58btc primitive (vendored to avoid dependencies)
// ---------------------------------------------------------------------------

func b58Encode(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	nZero := 0
	for _, b := range data {
		if b == 0 {
			nZero++
		} else {
			break
		}
	}
	num := new(big.Int).SetBytes(data)
	div := big.NewInt(58)
	mod := new(big.Int)
	encoded := make([]byte, 0, len(data)*2)
	for num.Sign() > 0 {
		num.DivMod(num, div, mod)
		encoded = append(encoded, b58Alphabet[mod.Int64()])
	}
	// Reverse and prepend leading zeros.
	for i, j := 0, len(encoded)-1; i < j; i, j = i+1, j-1 {
		encoded[i], encoded[j] = encoded[j], encoded[i]
	}
	prefix := make([]byte, nZero)
	for i := range prefix {
		prefix[i] = '1'
	}
	return string(append(prefix, encoded...))
}

func b58Decode(s string) ([]byte, error) {
	if len(s) == 0 {
		return []byte{}, nil
	}
	nZero := 0
	for _, ch := range s {
		if ch == '1' {
			nZero++
		} else {
			break
		}
	}
	num := big.NewInt(0)
	base := big.NewInt(58)
	for _, ch := range s {
		idx := indexInAlphabet(ch)
		if idx < 0 {
			return nil, fmt.Errorf("invalid base58 character: %q", ch)
		}
		num.Mul(num, base)
		num.Add(num, big.NewInt(int64(idx)))
	}
	body := num.Bytes()
	out := make([]byte, nZero+len(body))
	copy(out[nZero:], body)
	return out, nil
}

func indexInAlphabet(ch rune) int {
	for i, c := range b58Alphabet {
		if c == ch {
			return i
		}
	}
	return -1
}
