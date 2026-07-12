// Root-identity recovery by Shamir secret sharing (the OSS recovery path).
//
// Mirrors vouch/recovery.py and typescript/src/recovery.ts. Splits a root
// identity's Ed25519 seed into n shares so that any t of them reconstruct it,
// and none fewer reveal anything. Hand the shares to guardians, a
// safe-deposit box, or separate locations; gather t only during a deliberate
// recovery.
//
// This is the recovery / escrow primitive. It is distinct from threshold
// signing (FROST), where the key is never reassembled: here the seed IS
// reconstructed at recovery time, so do it on a trusted device and re-seal
// afterwards. Use it for cold recovery of a root, not for hot signing.
//
// The arithmetic is textbook Shamir over GF(2^8) (the AES field). Shares
// carry no integrity tag, so a corrupted share yields a wrong secret rather
// than an error; pair with your own checksum if you need to detect a bad
// share.
package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

// ---------------------------------------------------------------------------
// GF(2^8) arithmetic (AES field, reducing polynomial 0x11b)
// ---------------------------------------------------------------------------

var gfExp [512]byte
var gfLog [256]byte

func init() {
	// 3 (not 2) is a primitive element of GF(2^8) under 0x11b, so powers of 3
	// cycle through all 255 non-zero elements. Multiply by 3 = (x*2) XOR x.
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfLog[x] = byte(i)
		x2 := x << 1
		if x2&0x100 != 0 {
			x2 ^= 0x11B
		}
		x = x2 ^ x
	}
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

func gfInv(a byte) (byte, error) {
	if a == 0 {
		return 0, fmt.Errorf("no inverse for 0 in GF(2^8)")
	}
	return gfExp[255-int(gfLog[a])], nil
}

// evalPoly evaluates a polynomial (coeffs low-order first) at x in GF(2^8).
func evalPoly(coeffs []byte, x byte) byte {
	var result byte
	for i := len(coeffs) - 1; i >= 0; i-- {
		result = gfMul(result, x) ^ coeffs[i]
	}
	return result
}

// interpolateAtZero Lagrange-interpolates the points and returns the value at
// x = 0.
func interpolateAtZero(xs []byte, ys []byte) (byte, error) {
	var result byte
	for i := range xs {
		num := byte(1)
		den := byte(1)
		for j := range xs {
			if i == j {
				continue
			}
			num = gfMul(num, xs[j])       // (0 - xj) == xj in GF(2^8)
			den = gfMul(den, xs[i]^xs[j]) // (xi - xj) == xi ^ xj
		}
		inv, err := gfInv(den)
		if err != nil {
			return 0, err
		}
		result ^= gfMul(ys[i], gfMul(num, inv))
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Byte-level split / combine
// ---------------------------------------------------------------------------

// SplitSecret splits secret into shares pieces; any threshold reconstruct it.
// Each returned share is []byte{index} followed by the share body, where
// index is in 1..shares.
func SplitSecret(secret []byte, threshold, shares int) ([][]byte, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("secret must be non-empty bytes")
	}
	if threshold < 2 || threshold > shares || shares > 255 {
		return nil, fmt.Errorf("require 2 <= threshold <= shares <= 255")
	}

	out := make([][]byte, shares)
	for i := 0; i < shares; i++ {
		out[i] = make([]byte, 1, len(secret)+1)
		out[i][0] = byte(i + 1)
	}

	for _, b := range secret {
		coeffs := make([]byte, threshold)
		coeffs[0] = b
		randBytes := make([]byte, threshold-1)
		if _, err := rand.Read(randBytes); err != nil {
			return nil, fmt.Errorf("rng: %w", err)
		}
		copy(coeffs[1:], randBytes)
		for i := 0; i < shares; i++ {
			out[i] = append(out[i], evalPoly(coeffs, byte(i+1)))
		}
	}
	return out, nil
}

// CombineShares reconstructs a secret from threshold (or more) shares.
// Supplying fewer than the original threshold returns a wrong value, not an
// error.
func CombineShares(shares [][]byte) ([]byte, error) {
	if len(shares) < 2 {
		return nil, fmt.Errorf("need at least 2 shares")
	}
	xs := make([]byte, len(shares))
	bodies := make([][]byte, len(shares))
	seen := make(map[byte]bool, len(shares))
	for i, s := range shares {
		if len(s) < 2 {
			return nil, fmt.Errorf("malformed share")
		}
		xs[i] = s[0]
		if seen[s[0]] {
			return nil, fmt.Errorf("shares must have distinct indices")
		}
		seen[s[0]] = true
		bodies[i] = s[1:]
	}
	length := len(bodies[0])
	for _, b := range bodies {
		if len(b) != length {
			return nil, fmt.Errorf("shares have inconsistent length")
		}
	}

	secret := make([]byte, length)
	for j := 0; j < length; j++ {
		ys := make([]byte, len(bodies))
		for k, b := range bodies {
			ys[k] = b[j]
		}
		v, err := interpolateAtZero(xs, ys)
		if err != nil {
			return nil, err
		}
		secret[j] = v
	}
	return secret, nil
}

// ---------------------------------------------------------------------------
// Vouch identity recovery
// ---------------------------------------------------------------------------

// SplitIdentity splits a root identity's Ed25519 seed into recovery shares.
// Any threshold of them recover the identity via RecoverIdentity. Distribute
// them to separate guardians or locations.
func SplitIdentity(seed []byte, threshold, shares int) ([][]byte, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("seed must be %d bytes", ed25519.SeedSize)
	}
	return SplitSecret(seed, threshold, shares)
}

// RecoveredIdentity is a root identity rebuilt from recovery shares.
type RecoveredIdentity struct {
	DID       string
	Seed      []byte
	PublicKey ed25519.PublicKey
}

// RecoverIdentity recovers a root identity from threshold recovery shares.
// The recovered seed is deterministic, so the rebuilt key is identical to the
// original. Pass did to set it on the result (for example the DID the shares
// were split under); leave it empty to derive a did:key from the recovered
// public key instead.
func RecoverIdentity(shares [][]byte, did string) (*RecoveredIdentity, error) {
	seed, err := CombineShares(shares)
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("recovered seed is not %d bytes; wrong or too few shares", ed25519.SeedSize)
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	if did == "" {
		did, err = DIDKeyFromEd25519(pub)
		if err != nil {
			return nil, err
		}
	}

	return &RecoveredIdentity{DID: did, Seed: seed, PublicKey: pub}, nil
}
