//go:build frost

// FROST(Ed25519, SHA-512) threshold signing (RFC 9591).
//
// Gated behind the "frost" build tag (go build -tags frost / go test -tags
// frost) so the rest of this module stays pure Go with no cgo and no native
// library requirement; only code that explicitly opts into FROST needs a C
// toolchain and libvouch_core_uniffi at build and run time (see
// build-native.sh). Plain `go build ./...` / `go test ./...` are completely
// unaffected by this file.
//
// A key is split among max_signers participants so that any min_signers of
// them can produce a signature together, WITHOUT the full private key ever
// being reconstructed at any point, not even during signing. This is
// distinct from recovery.go (Shamir secret sharing), where the secret IS
// reconstructed at recovery time; FROST is for live, repeated signing across
// a threshold of custodians, and the key never exists whole anywhere.
//
// The critical property that makes this a drop-in fit for Vouch: the
// aggregated signature is a STANDARD Ed25519 signature, so it verifies with
// the existing VerifyDataIntegrityProof and needs no new proof type. Combine
// it with NewBackend to get a Signer whose sign callback runs a
// threshold-signing ceremony instead of holding a raw key.
//
// Unlike the rest of this package (a pure Go reimplementation of the
// protocol's signing and verification), this file is a cgo binding to the
// same audited Rust core (frost-ed25519, the Zcash Foundation crate, RFC
// 9591) that backs the Python, TypeScript, JVM, .NET, C++, and Swift SDKs,
// so every language produces byte-identical results from one implementation
// rather than a second, independently-reviewed FROST implementation in Go.
// This requires CGO_ENABLED=1 and the native vouch_core_uniffi shared
// library available at build and run time (see build-native.sh); a plain
// `go build` of this package needs a C toolchain, unlike the rest of the
// module.
//
// There is deliberately no "reconstruct" function here. Nothing in this
// file takes key shares and returns a seed or a private scalar.
package signer

/*
#cgo LDFLAGS: -L${SRCDIR}/../lib -lvouch_core_uniffi
#include <stdint.h>
#include <stdlib.h>

extern char *vouch_threshold_generate_key(uint16_t min_signers, uint16_t max_signers, char **err_out);
extern char *vouch_threshold_commit(const char *key_share_json, char **err_out);
extern char *vouch_threshold_sign_share(const char *message_b64, const char *key_share_json, const char *nonces_b64, const char *commitments_json, char **err_out);
extern char *vouch_threshold_aggregate(const char *message_b64, const char *commitments_json, const char *shares_json, const char *group_public_key_json, char **err_out);
extern void vouch_string_free(char *s);
*/
import "C"

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"unsafe"
)

// ThresholdError is returned when the native FROST core reports an error.
type ThresholdError struct{ msg string }

func (e *ThresholdError) Error() string { return e.msg }

// KeyShare is one participant's share of a threshold key. KeyPackage is
// secret key material and must be kept only by the participant it was
// issued to.
type KeyShare struct {
	Identifier string `json:"identifier"`  // base64
	KeyPackage string `json:"key_package"` // base64, SECRET
}

// GroupPublicKey is the threshold group's public identity. VerifyingKey is
// a standard 32-byte Ed25519 public key (base64): publish it as the DID's
// verification method key, exactly like any other Vouch identity's key.
type GroupPublicKey struct {
	VerifyingKey     string `json:"verifying_key"`      // base64, 32 bytes
	PublicKeyPackage string `json:"public_key_package"` // base64, needed to aggregate
}

// GenerateKeyResult is the output of ThresholdGenerateKey.
type GenerateKeyResult struct {
	Shares         []KeyShare     `json:"shares"`
	GroupPublicKey GroupPublicKey `json:"group_public_key"`
}

// Round1 is one signer's round-1 output: secret nonces and a public commitment.
type Round1 struct {
	Nonces      string `json:"nonces"`      // base64, SECRET, single-use
	Commitments string `json:"commitments"` // base64, public
}

// callThreshold invokes a C-ABI threshold_* function and converts its
// (result, err_out) pair into a Go (string, error) pair, freeing whichever
// heap string the core returned.
func callThreshold(fn func(errOut **C.char) *C.char) (string, error) {
	var errOut *C.char
	result := fn(&errOut)
	if result == nil {
		msg := "unknown error"
		if errOut != nil {
			msg = C.GoString(errOut)
			C.vouch_string_free(errOut)
		}
		return "", &ThresholdError{msg}
	}
	s := C.GoString(result)
	C.vouch_string_free(result)
	return s, nil
}

func cCString(s string) *C.char {
	return C.CString(s)
}

// ThresholdGenerateKey mints a fresh threshold-native Ed25519 identity:
// maxSigners key shares, any minSigners of which can sign together, and a
// group public key. This mints a NEW identity; it does not convert an
// existing single-key Ed25519 identity (see this file's package doc for why).
func ThresholdGenerateKey(minSigners, maxSigners uint16) (*GenerateKeyResult, error) {
	raw, err := callThreshold(func(errOut **C.char) *C.char {
		return C.vouch_threshold_generate_key(C.uint16_t(minSigners), C.uint16_t(maxSigners), errOut)
	})
	if err != nil {
		return nil, err
	}
	var result GenerateKeyResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, &ThresholdError{fmt.Sprintf("invalid JSON from core: %v", err)}
	}
	return &result, nil
}

// ThresholdCommit runs round 1 for one signer: it generates single-use
// signing nonces and a public commitment. Nonces MUST be used for exactly
// one ThresholdSignShare call and then discarded; reusing them leaks the
// signer's key share.
func ThresholdCommit(keyShare KeyShare) (*Round1, error) {
	keyShareJSON, err := json.Marshal(keyShare)
	if err != nil {
		return nil, &ThresholdError{fmt.Sprintf("marshal key share: %v", err)}
	}
	cKeyShare := cCString(string(keyShareJSON))
	defer C.free(unsafe.Pointer(cKeyShare))

	raw, err := callThreshold(func(errOut **C.char) *C.char {
		return C.vouch_threshold_commit(cKeyShare, errOut)
	})
	if err != nil {
		return nil, err
	}
	var round1 Round1
	if err := json.Unmarshal([]byte(raw), &round1); err != nil {
		return nil, &ThresholdError{fmt.Sprintf("invalid JSON from core: %v", err)}
	}
	return &round1, nil
}

// ThresholdSignShare runs round 2 for one signer: given the message and
// every participating signer's commitment, it produces a signature share
// using this signer's own key share and its own (single-use) nonces from
// ThresholdCommit. commitmentsByParticipant maps each participant's base64
// identifier to its base64 commitment, including this signer's own. Returns
// the base64-encoded signature share.
func ThresholdSignShare(
	message []byte, keyShare KeyShare, nonces string, commitmentsByParticipant map[string]string,
) (string, error) {
	keyShareJSON, err := json.Marshal(keyShare)
	if err != nil {
		return "", &ThresholdError{fmt.Sprintf("marshal key share: %v", err)}
	}
	commitmentsJSON, err := json.Marshal(commitmentsByParticipant)
	if err != nil {
		return "", &ThresholdError{fmt.Sprintf("marshal commitments: %v", err)}
	}

	cMessage := cCString(base64.StdEncoding.EncodeToString(message))
	cKeyShare := cCString(string(keyShareJSON))
	cNonces := cCString(nonces)
	cCommitments := cCString(string(commitmentsJSON))
	defer C.free(unsafe.Pointer(cMessage))
	defer C.free(unsafe.Pointer(cKeyShare))
	defer C.free(unsafe.Pointer(cNonces))
	defer C.free(unsafe.Pointer(cCommitments))

	return callThreshold(func(errOut **C.char) *C.char {
		return C.vouch_threshold_sign_share(cMessage, cKeyShare, cNonces, cCommitments, errOut)
	})
}

// ThresholdAggregate combines minSigners (or more) signature shares into the
// final, standard Ed25519 signature. Verify the result with
// VerifyDataIntegrityProof against groupPublicKey.VerifyingKey, exactly like
// any other Vouch credential.
func ThresholdAggregate(
	message []byte,
	commitmentsByParticipant map[string]string,
	sharesByParticipant map[string]string,
	groupPublicKey GroupPublicKey,
) ([]byte, error) {
	commitmentsJSON, err := json.Marshal(commitmentsByParticipant)
	if err != nil {
		return nil, &ThresholdError{fmt.Sprintf("marshal commitments: %v", err)}
	}
	sharesJSON, err := json.Marshal(sharesByParticipant)
	if err != nil {
		return nil, &ThresholdError{fmt.Sprintf("marshal shares: %v", err)}
	}
	groupPublicKeyJSON, err := json.Marshal(groupPublicKey)
	if err != nil {
		return nil, &ThresholdError{fmt.Sprintf("marshal group public key: %v", err)}
	}

	cMessage := cCString(base64.StdEncoding.EncodeToString(message))
	cCommitments := cCString(string(commitmentsJSON))
	cShares := cCString(string(sharesJSON))
	cGroupPublicKey := cCString(string(groupPublicKeyJSON))
	defer C.free(unsafe.Pointer(cMessage))
	defer C.free(unsafe.Pointer(cCommitments))
	defer C.free(unsafe.Pointer(cShares))
	defer C.free(unsafe.Pointer(cGroupPublicKey))

	sigB64, err := callThreshold(func(errOut **C.char) *C.char {
		return C.vouch_threshold_aggregate(cMessage, cCommitments, cShares, cGroupPublicKey, errOut)
	})
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, &ThresholdError{fmt.Sprintf("invalid base64 signature from core: %v", err)}
	}
	return sig, nil
}

// ThresholdSigner runs a full commit/sign-share/aggregate ceremony in one
// call. It holds minSigners (or more) key shares locally and produces a
// signature over any message with a single Sign call, running round 1,
// round 2, and aggregation across the shares it holds. This fits a
// coordinator process with access to enough shares to sign (for example, a
// service with several custodian shares mounted, or a test harness); a true
// multi-device ceremony instead calls ThresholdCommit / ThresholdSignShare /
// ThresholdAggregate directly across devices, passing commitments and
// shares over the network.
//
// Pass Sign to NewBackend to get a Signer backed by threshold signing.
type ThresholdSigner struct {
	shares         []KeyShare
	groupPublicKey GroupPublicKey
}

// NewThresholdSigner creates a ThresholdSigner over the given key shares.
func NewThresholdSigner(shares []KeyShare, groupPublicKey GroupPublicKey) (*ThresholdSigner, error) {
	if len(shares) < 2 {
		return nil, &ThresholdError{"ThresholdSigner needs at least 2 key shares"}
	}
	return &ThresholdSigner{shares: shares, groupPublicKey: groupPublicKey}, nil
}

// Sign signs digest via a full commit/sign-share/aggregate ceremony across
// the held shares. Matches the func(digest []byte) []byte shape NewBackend
// expects; panics if the ceremony fails (a healthy set of shares should
// never fail this call), since that callback type has no error return.
func (t *ThresholdSigner) Sign(digest []byte) []byte {
	noncesByID := make(map[string]string, len(t.shares))
	commitments := make(map[string]string, len(t.shares))
	for _, share := range t.shares {
		round1, err := ThresholdCommit(share)
		if err != nil {
			panic(fmt.Sprintf("vouch: ThresholdSigner.Sign: commit: %v", err))
		}
		commitments[share.Identifier] = round1.Commitments
		noncesByID[share.Identifier] = round1.Nonces
	}

	sharesOut := make(map[string]string, len(t.shares))
	for _, share := range t.shares {
		sigShare, err := ThresholdSignShare(digest, share, noncesByID[share.Identifier], commitments)
		if err != nil {
			panic(fmt.Sprintf("vouch: ThresholdSigner.Sign: sign_share: %v", err))
		}
		sharesOut[share.Identifier] = sigShare
	}

	sig, err := ThresholdAggregate(digest, commitments, sharesOut, t.groupPublicKey)
	if err != nil {
		panic(fmt.Sprintf("vouch: ThresholdSigner.Sign: aggregate: %v", err))
	}
	return sig
}
