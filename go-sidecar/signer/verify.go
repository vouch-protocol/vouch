// Credential verification with the validity window and required intent.resource
// binding, plus did:key resolution. Mirrors vouch/verifier.py's
// CredentialPassport and verify().
//
// VerifyProof (data_integrity_hybrid.go) checks only the signature, whichever
// proof shape the credential carries; this file adds the temporal and
// structural checks Specification §8.1 requires, and builds a passport the
// same shape as the Python and TypeScript SDKs return.

package signer

import (
	"errors"
	"fmt"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

// CredentialPassport is a verified credential, with the intent and delegation
// chain surfaced directly so a caller does not have to re-walk the raw map.
type CredentialPassport struct {
	Sub             string
	Issuer          string
	ValidFrom       string
	ValidUntil      string
	CredentialID    string
	Intent          map[string]any
	ReputationScore *int
	DelegationChain []DelegationLink
	RawCredential   map[string]any
}

// Action returns intent["action"] as a string, or "" if absent.
func (p *CredentialPassport) Action() string { return intentString(p.Intent, "action") }

// Target returns intent["target"] as a string, or "" if absent.
func (p *CredentialPassport) Target() string { return intentString(p.Intent, "target") }

// Resource returns intent["resource"] as a string, or "" if absent.
func (p *CredentialPassport) Resource() string { return intentString(p.Intent, "resource") }

func intentString(intent map[string]any, key string) string {
	if intent == nil {
		return ""
	}
	if v, ok := intent[key].(string); ok {
		return v
	}
	return ""
}

// VerifyCredential verifies a credential's Data Integrity proof and its
// validity window, and checks the required intent.resource binding
// (Specification §5.4.1, §8.4). publicKey verifies the proof; nowISO and
// clockSkewSeconds bound the validity window. Returns (valid, passport, err).
//
// The proof is verified by shape, so a post-quantum credential carrying a
// proof set verifies here the same way a classical one does. Pass the
// credential's ML-DSA-44 public key as the trailing optional argument to check
// a post-quantum credential; without it, a credential carrying an ML-DSA-44
// proof returns ErrMissingMLDSA44Key rather than passing on the Ed25519 proof
// alone.
//
// err is non-nil for a malformed credential's key requirements; an otherwise
// well-formed but invalid/expired credential returns (false, nil, nil).
func VerifyCredential(
	credential map[string]any,
	publicKey []byte,
	nowISO string,
	clockSkewSeconds int64,
	mldsa44PublicKey ...*mldsa44.PublicKey,
) (bool, *CredentialPassport, error) {
	proofOK, err := VerifyProof(credential, publicKey, optionalMLDSA44(mldsa44PublicKey))
	if err != nil {
		if errors.Is(err, ErrMissingMLDSA44Key) {
			return false, nil, err
		}
		return false, nil, nil //nolint:nilerr // malformed proof is "invalid", not a caller error
	}
	if !proofOK {
		return false, nil, nil
	}

	now, err := parseISO8601(nowISO)
	if err != nil {
		return false, nil, fmt.Errorf("parse now: %w", err)
	}
	validFrom, vfErr := parseISO8601(asString(credential["validFrom"]))
	validUntil, vuErr := parseISO8601(asString(credential["validUntil"]))
	if vfErr != nil || vuErr != nil {
		return false, nil, nil
	}

	skew := time.Duration(clockSkewSeconds) * time.Second
	if now.Sub(validUntil) > skew {
		return false, nil, nil
	}
	if validFrom.Sub(now) > skew {
		return false, nil, nil
	}

	subject, _ := credential["credentialSubject"].(map[string]any)
	if subject == nil {
		return false, nil, nil
	}
	intent, _ := subject["intent"].(map[string]any)
	if intent == nil || asString(intent["resource"]) == "" {
		return false, nil, nil
	}

	var repScore *int
	if raw, ok := subject["reputationScore"]; ok {
		if f, ok := raw.(float64); ok {
			v := int(f)
			repScore = &v
		}
	}

	var chain []DelegationLink
	if rawChain, ok := subject["delegationChain"].([]any); ok {
		for _, item := range rawChain {
			linkMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			link := DelegationLink{
				Issuer:  asString(linkMap["issuer"]),
				Subject: asString(linkMap["subject"]),
			}
			if intentMap, ok := linkMap["intent"].(map[string]any); ok {
				link.Intent = intentMap
			}
			link.ValidFrom = asString(linkMap["validFrom"])
			link.ValidUntil = asString(linkMap["validUntil"])
			link.ParentProofValue = asString(linkMap["parentProofValue"])
			chain = append(chain, link)
		}
	}

	passport := &CredentialPassport{
		Sub:             asString(subject["id"]),
		Issuer:          issuerOf(credential),
		ValidFrom:       asString(credential["validFrom"]),
		ValidUntil:      asString(credential["validUntil"]),
		CredentialID:    asString(credential["id"]),
		Intent:          intent,
		ReputationScore: repScore,
		DelegationChain: chain,
		RawCredential:   credential,
	}
	return true, passport, nil
}

// optionalMLDSA44 unwraps the trailing optional ML-DSA-44 key argument.
func optionalMLDSA44(keys []*mldsa44.PublicKey) *mldsa44.PublicKey {
	if len(keys) == 0 {
		return nil
	}
	return keys[0]
}

// Verify verifies a credential, resolving the issuer's key automatically when
// publicKey is nil: a did:key issuer resolves offline from the DID itself. A
// did:web issuer without an explicit publicKey cannot be resolved here (no
// network resolution in this package); pass the key explicitly for did:web.
//
// A did:key encodes one key, so a post-quantum credential's ML-DSA-44 key can
// never be resolved from the issuer. Pass it as the trailing optional argument.
func Verify(
	credential map[string]any,
	publicKey []byte,
	clockSkewSeconds int64,
	mldsa44PublicKey ...*mldsa44.PublicKey,
) (bool, *CredentialPassport, error) {
	if publicKey == nil {
		issuer := issuerOf(credential)
		if !IsDIDKey(issuer) {
			return false, nil, errors.New(
				"no public key supplied and issuer is not a did:key; pass publicKey explicitly",
			)
		}
		resolved, err := Ed25519FromDIDKey(issuer)
		if err != nil {
			return false, nil, err
		}
		publicKey = resolved
	}
	return VerifyCredential(
		credential, publicKey, formatISO8601(time.Now()), clockSkewSeconds, mldsa44PublicKey...,
	)
}

func issuerOf(credential map[string]any) string {
	switch v := credential["issuer"].(type) {
	case string:
		return v
	case []any:
		if len(v) > 0 {
			return asString(v[0])
		}
	}
	return ""
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

// parseISO8601 parses a VC datetime string in either "...Z" or an RFC3339
// offset form, returning a UTC time.
func parseISO8601(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, errors.New("empty timestamp")
	}
	for _, layout := range []string{
		"2006-01-02T15:04:05Z",
		time.RFC3339,
		time.RFC3339Nano,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized timestamp: %s", s)
}
