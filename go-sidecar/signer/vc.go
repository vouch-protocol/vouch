// W3C Verifiable Credential envelope for Vouch Protocol.
//
// Mirrors vouch/vc.py and typescript/src/vc.ts. Builds a VouchCredential
// per W3C CG Report §5: a W3C VC Data Model 2.0 credential carrying an
// agent's intent, optional reputation, and optional delegation chain,
// secured by a Data Integrity proof (eddsa-jcs-2022).

package signer

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"
)

const (
	VCContextV2          = "https://www.w3.org/ns/credentials/v2"
	VouchContextV1       = "https://vouch-protocol.com/contexts/v1"
	VCType               = "VerifiableCredential"
	VouchCredentialType  = "VouchCredential"
	SessionVoucherType   = "SessionVoucher"
	ProtocolVersion      = "1.0"
)

// Intent describes the action being authorized. action, target, and resource
// are REQUIRED per W3C CG Report §5.4.1.
type Intent struct {
	Action   string         `json:"action"`
	Target   string         `json:"target"`
	Resource string         `json:"resource"`
	Extra    map[string]any `json:"-"`
}

// DelegationLink is one link in a delegation chain.
type DelegationLink struct {
	Issuer            string         `json:"issuer"`
	Subject           string         `json:"subject"`
	Intent            map[string]any `json:"intent"`
	ValidFrom         string         `json:"validFrom,omitempty"`
	ValidUntil        string         `json:"validUntil,omitempty"`
	ParentProofValue  string         `json:"parentProofValue,omitempty"`
}

// BuildVouchCredentialOptions configures BuildVouchCredential.
type BuildVouchCredentialOptions struct {
	IssuerDID        string
	Intent           map[string]any
	ValidSeconds     int
	ReputationScore  *int
	DelegationChain  []map[string]any
	CredentialID     string
	ValidFrom        time.Time

	// CredentialStatus is an optional W3C credentialStatus entry, typically
	// built via BuildStatusListEntry to reference a BitstringStatusListCredential
	// (W3C CG Report §11.2). When non-nil, it is attached to the credential as
	// the `credentialStatus` property.
	CredentialStatus map[string]any
}

// BuildVouchCredential constructs an unsigned Vouch Credential. The caller
// attaches a Data Integrity proof via BuildDataIntegrityProof.
//
// Returns the credential as a map[string]any so it composes naturally with
// the JCS canonicalizer.
func BuildVouchCredential(opts BuildVouchCredentialOptions) (map[string]any, error) {
	if err := validateIntent(opts.Intent); err != nil {
		return nil, err
	}

	issuedAt := opts.ValidFrom
	if issuedAt.IsZero() {
		issuedAt = time.Now().UTC()
	} else {
		issuedAt = issuedAt.UTC()
	}

	validSeconds := opts.ValidSeconds
	if validSeconds <= 0 {
		validSeconds = 300
	}
	expiresAt := issuedAt.Add(time.Duration(validSeconds) * time.Second)

	subject := map[string]any{
		"id":           opts.IssuerDID,
		"vouchVersion": ProtocolVersion,
		"intent":       opts.Intent,
	}

	if opts.ReputationScore != nil {
		score := *opts.ReputationScore
		if score < 0 {
			score = 0
		}
		if score > 100 {
			score = 100
		}
		subject["reputationScore"] = score
	}

	if len(opts.DelegationChain) > 0 {
		// Convert []map[string]any to []any for JSON shape.
		chain := make([]any, len(opts.DelegationChain))
		for i, link := range opts.DelegationChain {
			chain[i] = link
		}
		subject["delegationChain"] = chain
	}

	credID := opts.CredentialID
	if credID == "" {
		uuid, err := newUUIDURN()
		if err != nil {
			return nil, err
		}
		credID = uuid
	}

	vc := map[string]any{
		"@context":          []any{VCContextV2, VouchContextV1},
		"id":                credID,
		"type":              []any{VCType, VouchCredentialType},
		"issuer":            opts.IssuerDID,
		"validFrom":         formatISO8601(issuedAt),
		"validUntil":        formatISO8601(expiresAt),
		"credentialSubject": subject,
	}

	if opts.CredentialStatus != nil {
		vc["credentialStatus"] = opts.CredentialStatus
	}

	return vc, nil
}

func validateIntent(intent map[string]any) error {
	if intent == nil {
		return errors.New("intent must not be nil")
	}
	for _, required := range []string{"action", "target", "resource"} {
		v, ok := intent[required]
		if !ok || v == nil {
			return fmt.Errorf(
				"intent.%s is REQUIRED (W3C CG Report §5.4.1), Vouch credentials MUST bind to a concrete resource",
				required,
			)
		}
		if s, isStr := v.(string); isStr && s == "" {
			return fmt.Errorf(
				"intent.%s is REQUIRED (W3C CG Report §5.4.1), Vouch credentials MUST bind to a concrete resource",
				required,
			)
		}
	}
	return nil
}

// newUUIDURN returns a "urn:uuid:" prefixed UUID v4 string.
func newUUIDURN() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("uuid generation: %w", err)
	}
	// Set version (4) and variant (10).
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf(
		"urn:uuid:%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16],
	), nil
}
