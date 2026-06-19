// BitstringStatusList implementation for Vouch Protocol.
//
// Mirrors vouch/status_list.py and packages/sdk-ts/src/status-list.ts.
// Implements credential-level revocation and suspension status per W3C
// VC-BITSTRING-STATUS-LIST (https://www.w3.org/TR/vc-bitstring-status-list/),
// referenced in Specification §11.2.
//
// Cross-implementation interop is verified against the canonical test vector
// at test-vectors/bitstring-status-list/vector.json.

package signer

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"
)

const (
	// DefaultBitstringLength is the BitstringStatusList §4.2 minimum
	// bitstring length in bits (16 KiB).
	DefaultBitstringLength = 131_072

	StatusPurposeRevocation = "revocation"
	StatusPurposeSuspension = "suspension"
	StatusPurposeMessage  = "message"

	BitstringStatusListCredentialType = "BitstringStatusListCredential"
	BitstringStatusListSubjectType  = "BitstringStatusList"
	BitstringStatusListEntryType   = "BitstringStatusListEntry"

	// MultibaseBase64URLPrefix is the multibase prefix for base64url-no-pad.
	MultibaseBase64URLPrefix = "u"
)

var validStatusPurposes = map[string]struct{}{
	StatusPurposeRevocation: {},
	StatusPurposeSuspension: {},
	StatusPurposeMessage:  {},
}

// StatusList is an in-memory bitstring for credential status tracking.
//
// Bit ordering follows BitstringStatusList §4.2: bit at index i is stored
// at byte i/8, with bit position 7-(i%8) (most significant bit first within
// each byte).
type StatusList struct {
	statusListID  string
	statusPurpose string
	length     int
	bits      []byte
	nextIndex   int
}

// NewStatusList constructs a new StatusList with the given id, purpose, and length.
// Passing length == 0 selects the protocol minimum of 131,072 bits.
func NewStatusList(statusListID, statusPurpose string, length int) (*StatusList, error) {
	if statusListID == "" {
		return nil, errors.New("statusListID is required")
	}
	if statusPurpose == "" {
		statusPurpose = StatusPurposeRevocation
	}
	if _, ok := validStatusPurposes[statusPurpose]; !ok {
		return nil, fmt.Errorf(
			"statusPurpose must be one of revocation/suspension/message, got %q",
			statusPurpose,
		)
	}
	if length == 0 {
		length = DefaultBitstringLength
	}
	if length < DefaultBitstringLength {
		return nil, fmt.Errorf(
			"bitstring length must be at least %d per BitstringStatusList §4.2, got %d",
			DefaultBitstringLength, length,
		)
	}
	if length%8 != 0 {
		return nil, fmt.Errorf("bitstring length must be a multiple of 8, got %d", length)
	}

	return &StatusList{
		statusListID: statusListID,
		statusPurpose: statusPurpose,
		length:    length,
		bits:     make([]byte, length/8),
	}, nil
}

// StatusListID returns the URL where the signed credential is published.
func (s *StatusList) StatusListID() string { return s.statusListID }

// StatusPurpose returns the configured purpose.
func (s *StatusList) StatusPurpose() string { return s.statusPurpose }

// Length returns the bitstring length in bits.
func (s *StatusList) Length() int { return s.length }

// AllocateIndex returns the next unused index and advances the cursor.
func (s *StatusList) AllocateIndex() (int, error) {
	if s.nextIndex >= s.length {
		return 0, fmt.Errorf(
			"status list exhausted: all %d indices allocated", s.length,
		)
	}
	idx := s.nextIndex
	s.nextIndex++
	return idx, nil
}

// SetStatus sets the bit at index to 1 (default) or 0 if value is false.
func (s *StatusList) SetStatus(index int, value bool) error {
	if err := s.checkIndex(index); err != nil {
		return err
	}
	byteIdx := index / 8
	bitPos := 7 - (index % 8)
	if value {
		s.bits[byteIdx] |= 1 << uint(bitPos)
	} else {
		s.bits[byteIdx] &^= 1 << uint(bitPos)
	}
	return nil
}

// GetStatus returns true if the bit at index is set.
func (s *StatusList) GetStatus(index int) (bool, error) {
	if err := s.checkIndex(index); err != nil {
		return false, err
	}
	byteIdx := index / 8
	bitPos := 7 - (index % 8)
	return s.bits[byteIdx]&(1<<uint(bitPos)) != 0, nil
}

// Revoke is a convenience wrapper for SetStatus(index, true).
func (s *StatusList) Revoke(index int) error { return s.SetStatus(index, true) }

// Reinstate is a convenience wrapper for SetStatus(index, false).
func (s *StatusList) Reinstate(index int) error { return s.SetStatus(index, false) }

// IsSet is a convenience wrapper for GetStatus(index).
func (s *StatusList) IsSet(index int) (bool, error) { return s.GetStatus(index) }

// RawBytes returns a defensive copy of the uncompressed bitstring.
func (s *StatusList) RawBytes() []byte {
	out := make([]byte, len(s.bits))
	copy(out, s.bits)
	return out
}

// Encode returns the multibase (base64url, no pad) string of the
// gzip-compressed bitstring per BitstringStatusList §4.2.
//
// The gzip mtime is forced to 0, XFL is forced to best-compression (0x02),
// and the OS byte is forced to 0xff (unknown) so the encoded output is
// deterministic across runs and across language implementations.
func (s *StatusList) Encode() (string, error) {
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return "", fmt.Errorf("gzip writer: %w", err)
	}
	// ModTime zero matches Python's gzip.compress(..., mtime=0) and TS's
	// normalized header.
	gz.ModTime = time.Time{}
	gz.OS = 0xff
	if _, err := gz.Write(s.bits); err != nil {
		return "", fmt.Errorf("gzip write: %w", err)
	}
	if err := gz.Close(); err != nil {
		return "", fmt.Errorf("gzip close: %w", err)
	}
	compressed := buf.Bytes()
	if len(compressed) >= 10 {
		// Force XFL=0x02 (best compression) to match Python's gzip.compress.
		// Go's compress/gzip writes XFL based on level, but the value can
		// vary; this guarantees byte-identical output across implementations.
		compressed[8] = 0x02
		compressed[9] = 0xff
	}
	b64 := base64.RawURLEncoding.EncodeToString(compressed)
	return MultibaseBase64URLPrefix + b64, nil
}

// DecodeStatusList reconstructs a StatusList from its multibase encoding.
//
// Caller is responsible for verifying the Data Integrity proof on the
// enclosing BitstringStatusListCredential BEFORE calling this function.
func DecodeStatusList(encoded, statusListID, statusPurpose string) (*StatusList, error) {
	if statusPurpose == "" {
		statusPurpose = StatusPurposeRevocation
	}
	if len(encoded) == 0 || encoded[:1] != MultibaseBase64URLPrefix {
		return nil, fmt.Errorf(
			"encoded list must use multibase prefix %q (base64url)",
			MultibaseBase64URLPrefix,
		)
	}
	compressed, err := base64.RawURLEncoding.DecodeString(encoded[1:])
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()
	raw, err := io.ReadAll(gz)
	if err != nil {
		return nil, fmt.Errorf("gzip read: %w", err)
	}

	length := len(raw) * 8
	if length < DefaultBitstringLength {
		return nil, fmt.Errorf(
			"decoded bitstring length %d is below the protocol minimum (%d)",
			length, DefaultBitstringLength,
		)
	}

	lst, err := NewStatusList(statusListID, statusPurpose, length)
	if err != nil {
		return nil, err
	}
	copy(lst.bits, raw)
	return lst, nil
}

func (s *StatusList) checkIndex(index int) error {
	if index < 0 || index >= s.length {
		return fmt.Errorf("index %d out of range [0, %d)", index, s.length)
	}
	return nil
}

// StatusListStateDict is the JSON-serializable state of a StatusList,
// suitable for persistence between issuer restarts. Carries everything
// needed to reconstruct the list including nextIndex (which is NOT
// recoverable from the encoded bitstring alone).
type StatusListStateDict struct {
	Version    int  `json:"version"`
	StatusListID string `json:"statusListId"`
	StatusPurpose string `json:"statusPurpose"`
	Length    int  `json:"length"`
	NextIndex   int  `json:"nextIndex"`
	EncodedList  string `json:"encodedList"`
}

// ToStateDict serializes the StatusList to a state dict suitable for
// persistence. Issuers SHOULD persist this state after every revocation
// or allocation and reload it on startup to avoid re-allocating already-
// used indices.
func (s *StatusList) ToStateDict() (*StatusListStateDict, error) {
	encoded, err := s.Encode()
	if err != nil {
		return nil, err
	}
	return &StatusListStateDict{
		Version:    1,
		StatusListID: s.statusListID,
		StatusPurpose: s.statusPurpose,
		Length:    s.length,
		NextIndex:   s.nextIndex,
		EncodedList:  encoded,
	}, nil
}

// FromStateDict reconstructs a StatusList from a state dict produced by
// ToStateDict.
func FromStateDict(state *StatusListStateDict) (*StatusList, error) {
	if state == nil {
		return nil, errors.New("state is required")
	}
	if state.StatusListID == "" {
		return nil, errors.New("state.StatusListID is required")
	}
	if state.EncodedList == "" {
		return nil, errors.New("state.EncodedList is required")
	}
	lst, err := DecodeStatusList(state.EncodedList, state.StatusListID, state.StatusPurpose)
	if err != nil {
		return nil, err
	}
	if lst.length != state.Length {
		return nil, fmt.Errorf(
			"length mismatch: state declares %d, decoded bitstring has %d",
			state.Length, lst.length,
		)
	}
	if state.NextIndex < 0 || state.NextIndex > lst.length {
		return nil, fmt.Errorf(
			"nextIndex %d out of range [0, %d]", state.NextIndex, lst.length,
		)
	}
	lst.nextIndex = state.NextIndex
	return lst, nil
}

// BuildStatusListCredentialOptions configures BuildStatusListCredential.
type BuildStatusListCredentialOptions struct {
	IssuerDID  string
	StatusList  *StatusList
	CredentialID string
	ValidSeconds int    // default: 30 days
	ValidFrom  time.Time // default: now (UTC)
}

// BuildStatusListCredential constructs an unsigned BitstringStatusListCredential
// VC per BitstringStatusList §4. Caller attaches a Data Integrity proof
// before publishing.
func BuildStatusListCredential(opts BuildStatusListCredentialOptions) (map[string]any, error) {
	if opts.StatusList == nil {
		return nil, errors.New("StatusList is required")
	}
	if opts.IssuerDID == "" {
		return nil, errors.New("IssuerDID is required")
	}

	issuedAt := opts.ValidFrom
	if issuedAt.IsZero() {
		issuedAt = time.Now()
	}
	issuedAt = issuedAt.UTC()
	validSeconds := opts.ValidSeconds
	if validSeconds == 0 {
		validSeconds = 30 * 24 * 60 * 60
	}
	expiresAt := issuedAt.Add(time.Duration(validSeconds) * time.Second)

	listID := opts.CredentialID
	if listID == "" {
		listID = opts.StatusList.StatusListID()
	}

	encoded, err := opts.StatusList.Encode()
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"@context": []any{"https://www.w3.org/ns/credentials/v2"},
		"id":    listID,
		"type": []any{
			"VerifiableCredential",
			BitstringStatusListCredentialType,
		},
		"issuer":   opts.IssuerDID,
		"validFrom": issuedAt.Format("2006-01-02T15:04:05Z"),
		"validUntil": expiresAt.Format("2006-01-02T15:04:05Z"),
		"credentialSubject": map[string]any{
			"id":       listID + "#list",
			"type":      BitstringStatusListSubjectType,
			"statusPurpose": opts.StatusList.StatusPurpose(),
			"encodedList":  encoded,
		},
	}, nil
}

// BuildStatusListEntryOptions configures BuildStatusListEntry.
type BuildStatusListEntryOptions struct {
	StatusListCredential string
	StatusListIndex   int
	StatusPurpose    string // default: revocation
	EntryID       string
}

// BuildStatusListEntry constructs a credentialStatus entry for a Vouch
// Credential, referencing a specific bit index in a published
// BitstringStatusListCredential.
func BuildStatusListEntry(opts BuildStatusListEntryOptions) (map[string]any, error) {
	purpose := opts.StatusPurpose
	if purpose == "" {
		purpose = StatusPurposeRevocation
	}
	if _, ok := validStatusPurposes[purpose]; !ok {
		return nil, fmt.Errorf(
			"statusPurpose must be one of revocation/suspension/message, got %q",
			purpose,
		)
	}
	if opts.StatusListIndex < 0 {
		return nil, errors.New("StatusListIndex must be non-negative")
	}
	if opts.StatusListCredential == "" {
		return nil, errors.New("StatusListCredential URL is required")
	}

	entryID := opts.EntryID
	if entryID == "" {
		entryID = fmt.Sprintf("%s#%d", opts.StatusListCredential, opts.StatusListIndex)
	}

	return map[string]any{
		"id":          entryID,
		"type":         BitstringStatusListEntryType,
		"statusPurpose":    purpose,
		"statusListIndex":   strconv.Itoa(opts.StatusListIndex),
		"statusListCredential": opts.StatusListCredential,
	}, nil
}

// VerifyStatus looks up a credential's bit in a fetched status list credential.
//
// Returns true if the bit is set (e.g., revoked or suspended), false if the
// bit is in its default state. The caller MUST verify the Data Integrity
// proof on statusListCredential BEFORE calling this function.
func VerifyStatus(credentialStatus, statusListCredential map[string]any) (bool, error) {
	if credentialStatus == nil {
		return false, errors.New("credentialStatus is required")
	}
	if statusListCredential == nil {
		return false, errors.New("statusListCredential is required")
	}

	csType, _ := credentialStatus["type"].(string)
	if csType != BitstringStatusListEntryType {
		return false, fmt.Errorf(
			"credentialStatus.type must be %s, got %q",
			BitstringStatusListEntryType, csType,
		)
	}

	referenced, _ := credentialStatus["statusListCredential"].(string)
	if referenced == "" {
		return false, errors.New("credentialStatus.statusListCredential is required")
	}

	actualID, _ := statusListCredential["id"].(string)
	if actualID != referenced {
		return false, fmt.Errorf(
			"status list credential id mismatch: credential references %s, got %s",
			referenced, actualID,
		)
	}

	typeField, _ := statusListCredential["type"].([]any)
	if !containsString(typeField, BitstringStatusListCredentialType) {
		return false, fmt.Errorf(
			"fetched credential is not a %s", BitstringStatusListCredentialType,
		)
	}

	subject, _ := statusListCredential["credentialSubject"].(map[string]any)
	if subject == nil {
		return false, errors.New("credentialSubject is required")
	}
	subjType, _ := subject["type"].(string)
	if subjType != BitstringStatusListSubjectType {
		return false, fmt.Errorf(
			"credentialSubject.type must be %s, got %q",
			BitstringStatusListSubjectType, subjType,
		)
	}

	declaredPurpose, _ := credentialStatus["statusPurpose"].(string)
	actualPurpose, _ := subject["statusPurpose"].(string)
	if declaredPurpose != actualPurpose {
		return false, fmt.Errorf(
			"statusPurpose mismatch: credential entry declares %q, status list declares %q",
			declaredPurpose, actualPurpose,
		)
	}

	encoded, _ := subject["encodedList"].(string)
	if encoded == "" {
		return false, errors.New("credentialSubject.encodedList is required")
	}

	rawIndex, ok := credentialStatus["statusListIndex"].(string)
	if !ok {
		return false, errors.New("credentialStatus.statusListIndex is required (string)")
	}
	index, err := strconv.Atoi(rawIndex)
	if err != nil || index < 0 {
		return false, fmt.Errorf(
			"statusListIndex must be a non-negative integer string, got %q",
			rawIndex,
		)
	}

	lst, err := DecodeStatusList(encoded, actualID, actualPurpose)
	if err != nil {
		return false, err
	}
	return lst.GetStatus(index)
}

func containsString(arr []any, target string) bool {
	for _, v := range arr {
		if s, ok := v.(string); ok && s == target {
			return true
		}
	}
	return false
}
