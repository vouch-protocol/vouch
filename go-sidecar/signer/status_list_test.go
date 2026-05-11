// Tests for the W3C BitstringStatusList implementation (W3C CG Report §11.2).
//
// Mirrors tests/test_status_list.py and packages/sdk-ts/tests/status-list.test.ts.
// Cross-language interop is verified against the canonical test vector at
// test-vectors/bitstring-status-list/vector.json.

package signer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

const (
	testStatusURL  = "https://issuer.example/status/1"
	testIssuerDID  = "did:web:issuer.example"
)

// ---------------------------------------------------------------------------
// Construction & validation
// ---------------------------------------------------------------------------

func TestStatusListDefaultLengthAndPurpose(t *testing.T) {
	sl, err := NewStatusList(testStatusURL, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if sl.Length() != DefaultBitstringLength {
		t.Errorf("Length = %d, want %d", sl.Length(), DefaultBitstringLength)
	}
	if sl.StatusPurpose() != StatusPurposeRevocation {
		t.Errorf("StatusPurpose = %q, want %q", sl.StatusPurpose(), StatusPurposeRevocation)
	}
}

func TestStatusListRejectsShortBitstring(t *testing.T) {
	if _, err := NewStatusList(testStatusURL, StatusPurposeRevocation, 1024); err == nil {
		t.Error("expected error for short length")
	}
}

func TestStatusListRejectsNonMultipleOfEight(t *testing.T) {
	if _, err := NewStatusList(testStatusURL, StatusPurposeRevocation, DefaultBitstringLength+1); err == nil {
		t.Error("expected error for non-multiple-of-8 length")
	}
}

func TestStatusListRejectsInvalidPurpose(t *testing.T) {
	if _, err := NewStatusList(testStatusURL, "bogus", 0); err == nil {
		t.Error("expected error for invalid purpose")
	}
}

func TestStatusListRejectsEmptyID(t *testing.T) {
	if _, err := NewStatusList("", StatusPurposeRevocation, 0); err == nil {
		t.Error("expected error for empty id")
	}
}

func TestStatusListDefaultStateAllZero(t *testing.T) {
	sl, _ := NewStatusList(testStatusURL, "", 0)
	for _, idx := range []int{0, 1, 7, 8, 100, 65535, DefaultBitstringLength - 1} {
		got, err := sl.GetStatus(idx)
		if err != nil {
			t.Fatal(err)
		}
		if got {
			t.Errorf("GetStatus(%d) = true, want false", idx)
		}
	}
}

// ---------------------------------------------------------------------------
// Bit operations
// ---------------------------------------------------------------------------

func TestSetAndGetStatus(t *testing.T) {
	sl, _ := NewStatusList(testStatusURL, "", 0)
	if err := sl.SetStatus(42, true); err != nil {
		t.Fatal(err)
	}

	if got, _ := sl.GetStatus(42); !got {
		t.Error("expected bit 42 to be set")
	}
	if got, _ := sl.GetStatus(41); got {
		t.Error("expected bit 41 to be unset")
	}
	if got, _ := sl.GetStatus(43); got {
		t.Error("expected bit 43 to be unset")
	}
}

func TestClearAfterSet(t *testing.T) {
	sl, _ := NewStatusList(testStatusURL, "", 0)
	_ = sl.SetStatus(42, true)
	_ = sl.SetStatus(42, false)
	if got, _ := sl.GetStatus(42); got {
		t.Error("expected bit 42 to be cleared")
	}
}

func TestFirstAndLastBit(t *testing.T) {
	sl, _ := NewStatusList(testStatusURL, "", 0)
	_ = sl.Revoke(0)
	_ = sl.Revoke(DefaultBitstringLength - 1)
	if got, _ := sl.IsSet(0); !got {
		t.Error("expected first bit to be set")
	}
	if got, _ := sl.IsSet(DefaultBitstringLength - 1); !got {
		t.Error("expected last bit to be set")
	}
	if got, _ := sl.IsSet(1); got {
		t.Error("expected bit 1 to be unset")
	}
}

func TestOutOfRangeIndex(t *testing.T) {
	sl, _ := NewStatusList(testStatusURL, "", 0)
	if err := sl.SetStatus(-1, true); err == nil {
		t.Error("expected error for negative index")
	}
	if err := sl.SetStatus(DefaultBitstringLength, true); err == nil {
		t.Error("expected error for out-of-range index")
	}
}

// ---------------------------------------------------------------------------
// Allocation
// ---------------------------------------------------------------------------

func TestAllocateIndicesAreSequential(t *testing.T) {
	sl, _ := NewStatusList(testStatusURL, "", 0)
	for want := 0; want < 3; want++ {
		got, err := sl.AllocateIndex()
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("AllocateIndex = %d, want %d", got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

func TestEncodeUsesMultibasePrefix(t *testing.T) {
	sl, _ := NewStatusList(testStatusURL, "", 0)
	encoded, err := sl.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if encoded[:1] != MultibaseBase64URLPrefix {
		t.Errorf("encoded prefix = %q, want %q", encoded[:1], MultibaseBase64URLPrefix)
	}
}

func TestEncodeRoundTrip(t *testing.T) {
	sl, _ := NewStatusList(testStatusURL, "", 0)
	indices := []int{0, 1, 7, 8, 9, 16, 1023, 65535, DefaultBitstringLength - 1}
	for _, idx := range indices {
		_ = sl.Revoke(idx)
	}
	encoded, err := sl.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeStatusList(encoded, testStatusURL, StatusPurposeRevocation)
	if err != nil {
		t.Fatal(err)
	}
	for _, idx := range indices {
		got, _ := decoded.GetStatus(idx)
		if !got {
			t.Errorf("decoded.GetStatus(%d) = false, want true", idx)
		}
	}
	if got, _ := decoded.GetStatus(2); got {
		t.Error("expected bit 2 to be unset after roundtrip")
	}
}

func TestDecodeRejectsWrongPrefix(t *testing.T) {
	if _, err := DecodeStatusList("zSomethingBase58", testStatusURL, ""); err == nil {
		t.Error("expected error for wrong prefix")
	}
}

func TestDecodeRejectsCorruptPayload(t *testing.T) {
	if _, err := DecodeStatusList(MultibaseBase64URLPrefix+"$$$invalid$$$", testStatusURL, ""); err == nil {
		t.Error("expected error for corrupt payload")
	}
}

// ---------------------------------------------------------------------------
// Credential and entry builders
// ---------------------------------------------------------------------------

func TestBuildStatusListCredentialShape(t *testing.T) {
	sl, _ := NewStatusList(testStatusURL, "", 0)
	_ = sl.Revoke(7)
	vc, err := BuildStatusListCredential(BuildStatusListCredentialOptions{
		IssuerDID:  testIssuerDID,
		StatusList: sl,
	})
	if err != nil {
		t.Fatal(err)
	}
	if vc["id"] != testStatusURL {
		t.Errorf("id = %v, want %s", vc["id"], testStatusURL)
	}
	if vc["issuer"] != testIssuerDID {
		t.Errorf("issuer = %v, want %s", vc["issuer"], testIssuerDID)
	}
	typeField, _ := vc["type"].([]any)
	if !containsString(typeField, BitstringStatusListCredentialType) {
		t.Errorf("type does not contain %s", BitstringStatusListCredentialType)
	}
	subject, _ := vc["credentialSubject"].(map[string]any)
	if subject["statusPurpose"] != StatusPurposeRevocation {
		t.Errorf("statusPurpose = %v, want %s", subject["statusPurpose"], StatusPurposeRevocation)
	}
	encoded, _ := subject["encodedList"].(string)
	if encoded[:1] != MultibaseBase64URLPrefix {
		t.Errorf("encodedList prefix = %q, want %q", encoded[:1], MultibaseBase64URLPrefix)
	}
}

func TestBuildStatusListEntryShape(t *testing.T) {
	entry, err := BuildStatusListEntry(BuildStatusListEntryOptions{
		StatusListCredential: testStatusURL,
		StatusListIndex:      42,
	})
	if err != nil {
		t.Fatal(err)
	}
	if entry["statusListIndex"] != "42" {
		t.Errorf("statusListIndex = %v, want '42'", entry["statusListIndex"])
	}
	if entry["type"] != BitstringStatusListEntryType {
		t.Errorf("type = %v, want %s", entry["type"], BitstringStatusListEntryType)
	}
}

func TestBuildStatusListEntryRejectsNegativeIndex(t *testing.T) {
	_, err := BuildStatusListEntry(BuildStatusListEntryOptions{
		StatusListCredential: testStatusURL,
		StatusListIndex:      -1,
	})
	if err == nil {
		t.Error("expected error for negative index")
	}
}

// ---------------------------------------------------------------------------
// VerifyStatus
// ---------------------------------------------------------------------------

func buildPair(t *testing.T, revoked ...int) (*StatusList, map[string]any) {
	t.Helper()
	sl, _ := NewStatusList(testStatusURL, "", 0)
	for _, idx := range revoked {
		_ = sl.Revoke(idx)
	}
	vc, err := BuildStatusListCredential(BuildStatusListCredentialOptions{
		IssuerDID:  testIssuerDID,
		StatusList: sl,
	})
	if err != nil {
		t.Fatal(err)
	}
	return sl, vc
}

func TestVerifyStatusUnsetReturnsFalse(t *testing.T) {
	_, vc := buildPair(t)
	entry, _ := BuildStatusListEntry(BuildStatusListEntryOptions{
		StatusListCredential: testStatusURL,
		StatusListIndex:      10,
	})
	got, err := VerifyStatus(entry, vc)
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Error("expected unset bit to return false")
	}
}

func TestVerifyStatusSetReturnsTrue(t *testing.T) {
	_, vc := buildPair(t, 10)
	entry, _ := BuildStatusListEntry(BuildStatusListEntryOptions{
		StatusListCredential: testStatusURL,
		StatusListIndex:      10,
	})
	got, err := VerifyStatus(entry, vc)
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Error("expected set bit to return true")
	}
}

func TestVerifyStatusIDMismatchRaises(t *testing.T) {
	_, vc := buildPair(t)
	entry, _ := BuildStatusListEntry(BuildStatusListEntryOptions{
		StatusListCredential: "https://other.example/status/9",
		StatusListIndex:      0,
	})
	if _, err := VerifyStatus(entry, vc); err == nil {
		t.Error("expected error for id mismatch")
	}
}

func TestVerifyStatusPurposeMismatchRaises(t *testing.T) {
	sl, _ := NewStatusList(testStatusURL, StatusPurposeSuspension, 0)
	vc, _ := BuildStatusListCredential(BuildStatusListCredentialOptions{
		IssuerDID:  testIssuerDID,
		StatusList: sl,
	})
	entry, _ := BuildStatusListEntry(BuildStatusListEntryOptions{
		StatusListCredential: testStatusURL,
		StatusListIndex:      0,
		StatusPurpose:        StatusPurposeRevocation,
	})
	if _, err := VerifyStatus(entry, vc); err == nil {
		t.Error("expected error for purpose mismatch")
	}
}

// ---------------------------------------------------------------------------
// Cross-language interop against the canonical test vector
// ---------------------------------------------------------------------------

type statusListVector struct {
	StatusListID                    string         `json:"status_list_id"`
	IssuerDID                       string         `json:"issuer_did"`
	BitstringLengthBits             int            `json:"bitstring_length_bits"`
	StatusPurpose                   string         `json:"status_purpose"`
	RevokedIndices                  []int          `json:"revoked_indices"`
	ActiveIndicesSample             []int          `json:"active_indices_sample"`
	ExpectedEncodedList             string         `json:"expected_encoded_list"`
	StatusListCredential            map[string]any `json:"status_list_credential"`
	SampleCredentialStatusRevoked   map[string]any `json:"sample_credential_status_revoked"`
	SampleCredentialStatusActive    map[string]any `json:"sample_credential_status_active"`
}

func loadStatusListVector(t *testing.T) statusListVector {
	t.Helper()
	wd, _ := os.Getwd()
	repoRoot := filepath.Clean(filepath.Join(wd, "..", ".."))
	vecPath := filepath.Join(
		repoRoot, "test-vectors", "bitstring-status-list", "vector.json",
	)
	raw, err := os.ReadFile(vecPath)
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v statusListVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode vector: %v", err)
	}
	return v
}

func TestStatusListInteropEncodingDecodesEquivalent(t *testing.T) {
	// Go's compress/flate produces a valid DEFLATE stream that is byte-different
	// from Python/zlib's output (different DEFLATE encoder), but both decompress
	// to the same bitstring. W3C BitstringStatusList requires equivalence of the
	// decompressed bitstring, not the gzip envelope, so the right interop check
	// is decoded equivalence rather than encoded byte-identity.
	v := loadStatusListVector(t)
	sl, err := NewStatusList(v.StatusListID, v.StatusPurpose, v.BitstringLengthBits)
	if err != nil {
		t.Fatal(err)
	}
	for _, idx := range v.RevokedIndices {
		if err := sl.Revoke(idx); err != nil {
			t.Fatal(err)
		}
	}
	goEncoded, err := sl.Encode()
	if err != nil {
		t.Fatal(err)
	}

	goDecoded, err := DecodeStatusList(goEncoded, v.StatusListID, v.StatusPurpose)
	if err != nil {
		t.Fatal(err)
	}
	canonicalDecoded, err := DecodeStatusList(v.ExpectedEncodedList, v.StatusListID, v.StatusPurpose)
	if err != nil {
		t.Fatal(err)
	}

	if !bytesEqual(goDecoded.RawBytes(), canonicalDecoded.RawBytes()) {
		t.Errorf("Go-encoded bitstring does not decode equivalently to the canonical Python vector")
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestStatusListInteropDecodesCanonical(t *testing.T) {
	v := loadStatusListVector(t)
	sl, err := DecodeStatusList(v.ExpectedEncodedList, v.StatusListID, v.StatusPurpose)
	if err != nil {
		t.Fatal(err)
	}
	for _, idx := range v.RevokedIndices {
		got, _ := sl.GetStatus(idx)
		if !got {
			t.Errorf("decoded.GetStatus(%d) = false, expected revoked", idx)
		}
	}
	for _, idx := range v.ActiveIndicesSample {
		got, _ := sl.GetStatus(idx)
		if got {
			t.Errorf("decoded.GetStatus(%d) = true, expected active", idx)
		}
	}
}

func TestStatusListInteropVerifyMatchesCanonical(t *testing.T) {
	v := loadStatusListVector(t)

	revoked, err := VerifyStatus(v.SampleCredentialStatusRevoked, v.StatusListCredential)
	if err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Error("expected canonical revoked sample to verify as revoked")
	}

	active, err := VerifyStatus(v.SampleCredentialStatusActive, v.StatusListCredential)
	if err != nil {
		t.Fatal(err)
	}
	if active {
		t.Error("expected canonical active sample to verify as active")
	}
}

// Sanity-check that strconv.Itoa(0) yields "0" (used in entry builder).
func TestStringIndexFormat(t *testing.T) {
	if strconv.Itoa(0) != "0" {
		t.Error("strconv.Itoa(0) should yield '0'")
	}
}

// ---------------------------------------------------------------------------
// State dict persistence
// ---------------------------------------------------------------------------

func TestStateDictRoundTripPreservesBitsAndCursor(t *testing.T) {
	sl, _ := NewStatusList(testStatusURL, "", 0)
	a, _ := sl.AllocateIndex()
	b, _ := sl.AllocateIndex()
	c, _ := sl.AllocateIndex()
	_ = sl.Revoke(b)

	state, err := sl.ToStateDict()
	if err != nil {
		t.Fatal(err)
	}

	restored, err := FromStateDict(state)
	if err != nil {
		t.Fatal(err)
	}
	if restored.StatusListID() != testStatusURL {
		t.Errorf("StatusListID mismatch: got %q", restored.StatusListID())
	}
	if got, _ := restored.GetStatus(a); got {
		t.Error("expected idx_a to be unset")
	}
	if got, _ := restored.GetStatus(b); !got {
		t.Error("expected idx_b to be set")
	}
	if got, _ := restored.GetStatus(c); got {
		t.Error("expected idx_c to be unset")
	}
	next, err := restored.AllocateIndex()
	if err != nil {
		t.Fatal(err)
	}
	if next != c+1 {
		t.Errorf("expected next allocation to be %d, got %d", c+1, next)
	}
}

func TestStateDictJSONSerializable(t *testing.T) {
	sl, _ := NewStatusList(testStatusURL, "", 0)
	_ = sl.Revoke(100)
	state, err := sl.ToStateDict()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var decoded StatusListStateDict
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.NextIndex != state.NextIndex {
		t.Errorf("NextIndex mismatch after JSON round-trip")
	}
	if decoded.EncodedList != state.EncodedList {
		t.Errorf("EncodedList mismatch after JSON round-trip")
	}
}

func TestStateDictRejectsNil(t *testing.T) {
	if _, err := FromStateDict(nil); err == nil {
		t.Error("expected error for nil state")
	}
}

func TestStateDictRejectsOutOfRangeNextIndex(t *testing.T) {
	sl, _ := NewStatusList(testStatusURL, "", 0)
	state, _ := sl.ToStateDict()
	state.NextIndex = -1
	if _, err := FromStateDict(state); err == nil {
		t.Error("expected error for negative nextIndex")
	}
}
