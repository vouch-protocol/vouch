// Cross-language interop for the disconnected-edge (DTN) robotics primitives.
//
// Loads the shared vector at test-vectors/robotics/dtn_vector.json (Python-signed,
// PAD-106 to PAD-124) and proves the Go SDK verifies every credential and reproduces
// the sparse-Merkle revocation root byte-for-byte — the same vector the Rust core and
// TypeScript SDK interop tests use.
package robotics

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func loadDTNVector(t *testing.T) map[string]any {
	t.Helper()
	path := filepath.Join("..", "..", "test-vectors", "robotics", "dtn_vector.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read dtn_vector.json: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse dtn_vector.json: %v", err)
	}
	return doc
}

func dtnPubKey(t *testing.T, doc map[string]any) ed25519.PublicKey {
	t.Helper()
	x, _ := doc["issuerPublicKeyRawB64Url"].(string)
	b, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil || len(b) != ed25519.PublicKeySize {
		t.Fatalf("decode pubkey: %v", err)
	}
	return ed25519.PublicKey(b)
}

func v3(v any) [3]float64 {
	a := v.([]any)
	return [3]float64{a[0].(float64), a[1].(float64), a[2].(float64)}
}

func TestDTNInterop_PythonSignedCredentialsVerify(t *testing.T) {
	doc := loadDTNVector(t)
	pk := dtnPubKey(t, doc)

	for _, e := range doc["credentials"].([]any) {
		entry := e.(map[string]any)
		name := entry["name"].(string)
		cred := entry["credential"].(map[string]any)
		v := entry["verify"].(map[string]any)
		kind := v["kind"].(string)

		var ok bool
		switch kind {
		case "freshness_token":
			ok = VerifyFreshnessToken(cred, pk, VerifyFreshnessTokenOptions{
				VerifierEpoch: int64(v["verifierEpoch"].(float64)),
				Tier:          v["tier"].(string),
			}) != nil
		case "presence":
			ok = VerifyPresenceAttestation(cred, pk, v3(v["verifierPosition"]), v["expectedNonce"].(string)) != nil
		case "geoscope":
			sub := VerifyGeoscopedGrant(cred, pk, nil)
			ok = sub != nil && GeoscopePermits(sub, v3(v["position"]))
		case "conditional_revocation":
			ok = VerifyConditionalRevocation(cred, pk) != nil
		case "range_observation":
			ok = VerifyRangeObservation(cred, pk) != nil
		case "beam_presence":
			ok = VerifyBeamPresence(cred, pk, v3(v["peerDirection"]), v["expectedNonce"].(string)) != nil
		case "distress":
			ok = VerifyDistressAttestation(cred, pk) != nil
		case "trust_state_update":
			ok = VerifyTrustStateUpdate(cred, pk) != nil
		case "time_quality":
			sub := VerifyTimeQualityAttestation(cred, pk)
			ok = sub != nil && TimeQualityPermits(sub, v["tier"].(string), nil)
		case "integrity_risk":
			ok = VerifyIntegrityRiskAttestation(cred, pk) != nil
		case "perception_claim":
			ok = VerifyPerceptionClaim(cred, pk) != nil
		case "bundle":
			ok = VerifyBundleTrust(cred, pk, v["payloadHash"].(string)) != nil
		default:
			t.Fatalf("unknown verify kind: %s", kind)
		}
		if !ok {
			t.Errorf("Go failed to verify Python-signed credential: %s", name)
		}
	}
}

func TestDTNInterop_AccumulatorRootAndProofs(t *testing.T) {
	doc := loadDTNVector(t)
	pk := dtnPubKey(t, doc)
	acc := doc["accumulator"].(map[string]any)

	tree := NewSparseMerkleTree()
	for _, cid := range acc["revokedIds"].([]any) {
		tree.Revoke(cid.(string))
	}
	if got, want := tree.RootMultibase(), acc["rootMultibase"].(string); got != want {
		t.Fatalf("sparse-Merkle root mismatch:\n got %s\nwant %s", got, want)
	}

	signed := acc["signedRoot"].(map[string]any)
	if !VerifyNonRevocation(acc["nonRevokedId"].(string), acc["nonRevokedProof"].(map[string]any), signed, pk) {
		t.Error("a non-revoked credential's Python proof must verify in Go")
	}
	if VerifyNonRevocation(acc["revokedId"].(string), acc["revokedProof"].(map[string]any), signed, pk) {
		t.Error("a revoked credential's proof must NOT verify")
	}
}
