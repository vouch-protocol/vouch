// Cross-language interop vectors for capability attenuation (Specification
// v1.7, Sections 9.3 to 9.5, CH-001).
//
// Runs the shared vectors in test-vectors/delegation-attenuation/vector.json.
// The Python and TypeScript SDKs run the SAME vectors and MUST produce
// identical accept/reject decisions and identical rejection reasons. Do not
// fork the expectations per language.
package signer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type attenVector struct {
	Name   string         `json:"name"`
	Chain  []Capability   `json:"chain"`
	Budget map[string]any `json:"budget"`
	Accept bool           `json:"accept"`
	Reason string         `json:"reason"`
}

func loadAttenVectors(t *testing.T) []attenVector {
	t.Helper()
	// Repo root is two levels up from go-sidecar/signer.
	path := filepath.Join("..", "..", "test-vectors", "delegation-attenuation", "vector.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var doc struct {
		Vectors []attenVector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal vectors: %v", err)
	}
	return doc.Vectors
}

func budgetFromMap(b map[string]any) *VerifierBudget {
	if b == nil {
		return nil
	}
	out := &VerifierBudget{}
	if v, ok := b["max_depth"]; ok {
		n := int(v.(float64))
		out.MaxDepth = &n
	}
	if v, ok := b["max_cumulative_ttl_seconds"]; ok {
		n := int(v.(float64))
		out.MaxCumulativeTTLSeconds = &n
	}
	if v, ok := b["max_verification_seconds"]; ok {
		f := v.(float64)
		out.MaxVerificationSeconds = &f
	}
	return out
}

func TestAttenuationVectorsModule(t *testing.T) {
	for _, vec := range loadAttenVectors(t) {
		vec := vec
		t.Run(vec.Name, func(t *testing.T) {
			result := ValidateChain(vec.Chain, budgetFromMap(vec.Budget), nil)
			if result.OK != vec.Accept {
				t.Fatalf("ok=%v want %v (reason=%s detail=%s)", result.OK, vec.Accept, result.Reason, result.Detail)
			}
			if !vec.Accept && result.Reason != vec.Reason {
				t.Fatalf("reason=%s want %s", result.Reason, vec.Reason)
			}
		})
	}
}

func TestAttenuationVectorsViaVerifier(t *testing.T) {
	for _, vec := range loadAttenVectors(t) {
		vec := vec
		t.Run(vec.Name, func(t *testing.T) {
			links := make([]any, 0, len(vec.Chain))
			for _, capx := range vec.Chain {
				intent := map[string]any{}
				for _, k := range []string{"action", "target", "resource"} {
					if v, ok := capx[k]; ok {
						intent[k] = v
					}
				}
				link := map[string]any{"intent": intent}
				for _, k := range []string{"validFrom", "validUntil", "rate", "policy"} {
					if v, ok := capx[k]; ok {
						link[k] = v
					}
				}
				links = append(links, link)
			}
			credential := map[string]any{
				"credentialSubject": map[string]any{"delegationChain": links},
			}
			result := ValidateDelegationChain(credential, budgetFromMap(vec.Budget))
			if result.OK != vec.Accept {
				t.Fatalf("ok=%v want %v (reason=%s)", result.OK, vec.Accept, result.Reason)
			}
			if !vec.Accept && result.Reason != vec.Reason {
				t.Fatalf("reason=%s want %s", result.Reason, vec.Reason)
			}
		})
	}
}
