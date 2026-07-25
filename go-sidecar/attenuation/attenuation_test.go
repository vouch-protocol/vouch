package attenuation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The Go validator MUST produce the same verdicts as the Rust core on the
// shared interop vectors.
func TestGoMatchesDelegationVectors(t *testing.T) {
	path := filepath.Join("..", "..", "test-vectors", "delegation-attenuation", "vector.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var doc struct {
		Cases []struct {
			Name    string                 `json:"name"`
			Request map[string]interface{} `json:"request"`
			Expect  map[string]interface{} `json:"expect"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("no cases")
	}

	for _, c := range doc.Cases {
		reqBytes, _ := json.Marshal(c.Request)
		var verdict map[string]interface{}
		if err := json.Unmarshal([]byte(ValidateChainJSON(string(reqBytes))), &verdict); err != nil {
			t.Fatalf("%s: verdict not json: %v", c.Name, err)
		}
		if verdict["valid"] != c.Expect["valid"] {
			t.Errorf("%s: valid mismatch: got %v", c.Name, verdict)
			continue
		}
		if c.Expect["valid"] == false {
			if verdict["code"] != c.Expect["code"] {
				t.Errorf("%s: code mismatch: got %v", c.Name, verdict)
			}
			for _, field := range []string{"dimension", "limit", "linkIndex"} {
				if want, ok := c.Expect[field]; ok {
					if verdict[field] != want {
						t.Errorf("%s: %s mismatch: got %v want %v", c.Name, field, verdict[field], want)
					}
				}
			}
		}
	}
}
