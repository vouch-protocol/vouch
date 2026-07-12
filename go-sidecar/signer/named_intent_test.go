// Tests for the named-argument intent convenience on SignOptions
// (Action/Target/Resource). Mirrors the Python tests in tests/test_dx_sugar.py.

package signer

import "testing"

func TestSignNamedIntentFields(t *testing.T) {
	s := newTestSigner(t, "")

	cred, err := s.Sign(SignOptions{
		Action:   "read",
		Target:   "users_table",
		Resource: "https://api.example.com/v1/users",
	})
	if err != nil {
		t.Fatalf("Sign with named fields: %v", err)
	}

	subject, ok := cred["credentialSubject"].(map[string]any)
	if !ok {
		t.Fatal("missing credentialSubject")
	}
	intent, ok := subject["intent"].(map[string]any)
	if !ok {
		t.Fatal("missing intent")
	}
	if intent["action"] != "read" || intent["target"] != "users_table" ||
		intent["resource"] != "https://api.example.com/v1/users" {
		t.Fatalf("named fields not applied: %#v", intent)
	}
}

func TestSignNamedFieldsOverrideIntentMap(t *testing.T) {
	s := newTestSigner(t, "")

	cred, err := s.Sign(SignOptions{
		Intent:   validIntent(),
		Resource: "https://api.example.com/v1/users/override",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	intent := cred["credentialSubject"].(map[string]any)["intent"].(map[string]any)
	if intent["resource"] != "https://api.example.com/v1/users/override" {
		t.Fatalf("named field did not override: %#v", intent)
	}
	if intent["action"] != "read_database" {
		t.Fatalf("unrelated intent key lost: %#v", intent)
	}
}

func TestMergeIntentDoesNotMutateInput(t *testing.T) {
	original := validIntent()
	_ = mergeIntent(original, "write", "", "")
	if original["action"] != "read_database" {
		t.Fatalf("input intent was mutated: %#v", original)
	}
}
