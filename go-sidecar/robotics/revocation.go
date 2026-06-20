// Revocation for robot credentials (Phase 5.x), Go.
//
// Mirrors vouch/robotics/revocation.py and the TypeScript SDK. Robot identity,
// provenance, and capability credentials need the same two-level revocation the
// rest of Vouch provides, applied to physical machines:
//
//   - Whole-DID kill (key compromise): a robot DID is an ordinary DID, so the
//     existing DID-level revocation distribution path works unchanged.
//   - Surgical per-credential revocation: a single capability grant, a
//     superseded provenance attestation, or one identity credential is retired
//     without killing the robot's whole identity, by carrying a
//     BitstringStatusList entry.
//
// This file adds the ergonomics for putting a BitstringStatusList entry on any
// robot credential and checking it, over the existing signer status-list
// primitives. The formats and the verifier here are the open protocol surface;
// fleet-scale operation (SLA'd propagation, dashboards, aggregation) is a
// service concern layered on top.
package robotics

import (
	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// StatusError is returned for malformed credentialStatus structures.
type StatusError struct{ Msg string }

func (e *StatusError) Error() string { return e.Msg }

// AttachStatusOptions configures AttachCredentialStatus.
type AttachStatusOptions struct {
	StatusListCredential string
	StatusListIndex      int
	StatusPurpose        string // "" defaults to revocation
	EntryID              string // "" derives "<statusListCredential>#<index>"
}

// AttachCredentialStatus adds a BitstringStatusList credentialStatus entry to a
// robot credential and (re)signs it, so the credential can later be revoked or
// suspended surgically. The entry references a bit index in a published status
// list credential. The credential is signed after the entry is added, so the
// proof covers the status binding. Any pre-existing proof is replaced. If the
// credential already carries a credentialStatus, the new entry is appended (the
// field becomes a list), matching the Verifiable Credentials data model.
//
// Returns the signed credential.
func AttachCredentialStatus(cred map[string]any, s *signer.Signer, opts AttachStatusOptions) (map[string]any, error) {
	entry, err := signer.BuildStatusListEntry(signer.BuildStatusListEntryOptions{
		StatusListCredential: opts.StatusListCredential,
		StatusListIndex:      opts.StatusListIndex,
		StatusPurpose:        opts.StatusPurpose,
		EntryID:              opts.EntryID,
	})
	if err != nil {
		return nil, err
	}

	existing, ok := cred["credentialStatus"]
	switch {
	case !ok || existing == nil:
		cred["credentialStatus"] = entry
	case isList(existing):
		cred["credentialStatus"] = append(toAnyList(existing), entry)
	default:
		cred["credentialStatus"] = []any{existing, entry}
	}

	// Re-sign: the proof must cover the credentialStatus we just added.
	delete(cred, "proof")
	return s.AttachProof(cred)
}

// CheckCredentialStatus returns true if the robot credential's status bit for
// statusPurpose is set (for example, the credential has been revoked) in the
// supplied status list. An empty statusPurpose defaults to revocation.
//
// The caller MUST verify the Data Integrity proof on statusListCredential before
// calling this, exactly as for the agent-side status-list verify. Returns false
// when the credential carries no matching status entry.
func CheckCredentialStatus(cred, statusListCredential map[string]any, statusPurpose string) (bool, error) {
	if statusPurpose == "" {
		statusPurpose = signer.StatusPurposeRevocation
	}
	referencedID, _ := statusListCredential["id"].(string)
	entries, err := statusEntries(cred)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if p, _ := entry["statusPurpose"].(string); p != statusPurpose {
			continue
		}
		if c, _ := entry["statusListCredential"].(string); c != referencedID {
			continue
		}
		return signer.VerifyStatus(entry, statusListCredential)
	}
	return false, nil
}

// statusEntries normalizes credentialStatus into a list of entry objects,
// accepting a single object, a list of objects, or nothing.
func statusEntries(cred map[string]any) ([]map[string]any, error) {
	raw, ok := cred["credentialStatus"]
	if !ok || raw == nil {
		return nil, nil
	}
	if m, ok := raw.(map[string]any); ok {
		return []map[string]any{m}, nil
	}
	if list, ok := asAnyList(raw); ok {
		out := make([]map[string]any, 0, len(list))
		for _, e := range list {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out, nil
	}
	return nil, &StatusError{"credentialStatus must be an object or a list of objects"}
}

func isList(v any) bool {
	_, ok := asAnyList(v)
	return ok
}

func toAnyList(v any) []any {
	list, _ := asAnyList(v)
	return list
}

// asAnyList coerces the list shapes credentialStatus may take: a []any (as a
// builder assembles it) or a []map[string]any (as some decoders produce).
func asAnyList(v any) ([]any, bool) {
	switch list := v.(type) {
	case []any:
		return list, true
	case []map[string]any:
		out := make([]any, len(list))
		for i, e := range list {
			out[i] = e
		}
		return out, true
	}
	return nil, false
}
