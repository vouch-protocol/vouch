// Cross-device identity by per-device keys and delegation (the OSS path).
//
// Mirrors vouch/fleet.py. The private key never travels. Each device mints
// its OWN key locally, and the user's root identity delegates scoped,
// time-bound, revocable authority to that device's DID. A device signs its
// actions with its own key, chained under the root grant. Losing a device
// means revoking one delegation, not rotating the whole identity, and no key
// is ever copied between devices.
package signer

import (
	"fmt"
	"time"
)

// EnrollDeviceOptions configures EnrollDevice.
type EnrollDeviceOptions struct {
	DeviceDID       string
	Action          string
	Target          string
	Resource        string
	ValidSeconds    int // defaults to 86400 (1 day) if zero
	ReputationScore *int
}

// EnrollDevice issues a delegation grant from the root signer to a device's
// DID. The returned grant authorizes DeviceDID to act within the given scope.
// The device, holding its own key, signs actions with this grant as
// SignCredentialOptions.ParentCredential, so each action chains back to the
// root. The root never sees or holds the device's key.
func EnrollDevice(root *Signer, opts EnrollDeviceOptions) (map[string]any, error) {
	validSeconds := opts.ValidSeconds
	if validSeconds <= 0 {
		validSeconds = 86400
	}
	intent := map[string]any{
		"action":    opts.Action,
		"target":    opts.Target,
		"resource":  opts.Resource,
		"delegatee": opts.DeviceDID,
	}
	return root.SignCredential(SignCredentialOptions{
		Intent:          intent,
		ValidSeconds:    validSeconds,
		ReputationScore: opts.ReputationScore,
	})
}

// FleetResult is the outcome of verifying a delegated device chain.
type FleetResult struct {
	OK      bool
	Leaf    *CredentialPassport
	RootDID string
	Reason  string
}

// VerifyDelegatedChainOptions configures VerifyDelegatedChain.
type VerifyDelegatedChainOptions struct {
	// TrustedRoots maps an accepted root issuer DID to its public key. The
	// first credential's issuer MUST appear here.
	TrustedRoots map[string][]byte

	// ClockSkewSeconds tolerates clock drift when checking validity windows
	// (default 30 if zero).
	ClockSkewSeconds int64

	// Revoked reports whether an identifier (a device DID or a credential id)
	// has been revoked. The chain is rejected if any link's issuer, any
	// credential id, or any grant's delegatee is revoked. Losing a device is
	// handled by revoking its DID here; nil means nothing is revoked.
	Revoked func(identifier string) bool

	RequireAction   string
	RequireTarget   string
	RequireResource string
}

// VerifyDelegatedChain verifies a delegation chain from a trusted root down to
// a leaf action. credentials is ordered root-first:
// [rootGrant, ...intermediateGrants, leafAction]. Every credential's Data
// Integrity proof and validity window are checked, each step must be
// authorized by the step before it (the child's issuer is the parent's
// delegatee), the resource may only narrow, and the validity windows must
// nest.
func VerifyDelegatedChain(
	credentials []map[string]any,
	opts VerifyDelegatedChainOptions,
) FleetResult {
	if len(credentials) == 0 {
		return FleetResult{OK: false, Reason: "empty chain"}
	}
	skew := opts.ClockSkewSeconds
	if skew <= 0 {
		skew = 30
	}
	isRevoked := opts.Revoked
	if isRevoked == nil {
		isRevoked = func(string) bool { return false }
	}

	passports := make([]*CredentialPassport, 0, len(credentials))
	for index, cred := range credentials {
		issuer := issuerOf(cred)
		if issuer == "" {
			return FleetResult{OK: false, Reason: fmt.Sprintf("credential %d has no issuer", index)}
		}

		key, trusted := opts.TrustedRoots[issuer]
		if index == 0 && !trusted {
			return FleetResult{OK: false, Reason: fmt.Sprintf("root issuer %q is not in trusted roots", issuer)}
		}

		var ok bool
		var passport *CredentialPassport
		var err error
		if trusted {
			ok, passport, err = VerifyCredential(cred, key, formatISO8601(time.Now()), skew)
		} else {
			ok, passport, err = Verify(cred, nil, skew)
		}
		if err != nil || !ok || passport == nil {
			return FleetResult{OK: false, Reason: fmt.Sprintf("credential %d failed verification", index)}
		}

		if isRevoked(passport.Issuer) {
			return FleetResult{OK: false, Reason: fmt.Sprintf("credential %d issuer %q is revoked", index, passport.Issuer)}
		}
		if passport.CredentialID != "" && isRevoked(passport.CredentialID) {
			return FleetResult{OK: false, Reason: fmt.Sprintf("credential %d (%s) is revoked", index, passport.CredentialID)}
		}
		passports = append(passports, passport)
	}

	for i := 0; i < len(passports)-1; i++ {
		parent := passports[i]
		child := passports[i+1]

		delegatee, _ := parent.Intent["delegatee"].(string)
		if delegatee == "" {
			return FleetResult{OK: false, Reason: fmt.Sprintf("link %d (grant by %q) names no delegatee", i, parent.Issuer)}
		}
		if isRevoked(delegatee) {
			return FleetResult{OK: false, Reason: fmt.Sprintf("link %d: delegatee %q is revoked", i, delegatee)}
		}
		if child.Issuer != delegatee {
			return FleetResult{OK: false, Reason: fmt.Sprintf(
				"link %d: child issuer %q is not the delegatee %q the parent authorized", i, child.Issuer, delegatee,
			)}
		}

		parentResource := parent.Resource()
		childResource := child.Resource()
		if parentResource != "" && childResource != "" && !isSubResource(childResource, parentResource) {
			return FleetResult{OK: false, Reason: fmt.Sprintf(
				"link %d: resource %q is not within the granted %q", i, childResource, parentResource,
			)}
		}

		if !windowWithin(child, parent) {
			return FleetResult{OK: false, Reason: fmt.Sprintf("link %d: child validity is outside the grant window", i)}
		}
	}

	leaf := passports[len(passports)-1]
	checks := []struct {
		field    string
		expected string
		actual   string
	}{
		{"action", opts.RequireAction, leaf.Action()},
		{"target", opts.RequireTarget, leaf.Target()},
		{"resource", opts.RequireResource, leaf.Resource()},
	}
	for _, c := range checks {
		if c.expected != "" && c.actual != c.expected {
			return FleetResult{OK: false, Leaf: leaf, Reason: fmt.Sprintf("leaf intent.%s != %q", c.field, c.expected)}
		}
	}

	return FleetResult{OK: true, Leaf: leaf, RootDID: passports[0].Issuer}
}

func windowWithin(child, parent *CredentialPassport) bool {
	cFrom, err1 := parseISO8601(child.ValidFrom)
	cUntil, err2 := parseISO8601(child.ValidUntil)
	pFrom, err3 := parseISO8601(parent.ValidFrom)
	pUntil, err4 := parseISO8601(parent.ValidUntil)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return false
	}
	return !cFrom.Before(pFrom) && !cUntil.After(pUntil)
}

// DeviceRegistry is a small in-memory record of a root's enrolled and revoked
// devices. Pass Registry.IsRevoked straight to
// VerifyDelegatedChainOptions.Revoked, or back this with your own store (a
// database, a BitstringStatusList) by implementing the same is-revoked
// predicate yourself; this is only the simplest default.
type DeviceRegistry struct {
	enrolled map[string]map[string]any
	revoked  map[string]bool
}

// NewDeviceRegistry creates an empty registry.
func NewDeviceRegistry() *DeviceRegistry {
	return &DeviceRegistry{
		enrolled: make(map[string]map[string]any),
		revoked:  make(map[string]bool),
	}
}

// Enroll records a device as enrolled (optionally keeping its grant).
func (r *DeviceRegistry) Enroll(deviceDID string, grant map[string]any) {
	r.enrolled[deviceDID] = grant
	delete(r.revoked, deviceDID)
}

// Revoke revokes a device. Chains issued by or delegated to it stop
// verifying.
func (r *DeviceRegistry) Revoke(deviceDID string) {
	r.revoked[deviceDID] = true
}

// IsRevoked reports whether identifier has been revoked.
func (r *DeviceRegistry) IsRevoked(identifier string) bool {
	return r.revoked[identifier]
}

// ActiveDevices lists enrolled devices that have not been revoked.
func (r *DeviceRegistry) ActiveDevices() []string {
	out := make([]string, 0, len(r.enrolled))
	for did := range r.enrolled {
		if !r.revoked[did] {
			out = append(out, did)
		}
	}
	return out
}
