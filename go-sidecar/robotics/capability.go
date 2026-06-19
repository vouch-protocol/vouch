// Physical capability scope for robots (Phase 5.3), Go.
//
// Mirrors vouch/robotics/capability.py and the TypeScript SDK. Extends capability
// attenuation to the physical world: max force and speed, a slower speed cap near
// humans, allowed zones, and shift windows, carried in a signed credential so the
// bound is cryptographically enforceable. A controller checks a proposed action
// against the granted scope before actuating, and a delegated scope must attenuate
// (narrow, never broaden) its parent.
//
// CheckPhysicalAction and Attenuates accept a scope as map[string]any, which is
// both how the builder assembles it and how it arrives after a cross-language
// JSON verify (numbers as float64, arrays as []any of map[string]any). The
// coercion helpers below handle both shapes so the same scope verified in Python
// or TypeScript checks identically in Go.
package robotics

import (
	"fmt"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// PhysicalScopeType is the credential type for a physical capability scope.
const PhysicalScopeType = "PhysicalCapabilityScope"

// PhysicalAction is a proposed actuation to check against a scope. Pointer
// numerics distinguish "not specified" from a meaningful zero (0 N is a real
// force bound).
type PhysicalAction struct {
	ForceN     *float64
	SpeedMps   *float64
	NearHumans bool
	Zone       string // "" = not specified
	TimeHm     string // "HH:MM" local; "" = not specified
}

// CheckResult is the outcome of CheckPhysicalAction.
type CheckResult struct {
	OK      bool
	Reasons []string
}

// ShiftWindow is an allowed time-of-day window, "HH:MM" start and end.
type ShiftWindow struct {
	Start string
	End   string
}

// BuildPhysicalScopeOptions configures BuildPhysicalScopeCredential. Pointer
// numerics omit the field when nil.
type BuildPhysicalScopeOptions struct {
	SubjectDID            string
	MaxForceN             *float64
	MaxSpeedMps           *float64
	MaxSpeedNearHumansMps *float64
	AllowedZones          []string      // nil omits the field
	ShiftWindows          []ShiftWindow // nil omits the field
	ValidSeconds          int           // 0 omits validUntil
	ValidFrom             time.Time     // zero uses now
}

// BuildPhysicalScopeCredential builds a signed PhysicalCapabilityScope credential.
func BuildPhysicalScopeCredential(s *signer.Signer, opts BuildPhysicalScopeOptions) (map[string]any, error) {
	scope := map[string]any{}
	if opts.MaxForceN != nil {
		scope["maxForceN"] = *opts.MaxForceN
	}
	if opts.MaxSpeedMps != nil {
		scope["maxSpeedMps"] = *opts.MaxSpeedMps
	}
	if opts.MaxSpeedNearHumansMps != nil {
		scope["maxSpeedNearHumansMps"] = *opts.MaxSpeedNearHumansMps
	}
	if opts.AllowedZones != nil {
		zones := make([]any, len(opts.AllowedZones))
		for i, z := range opts.AllowedZones {
			zones[i] = z
		}
		scope["allowedZones"] = zones
	}
	if opts.ShiftWindows != nil {
		ws := make([]any, len(opts.ShiftWindows))
		for i, w := range opts.ShiftWindows {
			ws[i] = map[string]any{"start": w.Start, "end": w.End}
		}
		scope["shiftWindows"] = ws
	}

	issued := opts.ValidFrom
	if issued.IsZero() {
		issued = time.Now().UTC()
	}
	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", PhysicalScopeType},
		"issuer":            s.DID(),
		"validFrom":         iso(issued),
		"credentialSubject": map[string]any{"id": opts.SubjectDID, "physicalScope": scope},
	}
	if opts.ValidSeconds > 0 {
		cred["validUntil"] = iso(issued.Add(time.Duration(opts.ValidSeconds) * time.Second))
	}
	return s.AttachProof(cred)
}

// CheckPhysicalAction checks a proposed physical action against a physical scope
// object, returning ok plus a list of reasons for any violation.
func CheckPhysicalAction(scope map[string]any, action PhysicalAction) CheckResult {
	var reasons []string

	if action.ForceN != nil {
		if cap, ok := scopeNum(scope, "maxForceN"); ok && *action.ForceN > cap {
			reasons = append(reasons, fmt.Sprintf("force_exceeded: %vN > %vN", *action.ForceN, cap))
		}
	}

	if action.SpeedMps != nil {
		cap, has := scopeNum(scope, "maxSpeedMps")
		if action.NearHumans {
			if nh, ok := scopeNum(scope, "maxSpeedNearHumansMps"); ok {
				cap, has = nh, true
			}
		}
		if has && *action.SpeedMps > cap {
			label := ""
			if action.NearHumans {
				label = "near_humans "
			}
			reasons = append(reasons, fmt.Sprintf("%sspeed_exceeded: %v m/s > %v m/s", label, *action.SpeedMps, cap))
		}
	}

	if action.Zone != "" {
		if zonesAny, ok := scope["allowedZones"]; ok {
			if !containsStr(toStrSlice(zonesAny), action.Zone) {
				reasons = append(reasons, "zone_not_allowed: "+action.Zone)
			}
		}
	}

	if action.TimeHm != "" {
		if wsAny, ok := scope["shiftWindows"]; ok {
			windows := toWindows(wsAny)
			if len(windows) > 0 {
				inAny := false
				for _, w := range windows {
					if inWindow(action.TimeHm, w) {
						inAny = true
						break
					}
				}
				if !inAny {
					reasons = append(reasons, "outside_shift_window: "+action.TimeHm)
				}
			}
		}
	}

	return CheckResult{OK: len(reasons) == 0, Reasons: reasons}
}

// Attenuates reports whether child is a valid attenuation of parent: never broader
// on any physical dimension. Numeric caps may only shrink; allowed zones may only
// be a subset; shift windows must each fit inside some parent window.
func Attenuates(parent, child map[string]any) bool {
	for _, key := range []string{"maxForceN", "maxSpeedMps", "maxSpeedNearHumansMps"} {
		if pv, ok := scopeNum(parent, key); ok {
			cv, has := scopeNum(child, key)
			if !has || cv > pv {
				return false
			}
		}
	}

	if pz, ok := parent["allowedZones"]; ok {
		pset := toStrSlice(pz)
		cz := toStrSlice(child["allowedZones"])
		if len(cz) == 0 {
			return false
		}
		for _, z := range cz {
			if !containsStr(pset, z) {
				return false
			}
		}
	}

	if pw, ok := parent["shiftWindows"]; ok {
		pWindows := toWindows(pw)
		for _, cw := range toWindows(child["shiftWindows"]) {
			cs, ce := windowBounds(cw)
			fits := false
			for _, pwin := range pWindows {
				ps, pe := windowBounds(pwin)
				if ps <= cs && ce <= pe {
					fits = true
					break
				}
			}
			if !fits {
				return false
			}
		}
	}

	return true
}

func inWindow(hm string, w ShiftWindow) bool {
	start, end := windowBounds(w)
	return start <= hm && hm <= end
}

func windowBounds(w ShiftWindow) (string, string) {
	start, end := w.Start, w.End
	if start == "" {
		start = "00:00"
	}
	if end == "" {
		end = "23:59"
	}
	return start, end
}

// scopeNum reads a numeric scope field, coercing the float64 that JSON decoding
// produces as well as native Go numerics.
func scopeNum(scope map[string]any, key string) (float64, bool) {
	v, ok := scope[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

func toStrSlice(v any) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		out := make([]string, 0, len(s))
		for _, e := range s {
			if str, ok := e.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}

func toWindows(v any) []ShiftWindow {
	switch ws := v.(type) {
	case []ShiftWindow:
		return ws
	case []any:
		out := make([]ShiftWindow, 0, len(ws))
		for _, e := range ws {
			if m, ok := e.(map[string]any); ok {
				w := ShiftWindow{}
				w.Start, _ = m["start"].(string)
				w.End, _ = m["end"].(string)
				out = append(out, w)
			}
		}
		return out
	}
	return nil
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
