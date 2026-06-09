// Capability attenuation for delegation chains.
//
// Specification v1.7, Sections 9.3 to 9.5 (see docs/specs/w3c-cg-report-v1.7-draft.md).
//
// Core rule (settled): every delegated capability MUST be a proper subset of its
// parent across at least one of {action, target, resource, time, rate, policy},
// and MUST NOT be broader on any dimension. A chain ends naturally when nothing
// remains to narrow; there is no fixed maximum depth (the v1.6.2 depth cap is
// removed). Cost control moves to optional, verifier-local budgets.
//
// This file is the Go mirror of vouch/attenuation.py. The Python, TypeScript,
// and Go SDKs behave identically: same accept/reject decisions and same
// rejection-reason strings on every shared interop vector.
//
// Three edge policies are intentionally left open (pending Alan Karp's input),
// exposed here as extension points rather than hardcoded rules:
//   - meaningful-narrowing threshold (CH-001 open question 1): see the
//     MeaningfulNarrowing hook.
//   - leaf/termination wording (CH-001 open question 2): falls out of the subset rule.
//   - chain-cascade revocation (CH-003): see the CascadeRevocation hook.
//
// Do not freeze these as final behavior until the open questions resolve.

package signer

import (
	"math"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Structured rejection reasons (stable strings, shared across the three SDKs).
// ---------------------------------------------------------------------------

const (
	ReasonCapabilityNotAttenuated = "capability_not_attenuated"
	ReasonResourceNotNarrowed   = "resource_not_narrowed"
	ReasonVerifierBudgetExceeded  = "verifier_budget_exceeded"
)

// NOTE: "chain_depth_exceeded" is removed as a protocol-level hard error in
// v1.7. Depth is now a verifier-budget concern and surfaces, when a verifier
// chooses to cap it, as ReasonVerifierBudgetExceeded with limit "max_depth".

// AttenuationDimensions is the dimension order. It is significant: the first
// broadened dimension found determines the rejection reason.
var AttenuationDimensions = []string{"action", "target", "resource", "time", "rate", "policy"}

// Capability is a plain map with any of:
//
//	action: string | []any
//	target: string | []any
//	resource: string
//	validFrom / validUntil: ISO-8601 string (the time dimension)
//	rate: {"limit": number, "window": ISO-8601 duration or seconds}
//	policy: map
//
// The vector JSON decodes straight into this type.
type Capability = map[string]any

// VerifierBudget is an optional, verifier-local cost cap (Specification v1.7
// Section 9.4). A nil pointer field means unlimited: there is NO protocol-level
// cap. A verifier MAY set any subset of these to bound the work it spends on a
// chain. Exceeding a set limit yields ReasonVerifierBudgetExceeded with the
// specific limit named, so the delegating agent narrows earlier instead of
// routing around the block.
type VerifierBudget struct {
	MaxDepth        *int
	MaxVerificationSeconds  *float64
	MaxCumulativeTTLSeconds *int
}

// AttenuationResult is the outcome of an attenuation/budget check.
type AttenuationResult struct {
	OK    bool
	Reason  string
	Detail  string
	// NarrowedOn lists the dimensions on which the child was strictly narrower.
	NarrowedOn []string
}

// MeaningfulNarrowing is an optional hook: meaningful-narrowing threshold
// (CH-001 open question 1). Receives (parent, child, narrowedOn) and returns
// true if the narrowing is "meaningful" per verifier policy. A nil hook accepts
// any proper subset on at least one dimension (the permissive rule). A verifier
// MAY supply a stricter hook, for example requiring narrowing on
// action/target/resource rather than a trivial rate 100 -> 99.
// TODO(CH-001 Q1): do not hardcode a final threshold here.
type MeaningfulNarrowing func(parent, child Capability, narrowedOn []string) bool

// PolicyComparator is an optional policy-dimension comparator. Returns one of
// "narrower", "equal", "broader", "incomparable". The default comparator is
// conservative (see comparePolicy). Supplied so deployments with domain-specific
// policy fields can define strictness without changing this file.
type PolicyComparator func(parent, child map[string]any) string

// CascadeRevocation is an optional extension point: chain-cascade revocation
// (CH-003). Receives the full ordered capability chain and returns an
// AttenuationResult; return OK=true to accept. A nil hook performs NO cascade
// check. TODO(CH-003): the cascade semantics (does revoking/rotating a mid-chain
// link invalidate everything downstream) are not yet specified. Do not assume a
// final rule here.
type CascadeRevocation func(capabilities []Capability) AttenuationResult

// AttenuationOptions bundles the optional hooks for the public functions.
type AttenuationOptions struct {
	MeaningfulNarrowing MeaningfulNarrowing
	PolicyComparator  PolicyComparator
	CascadeRevocation  CascadeRevocation
	// ElapsedSeconds is the measured verification time, supplied by the caller
	// for the max-verification-seconds budget. A nil pointer means unmeasured.
	ElapsedSeconds *float64
}

// ---------------------------------------------------------------------------
// Per-dimension subset tests. Each returns (isSubset, isStrict).
// "isSubset" means the child does NOT broaden this dimension.
// "isStrict" means the child is strictly narrower on this dimension.
// A dimension absent on the child is inherited unchanged (subset, not strict).
// ---------------------------------------------------------------------------

// asSet normalizes a value to a set of strings. A single value becomes a
// 1-element set. Returns (nil, false) when the value is absent.
func asSet(value any) (map[string]struct{}, bool) {
	if value == nil {
		return nil, false
	}
	out := make(map[string]struct{})
	switch v := value.(type) {
	case []any:
		for _, item := range v {
			out[setKey(item)] = struct{}{}
		}
	case []string:
		for _, item := range v {
			out[item] = struct{}{}
		}
	default:
		out[setKey(value)] = struct{}{}
	}
	return out, true
}

// setKey produces a stable, type-distinct key for a set member. Distinct types
// hash distinctly so that, for example, the string "1" and the number 1 are not
// treated as the same member.
func setKey(item any) string {
	switch v := item.(type) {
	case string:
		return "s:" + v
	case bool:
		return "b:" + strconv.FormatBool(v)
	case float64:
		return "n:" + strconv.FormatFloat(v, 'g', -1, 64)
	case float32:
		return "n:" + strconv.FormatFloat(float64(v), 'g', -1, 64)
	case int:
		return "n:" + strconv.FormatFloat(float64(v), 'g', -1, 64)
	case int64:
		return "n:" + strconv.FormatFloat(float64(v), 'g', -1, 64)
	default:
		return "x:" + strconv.Quote(reflectFallback(v))
	}
}

func reflectFallback(v any) string {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return ""
	}
	return rv.Kind().String()
}

// setsEqual reports whether two string sets contain the same members.
func setsEqual(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

// isSubsetOf reports whether every member of sub is in sup.
func isSubsetOf(sub, sup map[string]struct{}) bool {
	for k := range sub {
		if _, ok := sup[k]; !ok {
			return false
		}
	}
	return true
}

func checkSetDimension(parent, child Capability, key string) (bool, bool) {
	p, pOK := asSet(parent[key])
	c, cOK := asSet(child[key])
	if !cOK || (pOK && setsEqual(c, p)) {
		return true, false // inherited or unchanged
	}
	if !pOK {
		// Parent unconstrained, child constrains: narrower.
		return true, true
	}
	if isSubsetOf(c, p) {
		return true, !setsEqual(c, p) // strict subset
	}
	return false, false // child has members the parent lacks: broader
}

func checkAction(parent, child Capability) (bool, bool) {
	return checkSetDimension(parent, child, "action")
}

func checkTarget(parent, child Capability) (bool, bool) {
	return checkSetDimension(parent, child, "target")
}

// IsSubResource reports whether child is a sub-resource of (or equal to)
// parent. Conservative URL-prefix match: child must equal parent or extend it
// after a path separator. Mirrors the v1.6.2 resource-narrowing rule
// (Section 9.3 step 5).
func IsSubResource(child, parent string) bool {
	// Reject relative path-traversal segments (".."): a child like
	// "https://api/v1/../admin" passes a naive prefix check yet resolves outside
	// the granted scope, so it must not count as a sub-resource.
	if hasPathTraversal(child) || hasPathTraversal(parent) {
		return false
	}
	if child == parent {
		return true
	}
	if strings.HasPrefix(child, strings.TrimRight(parent, "/")+"/") {
		return true
	}
	return false
}

func hasPathTraversal(uri string) bool {
	for _, seg := range strings.Split(uri, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

func checkResource(parent, child Capability) (bool, bool) {
	p, _ := parent["resource"].(string)
	c, _ := child["resource"].(string)
	if c == "" || c == p {
		return true, false
	}
	if p == "" {
		return true, true
	}
	if IsSubResource(c, p) {
		return true, c != p
	}
	return false, false
}

func parseISO(value any) (time.Time, bool) {
	s, ok := value.(string)
	if !ok || s == "" {
		return time.Time{}, false
	}
	// Accept both "...Z" and "...+00:00" forms.
	v := strings.Replace(s, "Z", "+00:00", 1)
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05-07:00",
		"2006-01-02T15:04:05.999999999-07:00",
	}
	for _, f := range formats {
		if dt, err := time.Parse(f, v); err == nil {
			return dt.UTC(), true
		}
	}
	// Naive form without offset: treat as UTC.
	if dt, err := time.Parse("2006-01-02T15:04:05", s); err == nil {
		return dt.UTC(), true
	}
	return time.Time{}, false
}

func checkTime(parent, child Capability) (bool, bool) {
	pf, pfOK := parseISO(parent["validFrom"])
	pu, puOK := parseISO(parent["validUntil"])
	cf, cfOK := parseISO(child["validFrom"])
	cu, cuOK := parseISO(child["validUntil"])
	if !cfOK && !cuOK {
		return true, false // inherited
	}
	// Child interval must lie within the parent interval on both ends.
	if pfOK && cfOK && cf.Before(pf) {
		return false, false
	}
	if puOK && cuOK && cu.After(pu) {
		return false, false
	}
	strict := (pfOK && cfOK && cf.After(pf)) || (puOK && cuOK && cu.Before(pu))
	return true, strict
}

func ratePerSecond(rate any) (float64, bool) {
	m, ok := rate.(map[string]any)
	if !ok || m == nil {
		return 0, false
	}
	limit, ok := toFloat(m["limit"])
	if !ok {
		return 0, false
	}
	var window any = m["window"]
	if window == nil {
		window = float64(1)
	}
	seconds, ok := durationSeconds(window)
	if !ok || seconds <= 0 {
		return 0, false
	}
	return limit / seconds, true
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json_Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

// json_Number is a tiny alias so toFloat can accept encoding/json.Number when a
// decoder uses UseNumber(). The vector test decodes into any (float64), so this
// path is defensive only.
type json_Number interface {
	Float64() (float64, error)
}

var isoDurationRe = regexp.MustCompile(`^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$`)

// durationSeconds parses a rate window: a number of seconds, or a simple
// ISO-8601 duration (PT#H/PT#M/PT#S and P#D forms).
func durationSeconds(window any) (float64, bool) {
	if f, ok := toFloat(window); ok {
		return f, true
	}
	s, ok := window.(string)
	if !ok {
		return 0, false
	}
	s = strings.ToUpper(strings.TrimSpace(s))
	if !strings.HasPrefix(s, "P") {
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f, true
		}
		return 0, false
	}
	m := isoDurationRe.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	atoi := func(g string) int {
		if g == "" {
			return 0
		}
		n, _ := strconv.Atoi(g)
		return n
	}
	days, hours, mins, secs := atoi(m[1]), atoi(m[2]), atoi(m[3]), atoi(m[4])
	total := days*86400 + hours*3600 + mins*60 + secs
	if total <= 0 {
		return 0, false
	}
	return float64(total), true
}

func checkRate(parent, child Capability) (bool, bool) {
	rateVal, present := child["rate"]
	childHasRate := present && rateVal != nil
	p, pOK := ratePerSecond(parent["rate"])
	c, cOK := ratePerSecond(child["rate"])
	if !childHasRate {
		return true, false // absent (or null): inherited
	}
	if !cOK {
		// rate present but unparseable (for example window 0): treat as
		// broadening rather than silently inheriting, which would be a
		// rate-cap bypass.
		return false, false
	}
	if !pOK {
		return true, true // parent unconstrained, child caps: narrower
	}
	if c <= p {
		return true, c < p
	}
	return false, false
}

// comparePolicy is the conservative default policy comparator.
//
// A policy is "narrower" (stricter) when the child keeps every constraint the
// parent had AND adds at least one. It is "equal" when identical. It is
// "broader" when the child relaxes or removes a parent constraint.
// TODO(CH-001 Q1): policy strictness direction is deployment-specific; do not
// assume a global numeric direction here.
func comparePolicy(parent, child map[string]any) string {
	if reflect.DeepEqual(parent, child) {
		return "equal"
	}
	// Any parent key dropped, or any shared key whose value changed, is broader
	// under the conservative default (we cannot prove it got stricter).
	for k := range parent {
		cv, ok := child[k]
		if !ok {
			return "broader"
		}
		if !reflect.DeepEqual(parent[k], cv) {
			return "broader"
		}
	}
	// Child kept all parent constraints; if it added more it is stricter.
	if len(child) > len(parent) {
		return "narrower"
	}
	return "equal"
}

func checkPolicy(parent, child Capability, comparator PolicyComparator) (bool, bool) {
	cRaw, cPresent := child["policy"]
	if !cPresent || cRaw == nil {
		return true, false // inherited
	}
	c, _ := cRaw.(map[string]any)
	pRaw, pPresent := parent["policy"]
	p, _ := pRaw.(map[string]any)
	if !pPresent || pRaw == nil || len(p) == 0 {
		return true, len(c) > 0 // parent unconstrained, child adds policy: narrower
	}
	cmp := comparePolicy(p, c)
	if comparator != nil {
		cmp = comparator(p, c)
	}
	if cmp == "broader" || cmp == "incomparable" {
		return false, false
	}
	return true, cmp == "narrower"
}

func dimensionCheck(dim string, parent, child Capability, comparator PolicyComparator) (bool, bool) {
	switch dim {
	case "action":
		return checkAction(parent, child)
	case "target":
		return checkTarget(parent, child)
	case "resource":
		return checkResource(parent, child)
	case "time":
		return checkTime(parent, child)
	case "rate":
		return checkRate(parent, child)
	case "policy":
		return checkPolicy(parent, child, comparator)
	}
	return true, false
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// CheckAttenuation checks the attenuation rule for one (parent, child)
// capability pair.
//
// Returns OK=true iff the child is a proper subset of the parent across at
// least one dimension and broader on none. On failure, Reason is
// ReasonResourceNotNarrowed when the offending dimension is the resource, else
// ReasonCapabilityNotAttenuated.
func CheckAttenuation(parent, child Capability, opts *AttenuationOptions) AttenuationResult {
	var comparator PolicyComparator
	var meaningful MeaningfulNarrowing
	if opts != nil {
		comparator = opts.PolicyComparator
		meaningful = opts.MeaningfulNarrowing
	}

	var narrowedOn []string
	for _, dim := range AttenuationDimensions {
		isSubset, isStrict := dimensionCheck(dim, parent, child, comparator)
		if !isSubset {
			reason := ReasonCapabilityNotAttenuated
			if dim == "resource" {
				reason = ReasonResourceNotNarrowed
			}
			return AttenuationResult{OK: false, Reason: reason, Detail: "broader on " + dim}
		}
		if isStrict {
			narrowedOn = append(narrowedOn, dim)
		}
	}

	if len(narrowedOn) == 0 {
		// Subset on every dimension but strictly narrower on none: not attenuated.
		return AttenuationResult{
			OK:   false,
			Reason: ReasonCapabilityNotAttenuated,
			Detail: "no dimension narrowed",
		}
	}

	// TODO(CH-001 Q1): optional stricter "meaningful narrowing" policy. The
	// permissive default accepts a proper subset on any single dimension.
	if meaningful != nil && !meaningful(parent, child, narrowedOn) {
		return AttenuationResult{
			OK:     false,
			Reason:   ReasonCapabilityNotAttenuated,
			Detail:   "narrowing not meaningful (verifier policy)",
			NarrowedOn: narrowedOn,
		}
	}

	return AttenuationResult{OK: true, NarrowedOn: narrowedOn}
}

// FindBroadenedDimension returns the first dimension on which child BROADENS
// parent, or "" if none.
//
// Builder-side helper: a delegator can never grant more than it holds, so the
// builder blocks any outright broadening. It does NOT require strict narrowing
// (the full attenuation rule, narrowing on at least one dimension, is enforced
// by the verifier via CheckAttenuation / ValidateChain). This keeps the builder
// permissive enough for equal-capability pass-through while still refusing to
// widen authority.
func FindBroadenedDimension(parent, child Capability, opts *AttenuationOptions) string {
	var comparator PolicyComparator
	if opts != nil {
		comparator = opts.PolicyComparator
	}
	for _, dim := range AttenuationDimensions {
		isSubset, _ := dimensionCheck(dim, parent, child, comparator)
		if !isSubset {
			return dim
		}
	}
	return ""
}

// ValidateChain validates a full delegation chain, ordered broadest (root) to
// narrowest (leaf).
//
// Each adjacent pair (capabilities[i], capabilities[i+1]) must satisfy the
// attenuation rule. The chain terminates naturally at a leaf where nothing can
// narrow further (CH-001 Q2: this falls out of the subset rule; no explicit
// leaf condition is hardcoded). Verifier cost budgets are applied first and, on
// breach, return ReasonVerifierBudgetExceeded naming the limit hit.
func ValidateChain(capabilities []Capability, budget *VerifierBudget, opts *AttenuationOptions) AttenuationResult {
	// "depth" is the number of capability nodes in the chain (for a delegation
	// chain, the number of delegation links). Adjacent attenuation is checked
	// over the depth-1 edges between them.
	depth := len(capabilities)

	// Verifier cost budget: depth (replaces the removed protocol depth cap).
	if budget != nil && budget.MaxDepth != nil && depth > *budget.MaxDepth {
		return AttenuationResult{
			OK:   false,
			Reason: ReasonVerifierBudgetExceeded,
			Detail: "max_depth=" + strconv.Itoa(*budget.MaxDepth),
		}
	}

	// Verifier cost budget: cumulative validity (TTL) across the chain.
	if budget != nil && budget.MaxCumulativeTTLSeconds != nil {
		totalTTL, ok := cumulativeTTLSeconds(capabilities)
		if ok && totalTTL > float64(*budget.MaxCumulativeTTLSeconds) {
			return AttenuationResult{
				OK:   false,
				Reason: ReasonVerifierBudgetExceeded,
				Detail: "max_cumulative_ttl_seconds=" + strconv.Itoa(*budget.MaxCumulativeTTLSeconds),
			}
		}
	}

	// Verifier cost budget: total verification time (caller measures, passes in).
	if budget != nil && budget.MaxVerificationSeconds != nil &&
		opts != nil && opts.ElapsedSeconds != nil &&
		*opts.ElapsedSeconds > *budget.MaxVerificationSeconds {
		return AttenuationResult{
			OK:   false,
			Reason: ReasonVerifierBudgetExceeded,
			Detail: "max_verification_seconds=" + strconv.FormatFloat(*budget.MaxVerificationSeconds, 'g', -1, 64),
		}
	}

	for i := 0; i < depth-1; i++ {
		result := CheckAttenuation(capabilities[i], capabilities[i+1], opts)
		if !result.OK {
			return result
		}
	}

	// TODO(CH-003): chain-cascade revocation. The cascade semantics (mid-chain
	// revocation or key rotation invalidating downstream links) are not yet
	// specified. The hook is an extension point only; default does nothing.
	if opts != nil && opts.CascadeRevocation != nil {
		cascade := opts.CascadeRevocation(capabilities)
		if !cascade.OK {
			return cascade
		}
	}

	return AttenuationResult{OK: true}
}

func cumulativeTTLSeconds(capabilities []Capability) (float64, bool) {
	total := 0.0
	seen := false
	for _, cap := range capabilities {
		cf, cfOK := parseISO(cap["validFrom"])
		cu, cuOK := parseISO(cap["validUntil"])
		if cfOK && cuOK {
			total += math.Max(0.0, cu.Sub(cf).Seconds())
			seen = true
		}
	}
	return total, seen
}

// capabilityFromCredential projects a credential (and its intent) onto a
// capability for the attenuation checks: action/target/resource from intent,
// time from the credential, and the optional rate/policy from the
// credentialSubject. Builder-side helper.
func capabilityFromCredential(intent map[string]any, credential map[string]any) Capability {
	out := Capability{}
	if intent != nil {
		for _, k := range []string{"action", "target", "resource"} {
			if v, ok := intent[k]; ok && v != nil {
				out[k] = v
			}
		}
	}
	if credential != nil {
		if v, ok := credential["validFrom"]; ok && v != nil && v != "" {
			out["validFrom"] = v
		}
		if v, ok := credential["validUntil"]; ok && v != nil && v != "" {
			out["validUntil"] = v
		}
		if subj, ok := credential["credentialSubject"].(map[string]any); ok {
			if v, ok := subj["rate"]; ok && v != nil {
				out["rate"] = v
			}
			if v, ok := subj["policy"]; ok && v != nil {
				out["policy"] = v
			}
		}
	}
	return out
}

// linkCapability projects a delegation link onto a capability: action/target/
// resource from intent, time from validFrom/validUntil, and the optional
// rate/policy dimensions (Specification v1.7, Section 9.2). Verifier-side helper.
func linkCapability(link map[string]any) Capability {
	out := Capability{}
	intent, _ := link["intent"].(map[string]any)
	if intent != nil {
		for _, k := range []string{"action", "target", "resource"} {
			if v, ok := intent[k]; ok && v != nil {
				out[k] = v
			}
		}
	}
	for _, k := range []string{"validFrom", "validUntil", "rate", "policy"} {
		if v, ok := link[k]; ok && v != nil {
			out[k] = v
		}
	}
	return out
}

// ValidateDelegationChain is the verifier-side capability-attenuation check
// (Specification v1.7, 9.3 to 9.5). It extracts the ordered capability list from
// the credential's delegationChain and applies the attenuation rule plus any
// optional verifier cost budget. A chain of 0 or 1 link has nothing to attenuate
// (the root grant has no parent in the chain). There is no fixed depth limit;
// depth, when a verifier caps it, is part of budget and surfaces as
// ReasonVerifierBudgetExceeded.
func ValidateDelegationChain(credential map[string]any, budget *VerifierBudget) AttenuationResult {
	var capabilities []Capability
	if subject, ok := credential["credentialSubject"].(map[string]any); ok {
		switch raw := subject["delegationChain"].(type) {
		case []any:
			for _, item := range raw {
				if m, ok := item.(map[string]any); ok {
					capabilities = append(capabilities, linkCapability(m))
				}
			}
		case []map[string]any:
			for _, m := range raw {
				capabilities = append(capabilities, linkCapability(m))
			}
		}
	}
	return ValidateChain(capabilities, budget, nil)
}
