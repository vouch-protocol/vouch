// Package attenuation implements the v1.7 capability-attenuation rule: the
// non-expansion check over the six delegation dimensions, verifier cost
// budgets, and chain-cascade revocation (Specification 9.3-9.6).
//
// It is a faithful port of core/vouch-core/src/attenuation.rs; the two MUST
// agree verdict-for-verdict against test-vectors/delegation-attenuation.
//
// Security posture: default-deny. Any malformed input or ambiguous comparison
// rejects, because delegation grants authority and a false "valid" is an
// authority-escalation bug.
package attenuation

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"
)

const rateEpsilon = 1e-9

// Verdict is the uniform result shape shared with the other implementations.
type Verdict map[string]interface{}

func isoToEpoch(s string) (int64, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0, err
	}
	return t.Unix(), nil
}

// stringSet: nil map => absent; a string or []string => set; else error.
func stringSet(v interface{}) (map[string]bool, error) {
	if v == nil {
		return nil, nil
	}
	switch t := v.(type) {
	case string:
		return map[string]bool{t: true}, nil
	case []interface{}:
		set := map[string]bool{}
		for _, item := range t {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("action/target array must be strings")
			}
			set[s] = true
		}
		return set, nil
	default:
		return nil, fmt.Errorf("action/target must be a string or array")
	}
}

func isSubResource(child, parent string) bool {
	c := strings.TrimRight(child, "/")
	p := strings.TrimRight(parent, "/")
	if c == p {
		return true
	}
	return len(c) > len(p) && strings.HasPrefix(c, p) && c[len(p)] == '/'
}

func parseDurationSeconds(s string) (int64, error) {
	if len(s) == 0 || s[0] != 'P' {
		return 0, fmt.Errorf("invalid duration: %s", s)
	}
	var total int64
	num := ""
	inTime := false
	sawField := false
	for _, ch := range s[1:] {
		switch {
		case ch == 'T':
			inTime = true
		case ch >= '0' && ch <= '9':
			num += string(ch)
		case ch == 'D' || ch == 'H' || ch == 'M' || ch == 'S':
			if num == "" {
				return 0, fmt.Errorf("invalid duration: %s", s)
			}
			n, err := strconv.ParseInt(num, 10, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid duration: %s", s)
			}
			switch ch {
			case 'D':
				total += n * 86400
			case 'H':
				total += n * 3600
			case 'M':
				if inTime {
					total += n * 60
				} else {
					total += n * 2592000
				}
			case 'S':
				total += n
			}
			num = ""
			sawField = true
		default:
			return 0, fmt.Errorf("invalid duration: %s", s)
		}
	}
	if !sawField || num != "" {
		return 0, fmt.Errorf("invalid duration: %s", s)
	}
	return total, nil
}

func asFloat(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

func rateEventsPerSec(rate interface{}) (float64, error) {
	obj, ok := rate.(map[string]interface{})
	if !ok {
		return 0, fmt.Errorf("rate must be an object")
	}
	limit, ok := asFloat(obj["limit"])
	if !ok || limit < 0 {
		return 0, fmt.Errorf("rate.limit must be a non-negative number")
	}
	window, ok := obj["window"].(string)
	if !ok {
		return 0, fmt.Errorf("rate.window must be an ISO-8601 duration")
	}
	secs, err := parseDurationSeconds(window)
	if err != nil || secs <= 0 {
		return 0, fmt.Errorf("rate.window must be positive")
	}
	return limit / float64(secs), nil
}

func policyNotWeaker(parent, child interface{}) bool {
	pobj, ok1 := parent.(map[string]interface{})
	cobj, ok2 := child.(map[string]interface{})
	if !ok1 || !ok2 {
		return false
	}
	for k, pv := range pobj {
		cv, present := cobj[k]
		if !present {
			return false
		}
		pn, pIsNum := asFloat(pv)
		cn, cIsNum := asFloat(cv)
		if pIsNum && cIsNum {
			if cn < pn {
				return false
			}
		} else if pIsNum != cIsNum {
			return false
		} else if !reflect.DeepEqual(pv, cv) {
			return false
		}
	}
	return true
}

func window(link map[string]interface{}) (*int64, *int64, error) {
	var vf, vu *int64
	if s, ok := link["validFrom"].(string); ok {
		e, err := isoToEpoch(s)
		if err != nil {
			return nil, nil, err
		}
		vf = &e
	}
	if s, ok := link["validUntil"].(string); ok {
		e, err := isoToEpoch(s)
		if err != nil {
			return nil, nil, err
		}
		vu = &e
	}
	return vf, vu, nil
}

func intentOf(link map[string]interface{}) map[string]interface{} {
	if m, ok := link["intent"].(map[string]interface{}); ok {
		return m
	}
	return map[string]interface{}{}
}

// nonExpansion returns the offending dimension if child broadens parent, else "".
func nonExpansion(parent, child map[string]interface{}) string {
	pIntent := intentOf(parent)
	cIntent := intentOf(child)

	for _, dim := range []string{"action", "target"} {
		if cRaw, present := cIntent[dim]; present {
			cSet, err := stringSet(cRaw)
			if err != nil {
				return dim
			}
			pSet, _ := stringSet(pIntent[dim])
			if cSet != nil && pSet != nil {
				for k := range cSet {
					if !pSet[k] {
						return dim
					}
				}
			}
		}
	}

	if cRes, present := cIntent["resource"]; present {
		cs, ok := cRes.(string)
		if !ok {
			return "resource"
		}
		if ps, ok := pIntent["resource"].(string); ok && !isSubResource(cs, ps) {
			return "resource"
		}
	}

	cf, cu, err := window(child)
	if err != nil {
		return "time"
	}
	pf, pu, err := window(parent)
	if err != nil {
		return "time"
	}
	if cf != nil && pf != nil && *cf < *pf {
		return "time"
	}
	if cu != nil && pu != nil && *cu > *pu {
		return "time"
	}

	if cRate, present := child["rate"]; present && cRate != nil {
		ce, err := rateEventsPerSec(cRate)
		if err != nil {
			return "rate"
		}
		if pRate, present := parent["rate"]; present && pRate != nil {
			pe, err := rateEventsPerSec(pRate)
			if err != nil {
				return "rate"
			}
			if ce > pe+rateEpsilon {
				return "rate"
			}
		}
	}

	if cPol, present := child["policy"]; present && cPol != nil {
		if pPol, present := parent["policy"]; present && pPol != nil {
			if !policyNotWeaker(pPol, cPol) {
				return "policy"
			}
		}
	}

	return ""
}

// ValidateChain validates a delegation chain (root -> leaf) under v1.7 rules.
func ValidateChain(chain []interface{}, trustedRoots []string, revoked []int, budget map[string]interface{}, nowIso string, skew int64) Verdict {
	if len(chain) == 0 {
		return Verdict{"valid": false, "code": "malformed_delegation", "detail": "empty delegation chain"}
	}
	if md, ok := asFloat(budget["maxDepth"]); ok && len(chain) > int(md) {
		return Verdict{"valid": false, "code": "verifier_budget_exceeded", "limit": "depth"}
	}

	links := make([]map[string]interface{}, len(chain))
	for i, raw := range chain {
		m, ok := raw.(map[string]interface{})
		if !ok {
			return Verdict{"valid": false, "code": "malformed_delegation", "detail": fmt.Sprintf("link %d not object", i)}
		}
		_, iOk := m["issuer"].(string)
		_, sOk := m["subject"].(string)
		if !iOk || !sOk {
			return Verdict{"valid": false, "code": "malformed_delegation", "detail": fmt.Sprintf("link %d missing issuer/subject", i)}
		}
		links[i] = m
	}

	if len(trustedRoots) > 0 {
		rootIssuer := links[0]["issuer"].(string)
		found := false
		for _, r := range trustedRoots {
			if r == rootIssuer {
				found = true
				break
			}
		}
		if !found {
			return Verdict{"valid": false, "code": "untrusted_principal"}
		}
	}

	minRevoked := -1
	for _, idx := range revoked {
		if idx >= 0 && idx < len(links) && (minRevoked == -1 || idx < minRevoked) {
			minRevoked = idx
		}
	}
	if minRevoked != -1 {
		return Verdict{"valid": false, "code": "delegation_revoked", "linkIndex": minRevoked}
	}

	for i := 1; i < len(links); i++ {
		parent, child := links[i-1], links[i]
		if parent["subject"] != child["issuer"] {
			return Verdict{"valid": false, "code": "subject_issuer_mismatch", "linkIndex": i}
		}
		if dim := nonExpansion(parent, child); dim != "" {
			return Verdict{"valid": false, "code": "scope_exceeds_parent", "dimension": dim}
		}
	}

	var effStart, effEnd *int64
	var cumulativeTTL int64
	for _, link := range links {
		vf, vu, err := window(link)
		if err != nil {
			return Verdict{"valid": false, "code": "malformed_delegation", "detail": err.Error()}
		}
		if vf != nil {
			if effStart == nil || *vf > *effStart {
				effStart = vf
			}
		}
		if vu != nil {
			if effEnd == nil || *vu < *effEnd {
				effEnd = vu
			}
		}
		if vf != nil && vu != nil && *vu >= *vf {
			cumulativeTTL += *vu - *vf
		}
	}
	now, err := isoToEpoch(nowIso)
	if err != nil {
		return Verdict{"valid": false, "code": "malformed_delegation", "detail": err.Error()}
	}
	if effStart != nil && now < *effStart-skew {
		return Verdict{"valid": false, "code": "outside_validity_window"}
	}
	if effEnd != nil && now > *effEnd+skew {
		return Verdict{"valid": false, "code": "outside_validity_window"}
	}
	if mt, ok := asFloat(budget["maxCumulativeTtlSeconds"]); ok && cumulativeTTL > int64(mt) {
		return Verdict{"valid": false, "code": "verifier_budget_exceeded", "limit": "cumulative_ttl"}
	}

	return Verdict{"valid": true}
}

// ValidateChainJSON is the JSON boundary matching the core. Infallible.
func ValidateChainJSON(requestJSON string) string {
	var req map[string]interface{}
	if err := json.Unmarshal([]byte(requestJSON), &req); err != nil {
		return marshalVerdict(Verdict{"valid": false, "code": "malformed_delegation", "detail": "request json: " + err.Error()})
	}
	chain, ok := req["chain"].([]interface{})
	if !ok {
		return marshalVerdict(Verdict{"valid": false, "code": "malformed_delegation", "detail": "missing chain array"})
	}
	var trusted []string
	if arr, ok := req["trustedRoots"].([]interface{}); ok {
		for _, x := range arr {
			if s, ok := x.(string); ok {
				trusted = append(trusted, s)
			}
		}
	}
	var revoked []int
	if arr, ok := req["revokedIndices"].([]interface{}); ok {
		for _, x := range arr {
			if n, ok := asFloat(x); ok {
				revoked = append(revoked, int(n))
			}
		}
	}
	budget, _ := req["budget"].(map[string]interface{})
	now, _ := req["nowIso"].(string)
	skew := int64(30)
	if s, ok := asFloat(req["clockSkewSeconds"]); ok {
		skew = int64(s)
	}
	return marshalVerdict(ValidateChain(chain, trusted, revoked, budget, now, skew))
}

func marshalVerdict(v Verdict) string {
	b, _ := json.Marshal(v)
	return string(b)
}
