// JSON Canonicalization Scheme (JCS) per RFC 8785.
//
// Mirrors vouch/jcs.py and typescript/src/jcs.ts. Cross-implementation
// interop is REQUIRED: Python, TypeScript, and Go MUST produce byte-identical
// output for the same input. Verified against test-vectors/jcs/vectors.json.
//
// Conformance: RFC 8785 §3.2 (object members sorted by code-point order),
// §3.2.2 (number formatting via ECMAScript ToString), §3.2.4 (string
// escaping per JSON.stringify rules).

package signer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Canonicalize returns the RFC 8785 canonical form of the given Go value
// as a UTF-8 byte sequence. Maps with string keys are sorted by code-point
// order, integers render without exponents, strings are escaped per JSON.
func Canonicalize(value any) ([]byte, error) {
	var buf bytes.Buffer
	if err := canonWrite(&buf, value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CanonicalizeString returns the canonical form as a string. Useful for
// debugging and cross-language test vector comparison.
func CanonicalizeString(value any) (string, error) {
	b, err := Canonicalize(value)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// CanonicalizeJSON canonicalizes a JSON document supplied as raw bytes.
// Numbers retain integer form when expressible as int64; non-integers use
// strconv.FormatFloat with -1 precision (matches ECMA ToString for
// non-extreme magnitudes). For full RFC 8785 ECMA ToString fidelity on
// extreme floats, callers should prefer Canonicalize over typed Go values.
func CanonicalizeJSON(input []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return Canonicalize(v)
}

func canonWrite(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
		return nil
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil
	case string:
		return writeJSONString(buf, x)
	case json.Number:
		return writeJSONNumber(buf, string(x))
	case int:
		buf.WriteString(strconv.FormatInt(int64(x), 10))
		return nil
	case int8:
		buf.WriteString(strconv.FormatInt(int64(x), 10))
		return nil
	case int16:
		buf.WriteString(strconv.FormatInt(int64(x), 10))
		return nil
	case int32:
		buf.WriteString(strconv.FormatInt(int64(x), 10))
		return nil
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
		return nil
	case uint:
		buf.WriteString(strconv.FormatUint(uint64(x), 10))
		return nil
	case uint8:
		buf.WriteString(strconv.FormatUint(uint64(x), 10))
		return nil
	case uint16:
		buf.WriteString(strconv.FormatUint(uint64(x), 10))
		return nil
	case uint32:
		buf.WriteString(strconv.FormatUint(uint64(x), 10))
		return nil
	case uint64:
		buf.WriteString(strconv.FormatUint(x, 10))
		return nil
	case float32:
		return writeFloat(buf, float64(x))
	case float64:
		return writeFloat(buf, x)
	case []any:
		return writeArray(buf, x)
	case map[string]any:
		return writeObject(buf, x)
	}

	// Fallback: try to coerce via JSON round-trip. This handles structs,
	// custom types, and json.Marshaler implementations.
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("jcs: cannot serialize value of type %T", v)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var any2 any
	if err := dec.Decode(&any2); err != nil {
		return fmt.Errorf("jcs: round-trip failed for type %T: %w", v, err)
	}
	return canonWrite(buf, any2)
}

func writeArray(buf *bytes.Buffer, arr []any) error {
	buf.WriteByte('[')
	for i, item := range arr {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := canonWrite(buf, item); err != nil {
			return err
		}
	}
	buf.WriteByte(']')
	return nil
}

func writeObject(buf *bytes.Buffer, obj map[string]any) error {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	// RFC 8785 §3.2: sort by Unicode code-point order. For UTF-8 strings,
	// byte-wise comparison of UTF-8 happens to coincide with code-point
	// order, so sort.Strings is correct.
	sort.Strings(keys)

	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := writeJSONString(buf, k); err != nil {
			return err
		}
		buf.WriteByte(':')
		if err := canonWrite(buf, obj[k]); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

// writeJSONNumber preserves the integer form when possible.
func writeJSONNumber(buf *bytes.Buffer, s string) error {
	// Integer first
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		buf.WriteString(strconv.FormatInt(i, 10))
		return nil
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return writeFloat(buf, f)
	}
	return fmt.Errorf("jcs: cannot parse number %q", s)
}

// writeFloat serializes a float per RFC 8785 3.2.2.5 (ECMAScript ToString).
// Negative zero is normalized to 0.
func writeFloat(buf *bytes.Buffer, f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return errors.New("jcs: cannot serialize NaN or Infinity")
	}
	if f == 0 {
		buf.WriteByte('0') // normalizes -0 to 0
		return nil
	}
	buf.WriteString(esNumberToString(f))
	return nil
}

// esNumberToString implements ECMAScript Number.prototype.toString exactly:
// positional form for a decimal-point position in (-6, 21], exponential
// "Ne+M" / "Ne-M" otherwise, with no leading zeros in the exponent. This matches
// JavaScript and the Rust (ryu-js) and Python SDKs byte-for-byte, including
// integer-valued floats beyond int64 range (which the previous int64 cast
// silently corrupted).
func esNumberToString(f float64) string {
	sign := ""
	if f < 0 {
		sign = "-"
		f = -f
	}
	// Shortest round-trip mantissa and base-10 exponent, e.g. "1.2345678e+04".
	s := strconv.FormatFloat(f, 'e', -1, 64)
	mant := s
	exp := 0
	if i := strings.IndexByte(s, 'e'); i >= 0 {
		mant = s[:i]
		exp, _ = strconv.Atoi(s[i+1:])
	}
	digits := strings.Replace(mant, ".", "", 1)
	k := len(digits)
	n := exp + 1 // position of the decimal point within `digits`
	switch {
	case k <= n && n <= 21:
		return sign + digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		return sign + digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		return sign + "0." + strings.Repeat("0", -n) + digits
	default:
		e := n - 1
		eSign := "+"
		if e < 0 {
			eSign = "-"
			e = -e
		}
		if k == 1 {
			return sign + digits + "e" + eSign + strconv.Itoa(e)
		}
		return sign + digits[:1] + "." + digits[1:] + "e" + eSign + strconv.Itoa(e)
	}
}

// writeJSONString writes an RFC 8259 / JCS-conformant JSON string literal.
// We rely on encoding/json for string escaping but disable HTML escaping
// (RFC 8785 does not require <, >, & to be escaped).
func writeJSONString(buf *bytes.Buffer, s string) error {
	tmp := bytes.NewBuffer(nil)
	enc := json.NewEncoder(tmp)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return err
	}
	out := strings.TrimRight(tmp.String(), "\n")
	buf.WriteString(out)
	return nil
}
