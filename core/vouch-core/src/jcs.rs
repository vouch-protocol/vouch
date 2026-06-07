//! JSON Canonicalization Scheme (JCS) per RFC 8785.
//!
//! Byte-exact port of the TypeScript SDK `canonicalize()`
//! (packages/sdk-ts/src/jcs.ts) and `vouch/jcs.py`. Rules:
//!   - object members are sorted by UTF-16 code-unit order (matching ECMAScript
//!     Array.prototype.sort, which the reference SDK uses; for BMP code points
//!     this equals the code-point order RFC 8785 3.2 requires),
//!   - strings are escaped per JSON.stringify,
//!   - numbers use ECMAScript ToString, and -0 normalizes to 0.
//!
//! Cross-implementation interop is REQUIRED: this MUST produce byte-identical
//! output to the TypeScript and Python implementations for the same input.

use serde_json::Value;
use std::cmp::Ordering;

/// Canonicalize a JSON value to its RFC 8785 UTF-8 byte sequence (for hashing
/// and signing).
pub fn canonicalize(value: &Value) -> Vec<u8> {
    canonicalize_to_string(value).into_bytes()
}

/// Canonicalize to a string (useful for debugging and vector comparison).
pub fn canonicalize_to_string(value: &Value) -> String {
    let mut out = String::new();
    serialize(value, &mut out);
    out
}

fn serialize(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&format_number(n)),
        Value::String(s) => escape_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                serialize(v, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| utf16_cmp(a, b));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                escape_string(k, out);
                out.push(':');
                serialize(&map[*k], out);
            }
            out.push('}');
        }
    }
}

/// Compare two strings by their UTF-16 code-unit sequence (ECMAScript string
/// ordering, used by the reference SDK's `Object.keys(obj).sort()`).
fn utf16_cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// JSON string escaping matching ECMAScript JSON.stringify. serde_json escapes
/// identically for the relevant cases (quote, backslash, control chars as
/// \b \t \n \f \r or \u00xx; non-ASCII emitted raw as UTF-8), so it is reused
/// as a single source of truth.
fn escape_string(s: &str, out: &mut String) {
    let encoded = serde_json::to_string(s).expect("a string is always serializable");
    out.push_str(&encoded);
}

/// Number formatting per RFC 8785 3.2.2.5 (ECMAScript ToString), matching
/// jcs.ts `formatNumber`.
fn format_number(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    let f = n.as_f64().expect("a serde_json number is i64, u64, or f64");
    if f == 0.0 {
        // Normalizes both 0.0 and -0.0 to "0" (RFC 8785).
        return "0".to_string();
    }
    // ECMAScript Number.prototype.toString via ryu-js. This matches JavaScript
    // exactly, including the exponential thresholds and format ("1e+21",
    // "1e-7"), so the canonical form is byte-identical to the TypeScript SDK and
    // to a conformant Python implementation for any finite number.
    let mut buf = ryu_js::Buffer::new();
    buf.format(f).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_containers() {
        assert_eq!(canonicalize_to_string(&json!({})), "{}");
        assert_eq!(canonicalize_to_string(&json!([])), "[]");
    }

    #[test]
    fn sorts_object_keys() {
        assert_eq!(
            canonicalize_to_string(&json!({"b": 1, "a": 2, "c": 3})),
            "{\"a\":2,\"b\":1,\"c\":3}"
        );
    }

    #[test]
    fn array_preserves_order() {
        assert_eq!(canonicalize_to_string(&json!([3, 1, 2])), "[3,1,2]");
    }

    #[test]
    fn negative_zero_normalized() {
        assert_eq!(canonicalize_to_string(&json!({"n": -0})), "{\"n\":0}");
    }
}
