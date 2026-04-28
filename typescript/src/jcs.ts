/**
 * JSON Canonicalization Scheme (JCS) per RFC 8785.
 *
 * Produces a deterministic, byte-stable serialization of JSON data so that
 * cryptographic signatures over the canonical form remain valid regardless
 * of how the JSON is parsed and re-serialized between issuers and verifiers.
 *
 * Mirrors `vouch/jcs.py`. Cross-implementation interop is REQUIRED: Python
 * and TypeScript MUST produce byte-identical output for the same input.
 *
 * Conformance: RFC 8785 §3.2 (object members sorted by code-point order),
 * §3.2.2 (number formatting via ECMAScript's ToString), §3.2.4 (string
 * escaping per JSON.stringify rules).
 */

/**
 * Canonicalize a JSON-serializable value to a UTF-8 byte sequence per
 * RFC 8785. The output is the canonical form suitable for hashing and
 * signing.
 */
export function canonicalize(value: unknown): Uint8Array {
    const text = canonicalizeToString(value);
    return new TextEncoder().encode(text);
}

/**
 * Canonicalize to a string. Useful for debugging and for cross-language
 * test vector comparison.
 */
export function canonicalizeToString(value: unknown): string {
    return serialize(value);
}

function serialize(value: unknown): string {
    if (value === null) return 'null';
    if (value === undefined) {
        throw new TypeError('JCS cannot serialize undefined');
    }

    const t = typeof value;

    if (t === 'boolean') return value ? 'true' : 'false';

    if (t === 'number') {
        if (!Number.isFinite(value as number)) {
            throw new RangeError('JCS cannot serialize NaN or Infinity');
        }
        return formatNumber(value as number);
    }

    if (t === 'string') return JSON.stringify(value);

    if (Array.isArray(value)) {
        const items = value.map((v) => serialize(v));
        return '[' + items.join(',') + ']';
    }

    if (t === 'object') {
        const obj = value as Record<string, unknown>;
        // Sort keys by UTF-16 code-unit order, which matches Unicode code-point
        // order for keys in the BMP. RFC 8785 §3.2 requires code-point order.
        const keys = Object.keys(obj).sort();
        const parts: string[] = [];
        for (const k of keys) {
            const v = obj[k];
            if (v === undefined) continue; // RFC 8785: omit undefined members
            parts.push(JSON.stringify(k) + ':' + serialize(v));
        }
        return '{' + parts.join(',') + '}';
    }

    throw new TypeError(`JCS cannot serialize value of type ${t}`);
}

/**
 * Number formatting per RFC 8785 §3.2.2.5 (ECMAScript ToString for numbers).
 *
 * For integers within the safe range, render as a plain integer string.
 * For non-integers, defer to ECMAScript's String(number) which already
 * matches the algorithm RFC 8785 specifies.
 */
function formatNumber(n: number): string {
    if (Object.is(n, -0)) return '0'; // RFC 8785 normalizes -0 to 0
    if (Number.isInteger(n) && Math.abs(n) < 1e21) {
        return n.toFixed(0);
    }
    return String(n);
}
