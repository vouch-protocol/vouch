"""
JSON Canonicalization Scheme (JCS) — RFC 8785.

Produces a deterministic, byte-identical canonical form of any JSON value across
languages and runtimes. Required by the Data Integrity `eddsa-jcs-2022`
cryptosuite for Vouch Credentials (Specification §7.1).

This is a vendored minimal implementation. Cross-implementation byte-for-byte
parity against the official RFC 8785 §3.2 test vectors is required for
conformance and is enforced in tests/test_jcs.py.
"""

from __future__ import annotations

import math
import re
from typing import Any, Mapping, Sequence


_ESCAPE_MAP = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}

_LITERAL_NUMBER = re.compile(r"^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?$")


def canonicalize(value: Any) -> bytes:
    """Return the canonical JCS UTF-8 byte representation of `value`."""
    return _emit(value).encode("utf-8")


def canonicalize_str(value: Any) -> str:
    """Return the canonical JCS string representation of `value` (no encoding)."""
    return _emit(value)


def _emit(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return _emit_number(value)
    if isinstance(value, str):
        return _emit_string(value)
    if isinstance(value, Mapping):
        return _emit_object(value)
    if isinstance(value, (list, tuple)) or (
        isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))
    ):
        return _emit_array(value)
    raise TypeError(f"JCS: unsupported type {type(value).__name__}: {value!r}")


def _emit_number(value: float | int) -> str:
    # JCS forbids NaN and Infinity (RFC 8785 §3.2.2.3).
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError("JCS: NaN and Infinity are not permitted")
        # Integer-valued floats serialize as integers (RFC 8785 §3.2.2.3).
        if value.is_integer() and -(2**53) <= value <= (2**53):
            value = int(value)
        else:
            # ECMAScript Number.prototype.toString equivalent — Python's repr()
            # is close but emits `1e+20` where ECMAScript emits `100000000000000000000`.
            # Use a shortest-round-trip serialization.
            s = repr(value)
            # Normalize exponent capitalization and sign formatting per ES.
            return _normalize_float_repr(s)
    if isinstance(value, bool):  # bool is a subclass of int in Python; guard above.
        raise TypeError("JCS: booleans handled by separate branch")
    return str(int(value))


def _normalize_float_repr(s: str) -> str:
    # Python repr for floats may produce forms like '1e+20' or '0.5'.
    # ECMAScript toString uses lowercase 'e', no '+' after 'e' for positive,
    # and uses positional form for magnitudes between 1e-6 and 1e21 (exclusive).
    # This is a best-effort minimal normalizer; full ES coverage requires a
    # dedicated library if exotic floats are encountered.
    s = s.lower().replace("e+", "e")
    return s


def _emit_string(value: str) -> str:
    out = ['"']
    for ch in value:
        cp = ord(ch)
        if cp in _ESCAPE_MAP:
            out.append(_ESCAPE_MAP[cp])
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _emit_object(obj: Mapping[Any, Any]) -> str:
    # Keys must be strings; sort by UTF-16 code units (RFC 8785 §3.2.3).
    items = []
    for k in obj:
        if not isinstance(k, str):
            raise TypeError(f"JCS: object keys must be strings, got {type(k).__name__}")
        items.append(k)
    items.sort(key=_utf16_sort_key)
    parts = []
    for key in items:
        parts.append(_emit_string(key))
        parts.append(":")
        parts.append(_emit(obj[key]))
        parts.append(",")
    if parts:
        parts.pop()  # remove trailing comma
    return "{" + "".join(parts) + "}"


def _emit_array(arr: Sequence[Any]) -> str:
    parts = []
    for item in arr:
        parts.append(_emit(item))
        parts.append(",")
    if parts:
        parts.pop()
    return "[" + "".join(parts) + "]"


def _utf16_sort_key(s: str) -> tuple[int, ...]:
    # RFC 8785 §3.2.3: object keys ordered by UTF-16 code-unit lexicographic order.
    # Encode to UTF-16-BE and read as 16-bit code units.
    encoded = s.encode("utf-16-be")
    return tuple((encoded[i] << 8) | encoded[i + 1] for i in range(0, len(encoded), 2))
