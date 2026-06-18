"""
Tests for the JCS (RFC 8785) canonicalizer.

Includes a representative subset of RFC 8785 §3.2 test vectors. Cross-implementation
byte-for-byte parity (Python / TypeScript / Go) is checked in a separate
interop test suite.
"""

import pytest

from vouch import jcs


def test_null():
    assert jcs.canonicalize(None) == b"null"


def test_booleans():
    assert jcs.canonicalize(True) == b"true"
    assert jcs.canonicalize(False) == b"false"


def test_simple_integer():
    assert jcs.canonicalize(0) == b"0"
    assert jcs.canonicalize(1) == b"1"
    assert jcs.canonicalize(-1) == b"-1"
    assert jcs.canonicalize(123) == b"123"


def test_string_simple():
    assert jcs.canonicalize("hello") == b'"hello"'


def test_string_escapes():
    # RFC 8785 only requires the seven core escapes; lower control chars use \uXXXX.
    assert jcs.canonicalize('"') == b'"\\""'
    assert jcs.canonicalize("\\") == b'"\\\\"'
    assert jcs.canonicalize("\n") == b'"\\n"'
    assert jcs.canonicalize("\t") == b'"\\t"'
    assert jcs.canonicalize("\x01") == b'"\\u0001"'


def test_array_preserves_order():
    assert jcs.canonicalize([1, 2, 3]) == b"[1,2,3]"
    assert jcs.canonicalize(["b", "a"]) == b'["b","a"]'


def test_object_keys_sorted_lexicographic():
    obj = {"b": 1, "a": 2, "c": 3}
    assert jcs.canonicalize(obj) == b'{"a":2,"b":1,"c":3}'


def test_object_keys_unicode_sort():
    # UTF-16 code units: ASCII < Latin-1 supplement, so 'a' < 'z' < 'e_acute'.
    obj = {"é": 1, "z": 2, "a": 3}
    canonical = jcs.canonicalize(obj).decode("utf-8")
    assert canonical.startswith('{"a":3,"z":2,')


def test_object_keys_rfc8785_unicode_sort_order():
    obj = {
        "\u20ac": "Euro Sign",
        "\r": "Carriage Return",
        "\ufb33": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\U0001f600": "Emoji: Grinning Face",
        "\u0080": "Control",
        "\u00f6": "Latin Small Letter O With Diaeresis",
    }

    expected = (
        '{"\\r":"Carriage Return","1":"One","\u0080":"Control",'
        '"\u00f6":"Latin Small Letter O With Diaeresis","\u20ac":"Euro Sign",'
        '"\U0001f600":"Emoji: Grinning Face","\ufb33":"Hebrew Letter Dalet With Dagesh"}'
    )

    assert jcs.canonicalize(obj) == expected.encode("utf-8")


def test_nested_object():
    obj = {"outer": {"y": 2, "x": 1}}
    assert jcs.canonicalize(obj) == b'{"outer":{"x":1,"y":2}}'


def test_nested_objects_sort_recursively_inside_arrays():
    obj = {
        "z": [{"b": 1, "a": {"d": 4, "c": 3}}],
        "a": {"y": [{"beta": 2, "alpha": 1}], "x": 0},
    }

    assert (
        jcs.canonicalize(obj)
        == b'{"a":{"x":0,"y":[{"alpha":1,"beta":2}]},"z":[{"a":{"c":3,"d":4},"b":1}]}'
    )


def test_no_whitespace():
    obj = {"a": [1, 2], "b": {"c": "d"}}
    out = jcs.canonicalize(obj).decode("utf-8")
    assert " " not in out
    assert "\n" not in out
    assert "\t" not in out


def test_mixed_object_keys_and_values():
    # Keys must sort: literals < numbers < string
    obj = {
        "numbers": [4.5, 2, 1],
        "string": "hello",
        "literals": [None, True, False],
    }
    out = jcs.canonicalize(obj).decode("utf-8")
    assert '"literals":[null,true,false]' in out
    assert '"string":"hello"' in out
    assert out.index('"literals"') < out.index('"numbers"') < out.index('"string"')


def test_rfc8785_number_formatting_edges():
    obj = {
        "numbers": [
            333333333.33333329,
            1e30,
            4.50,
            2e-3,
            0.000000000000000000000000001,
        ]
    }

    assert jcs.canonicalize(obj) == b'{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}'


def test_nan_and_inf_rejected():
    with pytest.raises(ValueError):
        jcs.canonicalize(float("nan"))
    with pytest.raises(ValueError):
        jcs.canonicalize(float("inf"))


def test_non_string_keys_rejected():
    with pytest.raises(TypeError):
        jcs.canonicalize({1: "a"})


def test_round_trip_in_data_integrity_form():
    # Practical test: a credential payload should produce stable output regardless
    # of dict insertion order in the source.
    cred1 = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "VouchCredential"],
        "issuer": "did:web:example.com",
    }
    cred2 = {
        "issuer": "did:web:example.com",
        "type": ["VerifiableCredential", "VouchCredential"],
        "@context": ["https://www.w3.org/ns/credentials/v2"],
    }
    assert jcs.canonicalize(cred1) == jcs.canonicalize(cred2)
