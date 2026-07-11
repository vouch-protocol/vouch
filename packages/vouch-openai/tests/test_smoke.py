"""Smoke tests for vouch-openai.

Hermetic: each test generates a throwaway identity and passes the Signer
explicitly, so no environment variables or network are needed.
"""

import json

import pytest

from vouch import Signer
from vouch.keys import generate_identity
from vouch_openai import protect, sign_tool_call, signed_tool, verify_tool_call


def _identity():
    keys = generate_identity(domain="agent.example.com")
    return keys, Signer(private_key=keys.private_key_jwk, did=keys.did)


def test_sign_and_verify_dict_tool_call():
    keys, signer = _identity()
    call = {"function": {"name": "get_weather", "arguments": json.dumps({"city": "Paris"})}}
    credential = sign_tool_call(call, signer=signer, publish=False)

    assert credential is not None
    assert credential["credentialSubject"]["intent"]["action"] == "get_weather"

    ok, passport = verify_tool_call(credential, public_key=keys.public_key_jwk)
    assert ok
    assert passport.action == "get_weather"


def test_sign_object_tool_call():
    class _Fn:
        def __init__(self, name, arguments):
            self.name = name
            self.arguments = arguments

    class _Call:
        def __init__(self, fn):
            self.function = fn

    keys, signer = _identity()
    call = _Call(_Fn("send_email", json.dumps({"to": "a@example.com"})))
    credential = sign_tool_call(call, signer=signer, publish=False)

    assert credential["credentialSubject"]["intent"]["action"] == "send_email"
    ok, _ = verify_tool_call(credential, public_key=keys.public_key_jwk)
    assert ok


def test_signed_tool_decorator_runs_and_marks():
    _, signer = _identity()

    @signed_tool(signer=signer)
    def add(a, b):
        return a + b

    assert getattr(add, "__vouch_signed__", False) is True
    assert add(2, 3) == 5


def test_protect_wraps_callables():
    _, signer = _identity()

    def fetch():
        return "ok"

    wrapped = protect([fetch], signer=signer)
    assert getattr(wrapped[0], "__vouch_signed__", False) is True
    assert wrapped[0]() == "ok"


def test_missing_function_name_raises():
    _, signer = _identity()
    with pytest.raises(ValueError):
        sign_tool_call({"function": {"arguments": "{}"}}, signer=signer, publish=False)
