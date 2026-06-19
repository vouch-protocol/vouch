"""Validation tests for the signer client (no network)."""

from __future__ import annotations

import pytest

from vouch_agent.signer import SignerError, validate_intent


def test_valid_intent_passes() -> None:
    validate_intent(
        {
            "action": "answer_question",
            "target": "session:abc",
            "resource": "https://vouch-protocol.org/help",
        }
    )


@pytest.mark.parametrize("missing", ["action", "target", "resource"])
def test_missing_field_raises(missing: str) -> None:
    intent = {
        "action": "answer_question",
        "target": "session:abc",
        "resource": "https://vouch-protocol.org/help",
    }
    intent.pop(missing)
    with pytest.raises(SignerError):
        validate_intent(intent)


def test_disallowed_action_raises() -> None:
    with pytest.raises(SignerError):
        validate_intent(
            {
                "action": "exfiltrate_keys",
                "target": "session:abc",
                "resource": "https://vouch-protocol.org/help",
            }
        )
