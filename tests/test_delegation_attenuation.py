"""The Python delegation validator MUST produce the same verdicts as the Rust
core on the shared interop vectors."""

import json
from pathlib import Path

import pytest

from vouch.attenuation import validate_chain_json

VECTORS = json.loads(
    (
        Path(__file__).resolve().parent.parent
        / "test-vectors"
        / "delegation-attenuation"
        / "vector.json"
    ).read_text()
)


@pytest.mark.parametrize("case", VECTORS["cases"], ids=[c["name"] for c in VECTORS["cases"]])
def test_python_matches_delegation_vector(case):
    verdict = json.loads(validate_chain_json(json.dumps(case["request"])))
    expect = case["expect"]
    assert verdict["valid"] == expect["valid"], f"{case['name']}: {verdict}"
    if not expect["valid"]:
        assert verdict["code"] == expect["code"], f"{case['name']}: {verdict}"
        for field in ("dimension", "limit", "linkIndex"):
            if field in expect:
                assert verdict.get(field) == expect[field], f"{case['name']}: {verdict}"
