"""
Self-check for the runtime-module test vectors (issue #152).

Regenerates each ``test-vectors/<module>/vector.json`` in memory under the same
``pinned()`` context the generator uses, and asserts the result matches the
committed file byte-for-byte. This guards the cross-language contract the runtime
ports (#94 through #105) build against: if a module's behaviour changes, the
committed vector goes stale and this test fails until it is regenerated with
``python scripts/gen_runtime_vectors.py``.
"""

import importlib.util
from pathlib import Path

import pytest

_GEN_PATH = Path(__file__).resolve().parent.parent / "scripts" / "gen_runtime_vectors.py"


def _load_generator():
    # scripts/ is not an importable package, so load the harness by file path.
    spec = importlib.util.spec_from_file_location("gen_runtime_vectors", _GEN_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gen = _load_generator()

EXPECTED_MODULES = {
    "trust_entropy",
    "quorum",
    "merkle",
    "canary",
    "behavioral_attestation",
    "heartbeat",
}


def test_builders_cover_exactly_the_six_runtime_modules():
    assert set(gen.BUILDERS) == EXPECTED_MODULES


@pytest.mark.parametrize("name", sorted(gen.BUILDERS))
def test_committed_vector_matches_fresh_generation(name):
    with gen.pinned():
        expected_text = gen.serialize(gen.BUILDERS[name]())

    vector_path = gen.VECTOR_ROOT / name / "vector.json"
    assert vector_path.exists(), f"missing committed vector: {vector_path}"
    actual_text = vector_path.read_text(encoding="utf-8")

    assert expected_text == actual_text, (
        f"test-vectors/{name}/vector.json is out of date. "
        f"Regenerate with `python scripts/gen_runtime_vectors.py`."
    )
