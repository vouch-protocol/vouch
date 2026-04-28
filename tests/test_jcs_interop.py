"""
Cross-implementation interop tests for JCS canonicalization.

Reads the shared test vectors at test-vectors/jcs/vectors.json and asserts
that the Python implementation produces byte-identical output for each one.
The TypeScript suite has a parallel test (typescript/tests/jcs-interop.test.ts)
that reads the same vectors. Together they verify Python and TypeScript
produce identical canonical bytes, which is required for cross-language
signature verification.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vouch import jcs


VECTOR_PATH = (
    Path(__file__).resolve().parent.parent
    / "test-vectors"
    / "jcs"
    / "vectors.json"
)


def _load_vectors():
    with open(VECTOR_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data["vectors"]


@pytest.mark.parametrize("vec", _load_vectors(), ids=lambda v: v["name"])
def test_jcs_interop_vector(vec):
    """Each vector's input MUST canonicalize to the documented output."""
    canonical_bytes = jcs.canonicalize(vec["input"])
    canonical_text = canonical_bytes.decode("utf-8")
    assert canonical_text == vec["canonical"], (
        f"\n  Input:    {json.dumps(vec['input'])}\n"
        f"  Expected: {vec['canonical']}\n"
        f"  Got:      {canonical_text}"
    )
