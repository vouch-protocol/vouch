"""
Tests for the Verified Contributor minting script.

Two kinds of contribution can be attested. The important property is
truthfulness: a `design` credential records what the person contributed and
which pull request implemented it, and never claims they authored the commits.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

from vouch import Verifier, generate_identity

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "mint_contributor_credential.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("mint_contributor_credential", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


mint = _load_module()

PR_URL = "https://github.com/vouch-protocol/vouch/pull/123"
REPO = "vouch-protocol/vouch"


@pytest.fixture
def issuer():
    return generate_identity(domain="vouch-protocol.com")


def _mint(issuer, **kwargs):
    params = {
        "subject": "someone",
        "pr_url": PR_URL,
        "pr_number": "123",
        "repo": REPO,
        "private_key": issuer.private_key_jwk,
        "did": issuer.did,
    }
    params.update(kwargs)
    return mint.mint_credential(**params)


def test_code_contribution_records_authorship(issuer):
    cred = _mint(issuer)
    intent = cred["credentialSubject"]["intent"]
    assert intent["role"] == "verified-contributor"
    assert intent["contributionType"] == "code"
    assert intent["pullRequest"] == 123
    assert intent["target"] == "github:someone"
    ok, _ = Verifier.verify(cred, public_key=issuer.public_key_jwk)
    assert ok is True


def test_design_contribution_does_not_claim_authorship(issuer):
    cred = _mint(
        issuer,
        contribution_type="design",
        contribution="Proposed the state-change framing and the treasury scenario",
    )
    intent = cred["credentialSubject"]["intent"]
    assert intent["role"] == "design-contributor"
    assert intent["contributionType"] == "design"
    # The credential must NOT assert the subject authored the pull request.
    assert "pullRequest" not in intent
    assert intent["implementedIn"] == 123
    assert "treasury scenario" in intent["contribution"]
    ok, _ = Verifier.verify(cred, public_key=issuer.public_key_jwk)
    assert ok is True


def test_design_contribution_requires_a_description(issuer):
    with pytest.raises(ValueError):
        _mint(issuer, contribution_type="design")


def test_unknown_contribution_type_is_rejected(issuer):
    with pytest.raises(ValueError):
        _mint(issuer, contribution_type="marketing")


def test_default_stays_backward_compatible(issuer):
    # An existing caller that passes no contribution type still mints the
    # merged-pull-request-author credential it always did.
    cred = _mint(issuer)
    assert cred["credentialSubject"]["intent"]["role"] == "verified-contributor"
    assert cred["credentialSubject"]["intent"]["pullRequest"] == 123
