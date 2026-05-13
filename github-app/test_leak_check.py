"""Tests for the Gatekeeper leak-check extension (M.2)."""

from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

# Make the github-app directory importable when running from repo root.
HERE = Path(__file__).parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from leak_check import run_leak_check, LeakCheckResult  # noqa: E402
from vouch.scan import Severity  # noqa: E402


class FakeGitHubClient:
    """Minimal fake matching the surface leak_check needs.

    The fake serves a tiny PR with three files: one safe, one with an
    Ed25519 private JWK, one .env with a seed. The blob endpoint returns
    base64-encoded content keyed on a synthetic blob SHA.
    """

    def __init__(self, files: list[dict], blobs: dict[str, str]) -> None:
        self.files = files
        self.blobs = blobs
        self.calls: list[tuple[str, str]] = []

    async def _request(self, method: str, endpoint: str, **kwargs):
        self.calls.append((method, endpoint))
        if "/pulls/" in endpoint and endpoint.endswith("/files") or "/pulls/" in endpoint and "files?" in endpoint:
            return self.files
        if "/git/blobs/" in endpoint:
            sha = endpoint.rsplit("/", 1)[-1]
            content = self.blobs.get(sha, "")
            return {
                "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
                "encoding": "base64",
            }
        return None


@pytest.mark.asyncio
async def test_leak_check_finds_jwk_and_seed():
    files = [
        {"filename": "config.json", "status": "modified", "sha": "blob-jwk"},
        {"filename": ".env",        "status": "added",    "sha": "blob-env"},
        {"filename": "README.md",   "status": "modified", "sha": "blob-readme"},
    ]
    blobs = {
        "blob-jwk":    '{"kty":"OKP","crv":"Ed25519","d":"' + "A" * 43 + '"}',
        "blob-env":    "VOUCH_ED25519_SEED=" + "0" * 64,
        "blob-readme": "# Project\nNothing sensitive here.\n",
    }
    gh = FakeGitHubClient(files=files, blobs=blobs)

    result = await run_leak_check(gh, "acme", "service", 42)
    assert isinstance(result, LeakCheckResult)
    assert result.files_scanned == 3
    # Two CRITICAL findings expected.
    crits = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(crits) == 2
    files_with_findings = {f.file for f in result.findings}
    assert "config.json" in files_with_findings
    assert ".env" in files_with_findings
    # README should be clean.
    assert "README.md" not in files_with_findings


@pytest.mark.asyncio
async def test_leak_check_clean_pr():
    files = [
        {"filename": "src/main.py", "status": "modified", "sha": "blob-py"},
        {"filename": "README.md",   "status": "added",    "sha": "blob-readme"},
    ]
    blobs = {
        "blob-py":     "def main():\n    print('hello')\n",
        "blob-readme": "# Project\n",
    }
    gh = FakeGitHubClient(files=files, blobs=blobs)

    result = await run_leak_check(gh, "acme", "service", 1)
    assert result.findings == []
    assert result.conclusion == "success"
    assert "No Vouch-shaped private key material detected" in result.summary


@pytest.mark.asyncio
async def test_leak_check_skips_removed_files():
    files = [
        # A removed file that previously had a leak: should NOT be flagged
        # again, because deletion of a leak is good.
        {"filename": "old.env", "status": "removed", "sha": "blob-removed"},
        {"filename": "ok.md",   "status": "modified", "sha": "blob-ok"},
    ]
    blobs = {
        "blob-removed": "VOUCH_ED25519_SEED=" + "f" * 64,
        "blob-ok":      "# safe\n",
    }
    gh = FakeGitHubClient(files=files, blobs=blobs)

    result = await run_leak_check(gh, "acme", "service", 7)
    assert result.findings == []
    # files_scanned counts files actually fetched and scanned (not removed).
    assert result.files_scanned == 1


@pytest.mark.asyncio
async def test_leak_check_filename_pattern_flagged():
    files = [
        {"filename": "vouch.json", "status": "added", "sha": "blob-vouch"},
    ]
    blobs = {
        # Empty but well-formed JSON. The filename pattern fires regardless.
        "blob-vouch": "{}",
    }
    gh = FakeGitHubClient(files=files, blobs=blobs)

    result = await run_leak_check(gh, "acme", "service", 11)
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.MEDIUM
    assert result.conclusion == "neutral"


@pytest.mark.asyncio
async def test_leak_check_result_serialization_metadata():
    files = [
        {"filename": "leaky.json", "status": "added", "sha": "blob-leaky"},
    ]
    blobs = {
        "blob-leaky": '{"kty":"OKP","crv":"Ed25519","d":"' + "B" * 43 + '"}',
    }
    gh = FakeGitHubClient(files=files, blobs=blobs)

    result = await run_leak_check(gh, "acme", "service", 13)
    assert result.critical_count == 1
    assert result.conclusion == "failure"
    assert "1 critical finding" in result.title
    details = result.details_markdown()
    # The markdown is structured for the GitHub check-run UI.
    assert "CRITICAL (1)" in details
    assert "vouch_ed25519_private_jwk" in details
    # The match snippet contains a hash, not the raw key (defense in depth).
    assert "sha256:" in details
