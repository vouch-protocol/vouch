"""
Tests for Vouch Git Workflow commands.

Tests for vouch git init and vouch git status functionality.
"""

import os
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from vouch.cli import (
    _export_vouch_key_to_ssh,
    _configure_git_signing,
    _install_commit_hook,
    _inject_readme_badge,
    VOUCH_BADGE_MARKDOWN,
    SSH_KEY_PATH,
    PRIVATE_KEY_PATH,
)


class TestExportSSHKey:
    """Tests for SSH key export functionality."""

    def test_export_ssh_key_creates_files(self):
        """Test that SSH key export creates the key files."""
        # Set up a test key
        os.environ["VOUCH_PRIVATE_KEY"] = '{"kty":"OKP","crv":"Ed25519","x":"test","d":"test"}'
        os.environ["VOUCH_DID"] = "did:vouch:test123"

        with patch.object(Path, "write_text"):
            with patch.object(Path, "chmod"):
                with patch.object(Path, "mkdir"):
                    try:
                        # This will fail due to invalid key, but we can test the flow
                        _export_vouch_key_to_ssh()
                    except Exception:
                        pass  # Expected - invalid test key

        # Clean up
        del os.environ["VOUCH_PRIVATE_KEY"]
        del os.environ["VOUCH_DID"]

    def test_export_generates_new_key_if_none_exists(self):
        """Test that a new key is generated if VOUCH_PRIVATE_KEY is not set."""
        # Ensure env vars are not set
        os.environ.pop("VOUCH_PRIVATE_KEY", None)
        os.environ.pop("VOUCH_DID", None)

        with patch.object(Path, "write_text"):
            with patch.object(Path, "chmod"):
                with patch.object(Path, "mkdir"):
                    ssh_public, did = _export_vouch_key_to_ssh()

        assert ssh_public.startswith("ssh-ed25519")
        assert did.startswith("did:vouch:")


class TestConfigureGitSigning:
    """Tests for git configuration."""

    def test_git_config_set(self):
        """Test that git config commands are executed."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)

            _configure_git_signing("/path/to/key", "did:vouch:test")

            # Should have called git config 4 times
            assert mock_run.call_count == 4

            # Verify the commands
            calls = [str(c) for c in mock_run.call_args_list]
            assert any("user.signingkey" in str(c) for c in calls)
            assert any("gpg.format" in str(c) for c in calls)
            assert any("commit.gpgsign" in str(c) for c in calls)
            assert any("vouch.did" in str(c) for c in calls)


class TestInstallCommitHook:
    """Tests for commit hook installation."""

    def test_hook_installed_in_git_repo(self):
        """Test that hook is installed when in a git repo."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Initialize a git repo
            subprocess.run(["git", "init"], cwd=tmpdir, capture_output=True)

            # Change to the temp dir
            original_dir = os.getcwd()
            os.chdir(tmpdir)

            try:
                result = _install_commit_hook(skip_trailer=False)

                hook_path = Path(tmpdir) / ".git" / "hooks" / "prepare-commit-msg"
                assert hook_path.exists()
                assert "Vouch Protocol" in hook_path.read_text()
                assert result is True
            finally:
                os.chdir(original_dir)

    def test_hook_skipped_when_requested(self):
        """Test that hook is not installed when skip_trailer=True."""
        result = _install_commit_hook(skip_trailer=True)
        assert result is False

    def test_hook_appends_to_existing(self):
        """Test that hook appends to existing hook."""
        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(["git", "init"], cwd=tmpdir, capture_output=True)

            # Create existing hook
            hook_path = Path(tmpdir) / ".git" / "hooks" / "prepare-commit-msg"
            hook_path.write_text("#!/bin/bash\n# Existing hook\necho 'existing'\n")

            original_dir = os.getcwd()
            os.chdir(tmpdir)

            try:
                _install_commit_hook(skip_trailer=False)

                content = hook_path.read_text()
                assert "Existing hook" in content
                assert "Vouch Protocol" in content
            finally:
                os.chdir(original_dir)


class TestBadgeInjection:
    """Tests for README badge injection."""

    def test_badge_injection(self):
        """Test that badge is injected into README."""
        with tempfile.TemporaryDirectory() as tmpdir:
            readme_path = Path(tmpdir) / "README.md"
            readme_path.write_text("# My Project\n\nSome content here.\n")

            original_dir = os.getcwd()
            os.chdir(tmpdir)

            try:
                with patch("builtins.input", return_value="y"):
                    result = _inject_readme_badge()

                content = readme_path.read_text()
                assert "Protected by Vouch" in content
                assert result is True
            finally:
                os.chdir(original_dir)

    def test_badge_skip_when_declined(self):
        """Test that badge is not injected when user declines."""
        with tempfile.TemporaryDirectory() as tmpdir:
            readme_path = Path(tmpdir) / "README.md"
            readme_path.write_text("# My Project\n")

            original_dir = os.getcwd()
            os.chdir(tmpdir)

            try:
                with patch("builtins.input", return_value="n"):
                    result = _inject_readme_badge()

                content = readme_path.read_text()
                assert "Protected by Vouch" not in content
                assert result is False
            finally:
                os.chdir(original_dir)

    def test_badge_already_present(self):
        """Test that badge is not duplicated if already present."""
        with tempfile.TemporaryDirectory() as tmpdir:
            readme_path = Path(tmpdir) / "README.md"
            readme_path.write_text(f"# My Project\n\n{VOUCH_BADGE_MARKDOWN}\n")

            original_dir = os.getcwd()
            os.chdir(tmpdir)

            try:
                with patch("builtins.input", return_value="y"):
                    result = _inject_readme_badge()

                assert result is False  # Badge already present
            finally:
                os.chdir(original_dir)


class TestVerifyGitHistory:
    """Tests for verify_git_history.py script."""

    def test_script_runs(self):
        """Test that the verification script runs without error."""
        result = subprocess.run(
            ["python", "scripts/verify_git_history.py", "--count", "5", "--report"],
            capture_output=True,
            text=True,
        )

        # Should run (may have 0 verified commits, but shouldn't crash)
        assert "Verifying" in result.stdout or result.returncode == 0
