"""
Vouch Verification - Shared verification logic for commits and signatures.

This module provides the core verification logic used by both:
- CLI (`vouch git verify`)
- GitHub App (VouchTrailerVerifier)

Having a single implementation ensures consistency across all verification contexts.
"""

from __future__ import annotations

import hashlib
import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Any


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class VerificationResult:
    """Result of verifying a commit's Vouch signature."""

    verified: bool
    """Whether the verification passed."""

    commit_hash: str
    """The commit hash that was verified."""

    trailer_did: Optional[str] = None
    """The Vouch-DID extracted from the commit trailer."""

    derived_did: Optional[str] = None
    """The DID derived from the signing key (if available)."""

    git_verified: bool = False
    """Whether git's signature verification passed."""

    signer: Optional[str] = None
    """The signer identity (username or email)."""

    source: str = "unknown"
    """Verification source: 'local', 'github_api', 'vouch_trailer', etc."""

    is_org_member: bool = False
    """Whether the signer is an org member (for GitHub App context)."""

    error: Optional[str] = None
    """Error message if verification failed."""

    warnings: List[str] = field(default_factory=list)
    """Non-fatal warnings encountered during verification."""


# =============================================================================
# DID Extraction
# =============================================================================


def extract_vouch_did_from_message(message: str) -> Optional[str]:
    """
    Extract Vouch-DID trailer from a commit message.

    The trailer format is:
        Vouch-DID: did:vouch:abc123

    Args:
        message: The full commit message

    Returns:
        The DID string if found, None otherwise
    """
    match = re.search(r"Vouch-DID:\s*(\S+)", message)
    return match.group(1) if match else None


def extract_vouch_did_from_commit(commit_hash: str) -> Optional[str]:
    """
    Extract Vouch-DID trailer from a git commit.

    Args:
        commit_hash: The git commit hash

    Returns:
        The DID string if found, None otherwise
    """
    result = subprocess.run(
        ["git", "log", "-1", "--format=%B", commit_hash],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        return None

    return extract_vouch_did_from_message(result.stdout)


# =============================================================================
# DID Derivation
# =============================================================================


def derive_did_from_public_key_bytes(public_key_bytes: bytes) -> str:
    """
    Derive a Vouch DID from raw Ed25519 public key bytes.

    The DID is derived by:
    1. Hashing the raw public key bytes with SHA256
    2. Taking the first 12 hex characters

    This method is language-agnostic and produces consistent DIDs.

    Args:
        public_key_bytes: Raw 32-byte Ed25519 public key

    Returns:
        A DID string like "did:vouch:abc123def456"
    """
    did_hash = hashlib.sha256(public_key_bytes).hexdigest()[:12]
    return f"did:vouch:{did_hash}"


def derive_did_from_ssh_pubkey(ssh_pubkey_path: str) -> Optional[str]:
    """
    Derive Vouch DID from an SSH public key file.

    Args:
        ssh_pubkey_path: Path to the SSH public key file

    Returns:
        The derived DID string, or None if derivation failed
    """
    try:
        from cryptography.hazmat.primitives.serialization import (
            load_ssh_public_key,
            Encoding,
            PublicFormat,
        )

        # Read SSH public key
        with open(ssh_pubkey_path, "r") as f:
            ssh_pubkey_data = f.read()

        # Parse the key (first part before comment)
        key_parts = ssh_pubkey_data.strip().split()
        if len(key_parts) < 2:
            return None

        key_type = key_parts[0]
        key_data = key_parts[1]

        # Load the key
        full_key = f"{key_type} {key_data}".encode()
        public_key = load_ssh_public_key(full_key)

        # Get raw public key bytes for Ed25519 (32 bytes)
        raw_bytes = public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)

        return derive_did_from_public_key_bytes(raw_bytes)

    except Exception as e:
        logging.debug(f"Error deriving DID from SSH key: {e}")
        return None


# =============================================================================
# Git Signature Verification
# =============================================================================


def verify_git_signature(commit_hash: str, ssh_key_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Verify a commit's signature using git.

    This sets up the allowed_signers file if needed and runs git verify-commit.

    Args:
        commit_hash: The git commit hash
        ssh_key_path: Optional path to the Vouch SSH key for allowed_signers setup

    Returns:
        Dict with keys:
            - verified: bool
            - key_fingerprint: Optional[str]
            - signer: Optional[str]
    """
    # Ensure allowed_signers file is configured for SSH verification
    allowed_signers_path = Path.home() / ".ssh" / "allowed_signers"

    if ssh_key_path and ssh_key_path.exists() and not allowed_signers_path.exists():
        _setup_allowed_signers(ssh_key_path, allowed_signers_path)

    result = subprocess.run(
        ["git", "verify-commit", "--raw", commit_hash],
        capture_output=True,
        text=True,
    )

    # Git outputs signature info to stderr
    output = result.stderr

    info = {
        "verified": result.returncode == 0,
        "key_fingerprint": None,
        "signer": None,
    }

    # Parse SSH signature info (e.g., "Good signature from...")
    if "Good signature" in output or "good signature" in output.lower():
        info["verified"] = True

    # Try to extract key fingerprint
    for line in output.split("\n"):
        if "SHA256:" in line:
            match = re.search(r"SHA256:(\S+)", line)
            if match:
                info["key_fingerprint"] = f"SHA256:{match.group(1)}"

    return info


def _setup_allowed_signers(ssh_key_path: Path, allowed_signers_path: Path) -> None:
    """Set up git's allowed_signers file for SSH signature verification."""
    try:
        ssh_pubkey = ssh_key_path.read_text().strip()

        # Get configured email
        email_result = subprocess.run(
            ["git", "config", "--global", "--get", "user.email"],
            capture_output=True,
            text=True,
        )
        email = email_result.stdout.strip() if email_result.returncode == 0 else "vouch@local"

        # Write allowed_signers file
        allowed_signers_path.write_text(f"{email} {ssh_pubkey}\n")

        # Configure git to use it
        subprocess.run(
            [
                "git",
                "config",
                "--global",
                "gpg.ssh.allowedSignersFile",
                str(allowed_signers_path),
            ],
            capture_output=True,
        )
    except Exception as e:
        logging.debug(f"Could not setup allowed_signers: {e}")


# =============================================================================
# Main Verification Functions
# =============================================================================


def verify_commit_vouch_signature(
    commit_hash: str,
    ssh_key_path: Optional[Path] = None,
    verbose: bool = False,
) -> VerificationResult:
    """
    Verify a commit's Vouch signature.

    This is the main verification function used by both CLI and GitHub App.

    Verification steps:
    1. Extract Vouch-DID trailer from commit message
    2. Verify git signature is valid
    3. (If local key available) Derive DID from signing key and compare

    Args:
        commit_hash: The git commit hash
        ssh_key_path: Optional path to local Vouch SSH key for full verification
        verbose: Enable verbose logging

    Returns:
        VerificationResult with verification status and details
    """
    result = VerificationResult(
        verified=False,
        commit_hash=commit_hash,
        source="local",
    )

    # 1. Get Vouch-DID from commit trailer
    trailer_did = extract_vouch_did_from_commit(commit_hash)
    result.trailer_did = trailer_did

    if not trailer_did:
        result.error = "No Vouch-DID trailer found in commit"
        return result

    # 2. Check if git verifies the signature
    sig_info = verify_git_signature(commit_hash, ssh_key_path)
    result.git_verified = sig_info["verified"]

    if not sig_info["verified"]:
        result.error = "Git signature verification failed"
        return result

    # 3. Derive DID from the signing key (if available)
    if ssh_key_path and ssh_key_path.exists():
        derived_did = derive_did_from_ssh_pubkey(str(ssh_key_path))
        result.derived_did = derived_did

        # 4. Compare DIDs
        if derived_did and trailer_did == derived_did:
            result.verified = True
        elif derived_did:
            result.error = f"DID mismatch: trailer={trailer_did}, key={derived_did}"
        else:
            result.error = "Could not derive DID from signing key"
    else:
        # For third-party verification, we can only check git's verification
        # and that the trailer exists
        result.verified = True
        result.warnings.append("Full DID verification requires local Vouch key")

    return result


def verify_commit_from_github_api(
    commit: Dict[str, Any],
    repo_org: str,
    check_org_membership: Optional[callable] = None,
) -> VerificationResult:
    """
    Verify a commit using data from GitHub API.

    This is used by the GitHub App when processing PRs.

    Args:
        commit: GitHub API commit object
        repo_org: The organization/owner of the repository
        check_org_membership: Optional async function to check org membership

    Returns:
        VerificationResult with verification status and details
    """
    result = VerificationResult(
        verified=False,
        commit_hash=commit.get("sha", "")[:8],
        source="github_api",
    )

    message = commit.get("commit", {}).get("message", "")
    verification = commit.get("commit", {}).get("verification", {})
    author_login = commit.get("author", {}).get("login")


    is_verified = verification.get("verified", False)
    signature = verification.get("signature", "")

    result.signer = author_login
    result.git_verified = is_verified

    # Extract Vouch-DID trailer
    vouch_did = extract_vouch_did_from_message(message)
    result.trailer_did = vouch_did

    # If no Vouch-DID trailer, check for backwards compatibility
    if not vouch_did:
        if is_verified and author_login:
            # Accept verified commits from org members even without trailer
            result.verified = True
            result.source = "github_verified_fallback"
            result.warnings.append(
                "No Vouch-DID trailer. Run 'vouch git init' to enable full verification."
            )
            return result

        result.error = "No Vouch-DID trailer in commit message"
        return result

    # Check if commit signature is valid
    if not signature:
        result.error = "Commit has Vouch-DID but is not signed"
        return result

    if not is_verified:
        reason = verification.get("reason", "unknown")
        result.error = f"Commit signature verification failed: {reason}"
        return result

    # Commit is signed, verified, and has Vouch-DID
    result.verified = True
    result.source = "vouch_trailer"

    return result


# =============================================================================
# Batch Verification
# =============================================================================


def verify_commits(
    commit_hashes: List[str],
    ssh_key_path: Optional[Path] = None,
    verbose: bool = False,
) -> List[VerificationResult]:
    """
    Verify multiple commits.

    Args:
        commit_hashes: List of git commit hashes
        ssh_key_path: Optional path to local Vouch SSH key
        verbose: Enable verbose logging

    Returns:
        List of VerificationResult objects
    """
    return [
        verify_commit_vouch_signature(h, ssh_key_path, verbose)
        for h in commit_hashes
    ]
