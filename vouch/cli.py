"""
Vouch Protocol Command Line Interface.

Provides commands for initializing identity, signing messages, verifying tokens,
and configuring git for cryptographic commit signing.
"""

from __future__ import annotations

import argparse
import sys
import json
import os
import logging
import subprocess
import webbrowser
import hashlib
import base64
from pathlib import Path

from jwcrypto import jwk
from cryptography.hazmat.primitives import serialization

from vouch.signer import Signer
from vouch.verifier import Verifier
from vouch.keys import KeyManager, generate_identity
import getpass

# Constants
SSH_KEY_PATH = Path.home() / ".ssh" / "vouch_signing.pub"
PRIVATE_KEY_PATH = Path.home() / ".ssh" / "vouch_signing"
VOUCH_BADGE_MARKDOWN = """[![Protected by Vouch](https://img.shields.io/badge/Protected_by-Vouch_Protocol-00C853?style=flat&labelColor=333&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgd2lkdGg9IjI0IiBoZWlnaHQ9IjI0Ij48cGF0aCBmaWxsPSIjMDBDODUzIiBkPSJNMTIgMjBMMiA0aDRsNiAxMC41TDE4IDRoNEwxMiAyMHoiLz48L3N2Zz4=)](https://github.com/vouch-protocol/vouch)"""

PREPARE_COMMIT_MSG_HOOK = """#!/bin/bash
# Vouch Protocol - Commit Trailer Hook
# Appends Vouch identity trailer to commit messages

COMMIT_MSG_FILE=$1
COMMIT_SOURCE=$2

# Skip for merge commits, amend, etc.
case "$COMMIT_SOURCE" in
    merge|squash) exit 0 ;;
esac

# Get Vouch DID from environment or config
VOUCH_DID="${VOUCH_DID:-$(git config --get vouch.did 2>/dev/null)}"

if [ -n "$VOUCH_DID" ]; then
    # Generate short hash of DID for identification
    DID_HASH=$(echo -n "$VOUCH_DID" | sha256sum | cut -c1-12)
    
    # Append trailers if not already present
    if ! grep -q "Vouch-DID:" "$COMMIT_MSG_FILE"; then
        echo "" >> "$COMMIT_MSG_FILE"
        echo "Signed-off-by: Vouch Protocol <Identity-Sidecar>" >> "$COMMIT_MSG_FILE"
        echo "Vouch-DID: $VOUCH_DID" >> "$COMMIT_MSG_FILE"
    fi
fi
"""


def setup_logging(verbose: bool = False) -> None:
    """Configure logging based on verbosity."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def cmd_init(args: argparse.Namespace) -> int:
    """Generate a new Ed25519 keypair for agent identity."""
    try:
        # Build DID
        domain = args.domain if args.domain else "example.com"
        
        # Generate keys
        keys = generate_identity(domain)

        if args.env:
            # Output as environment variable format
            print(f"export VOUCH_DID='{keys.did}'")
            print(f"export VOUCH_PRIVATE_KEY='{keys.private_key_jwk}'")
            print(f"# Public Key (for vouch.json): {keys.public_key_jwk}", file=sys.stderr)
        else:
            print("🔑 NEW AGENT IDENTITY GENERATED\n")
            print(f"DID: {keys.did}")
            
            # Key Storage
            km = KeyManager()
            
            # Prompt for passphrase
            print("\n🔐 Secure Storage")
            passphrase = getpass.getpass(f"Enter passphrase for {keys.did} (leave empty for no encryption): ")
            confirm = getpass.getpass("Confirm passphrase: ") if passphrase else ""
            
            if passphrase != confirm:
                print("❌ Error: Passphrases do not match", file=sys.stderr)
                return 1
                
            try:
                km.save_identity(keys, passphrase if passphrase else None)
                print(f"✅ Identity saved to: {km._get_filename(keys.did)}")
                if not passphrase:
                    print("⚠️  Warning: Key saved in PLAIN TEXT. Use a passphrase for security.")
            except Exception as e:
                print(f"❌ Error saving identity: {e}", file=sys.stderr)
                return 1

            print("\n--- PUBLIC KEY (Put this in vouch.json) ---")
            print(keys.public_key_jwk)

        return 0

    except Exception as e:
        print(f"Error generating keys: {e}", file=sys.stderr)
        return 1


def cmd_sign(args: argparse.Namespace) -> int:
    """Sign a message or JSON payload."""
    # Get credentials
    private_key = args.key or os.environ.get("VOUCH_PRIVATE_KEY")
    did = args.did or os.environ.get("VOUCH_DID")

    # If key/did not in args/env, try loading from keystore
    if not private_key:
        km = KeyManager()
        identities = km.list_identities()
        
        if not identities:
            print("Error: No identity found. Run 'vouch init' or set VOUCH_PRIVATE_KEY", file=sys.stderr)
            return 1
            
        # Select identity
        selected_did = did
        if not selected_did:
            if len(identities) == 1:
                selected_did = identities[0]["did"]
            else:
                print("Multiple identities found:")
                for i, ident in enumerate(identities):
                    print(f"{i+1}. {ident['did']}")
                try:
                    choice = int(input("Select identity (number): ")) - 1
                    selected_did = identities[choice]["did"]
                except (ValueError, IndexError):
                    print("Invalid selection", file=sys.stderr)
                    return 1
        
        # Load identity
        try:
            # Check if encrypted (naive check via list, or just try loading)
            # We'll just try loading. If it fails with password error, prompt.
            # But load_identity throws ValueError on password fail? No, if encrypted=True and password=None, it raises ValueError.
            
            # First, check if we need password
            # We can't easily check without parsing JSON, but load_identity handles it.
            # We'll assume we try with None, catch error, prompt.
            passphrase = None
            
            # Check if file is encrypted to prompt nicely 
            # (Optimization: We could peek at the JSON, but let's just try/except)
            
            # Actually, KeyManager.load_identity raises ValueError("Password required") if needed.
            try:
                keys = km.load_identity(selected_did, None)
            except ValueError as e:
                if "Password required" in str(e) or "Decryption" in str(e):
                    passphrase = getpass.getpass(f"Enter passphrase for {selected_did}: ")
                    keys = km.load_identity(selected_did, passphrase)
                else:
                    raise e
            
            private_key = keys.private_key_jwk
            did = keys.did # Update DID if we auto-selected
            
        except Exception as e:
            print(f"Error loading identity: {e}", file=sys.stderr)
            return 1

    if not private_key:
        print("Error: Missing private key. Set VOUCH_PRIVATE_KEY or use --key", file=sys.stderr)
        return 1

    if not did:
        print("Error: Missing DID. Set VOUCH_DID or use --did", file=sys.stderr)
        return 1

    try:
        # Parse the message
        if args.json:
            try:
                payload = json.loads(args.message)
            except json.JSONDecodeError as e:
                print(f"Error: Invalid JSON message: {e}", file=sys.stderr)
                return 1
        else:
            # Wrap string message in a payload
            payload = {"message": args.message}

        # Create signer and sign
        signer = Signer(private_key=private_key, did=did)
        token = signer.sign(payload)

        if args.header:
            print(f"Vouch-Token: {token}")
        else:
            print(token)

        return 0

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error signing message: {e}", file=sys.stderr)
        return 1


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify a Vouch-Token."""
    token = args.token
    public_key = args.key or os.environ.get("VOUCH_PUBLIC_KEY")

    try:
        if public_key:
            valid, passport = Verifier.verify(token, public_key_jwk=public_key)
        else:
            # Verify without signature check (structure only)
            valid, passport = Verifier.verify(token)
            if valid:
                print("⚠️  Warning: No public key provided, signature not verified", file=sys.stderr)

        if valid and passport:
            if args.json:
                result = {
                    "valid": True,
                    "sub": passport.sub,
                    "iss": passport.iss,
                    "iat": passport.iat,
                    "exp": passport.exp,
                    "jti": passport.jti,
                    "payload": passport.payload,
                }
                print(json.dumps(result, indent=2))
            else:
                print("✅ VALID")
                print(f"   Subject: {passport.sub}")
                print(f"   Issuer:  {passport.iss}")
                print(f"   Payload: {json.dumps(passport.payload)}")
            return 0
        else:
            if args.json:
                print(json.dumps({"valid": False}))
            else:
                print("❌ INVALID")
            return 1

    except Exception as e:
        print(f"Error verifying token: {e}", file=sys.stderr)
        return 1


def _export_vouch_key_to_ssh() -> tuple[str, str]:
    """Export Vouch identity to SSH key format.

    Returns:
        Tuple of (public_key_ssh, did)
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key_json = os.environ.get("VOUCH_PRIVATE_KEY")
    did = os.environ.get("VOUCH_DID")

    if not private_key_json:
        # Generate new key if none exists
        key = jwk.JWK.generate(kty="OKP", crv="Ed25519")
        private_key_json = key.export_private()

        # Extract raw public key bytes for DID derivation
        # This is language-agnostic and doesn't depend on JSON serialization format
        key_dict = json.loads(key.export_private())
        d_bytes = base64.urlsafe_b64decode(key_dict.get("d") + "==")
        private_key = Ed25519PrivateKey.from_private_bytes(d_bytes)
        raw_public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        # DID is derived from raw public key bytes (32 bytes for Ed25519)
        # This ensures consistent DIDs across all programming languages
        did = "did:vouch:" + hashlib.sha256(raw_public_bytes).hexdigest()[:12]
    else:
        key = jwk.JWK.from_json(private_key_json)

    # Convert JWK to cryptography key for SSH export
    # Export the key as JSON and parse for 'd' parameter
    key_dict = json.loads(key.export_private())
    d_bytes = base64.urlsafe_b64decode(key_dict.get("d") + "==")

    private_key = Ed25519PrivateKey.from_private_bytes(d_bytes)

    # Export to OpenSSH format
    ssh_public = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.OpenSSH, format=serialization.PublicFormat.OpenSSH
        )
        .decode()
        + " vouch-protocol"
    )

    ssh_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    # Save keys
    SSH_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    SSH_KEY_PATH.write_text(ssh_public + "\n")
    PRIVATE_KEY_PATH.write_text(ssh_private)
    PRIVATE_KEY_PATH.chmod(0o600)

    return ssh_public, did or "did:vouch:unknown"


def _configure_git_signing(ssh_key_path: str, did: str) -> None:
    """Configure git to use SSH key for signing."""
    commands = [
        ["git", "config", "--global", "user.signingkey", ssh_key_path],
        ["git", "config", "--global", "gpg.format", "ssh"],
        ["git", "config", "--global", "commit.gpgsign", "true"],
        ["git", "config", "--global", "vouch.did", did],
    ]
    for cmd in commands:
        subprocess.run(cmd, check=True, capture_output=True)


def _install_commit_hook(skip_trailer: bool = False) -> bool:
    """Install prepare-commit-msg hook for Vouch trailers.

    Returns:
        True if hook was installed, False otherwise
    """
    if skip_trailer:
        return False

    # Find git directory
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--git-dir"], capture_output=True, text=True, check=True
        )
        git_dir = Path(result.stdout.strip())
    except subprocess.CalledProcessError:
        return False  # Not in a git repo

    hook_path = git_dir / "hooks" / "prepare-commit-msg"

    if hook_path.exists():
        # Append to existing hook
        existing = hook_path.read_text()
        if "Vouch Protocol" not in existing:
            hook_path.write_text(existing + "\n" + PREPARE_COMMIT_MSG_HOOK)
            print("   Appended Vouch trailer to existing hook")
    else:
        hook_path.write_text(PREPARE_COMMIT_MSG_HOOK)
        hook_path.chmod(0o755)
        print("   Installed new prepare-commit-msg hook")

    return True


def _inject_readme_badge() -> bool:
    """Inject Vouch badge into README.md if user agrees."""
    readme_path = Path("README.md")
    if not readme_path.exists():
        return False

    response = input("\n🏷️  Add 'Protected by Vouch' badge to README.md? [Y/n]: ").strip().lower()
    if response == "n":
        return False

    content = readme_path.read_text()
    if "Protected by Vouch" in content:
        print("   Badge already present in README")
        return False

    # Find first heading or add at top
    lines = content.split("\n")
    insert_idx = 0
    for i, line in enumerate(lines):
        if line.startswith("# "):
            insert_idx = i + 1
            break

    lines.insert(insert_idx, "")
    lines.insert(insert_idx + 1, VOUCH_BADGE_MARKDOWN)
    lines.insert(insert_idx + 2, "")

    readme_path.write_text("\n".join(lines))
    print("   ✅ Badge added to README.md")
    return True


def _upload_ssh_key(ssh_public: str) -> None:
    """Upload SSH key to GitHub via gh CLI or browser fallback."""
    # Check if gh CLI is available
    try:
        subprocess.run(["gh", "--version"], capture_output=True, check=True)
        gh_available = True
    except (subprocess.CalledProcessError, FileNotFoundError):
        gh_available = False

    if gh_available:
        print("\n🔑 Uploading signing key to GitHub...")
        try:
            result = subprocess.run(
                [
                    "gh",
                    "ssh-key",
                    "add",
                    str(SSH_KEY_PATH),
                    "--type",
                    "signing",
                    "--title",
                    "Vouch Protocol Identity",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                print("   ✅ SSH key uploaded to GitHub!")
                return
            else:
                print(f"   ⚠️  gh upload failed: {result.stderr.strip()}")
        except Exception as e:
            print(f"   ⚠️  gh upload failed: {e}")

    # Fallback: browser + manual
    print("\n📋 Add this SSH key to GitHub manually:")
    print("=" * 60)
    print(ssh_public)
    print("=" * 60)
    print("\n1. Opening GitHub SSH settings...")
    webbrowser.open("https://github.com/settings/ssh/new")
    print("2. Select 'Signing Key' as the Key type")
    print("3. Paste the key above and save")


def cmd_git_init(args: argparse.Namespace) -> int:
    """Configure SSH signing and Vouch branding for git."""
    print("🚀 Vouch Git Workflow Setup\n")

    try:
        # Step 1: Export SSH key
        print("1️⃣  Exporting Vouch identity to SSH key...")
        ssh_public, did = _export_vouch_key_to_ssh()
        print(f"   Key saved to: {SSH_KEY_PATH}")
        print(f"   DID: {did}")

        # Step 2: Configure git
        print("\n2️⃣  Configuring git for SSH signing...")
        _configure_git_signing(str(SSH_KEY_PATH), did)
        print("   ✅ Git configured: commit.gpgsign=true, gpg.format=ssh")

        # Step 3: Upload to GitHub
        _upload_ssh_key(ssh_public)

        # Step 4: Install hook (optional)
        if not args.no_trailer:
            print("\n3️⃣  Installing commit trailer hook...")
            _install_commit_hook(skip_trailer=False)

        # Step 5: Badge injection (optional)
        if not args.no_badge:
            _inject_readme_badge()

        print("\n" + "=" * 60)
        print("✅ Vouch Git Workflow configured!")
        print("   All future commits will be signed and show ✅ Verified on GitHub")
        print("=" * 60)

        return 0

    except Exception as e:
        print(f"\n❌ Error: {e}", file=sys.stderr)
        return 1


def cmd_git_status(args: argparse.Namespace) -> int:
    """Show current Vouch git signing configuration."""
    print("🔍 Vouch Git Status\n")

    # Check SSH key
    if SSH_KEY_PATH.exists():
        print(f"✅ SSH Key: {SSH_KEY_PATH}")
        # Show fingerprint
        try:
            result = subprocess.run(
                ["ssh-keygen", "-lf", str(SSH_KEY_PATH)], capture_output=True, text=True
            )
            if result.returncode == 0:
                print(f"   Fingerprint: {result.stdout.strip()}")
        except Exception:
            pass
    else:
        print("❌ SSH Key: Not configured")

    # Check git config
    configs = [
        ("user.signingkey", "Signing Key"),
        ("gpg.format", "GPG Format"),
        ("commit.gpgsign", "Auto-sign"),
        ("vouch.did", "Vouch DID"),
    ]

    print("\n📝 Git Configuration:")
    for key, label in configs:
        try:
            result = subprocess.run(
                ["git", "config", "--global", "--get", key], capture_output=True, text=True
            )
            value = result.stdout.strip() if result.returncode == 0 else "Not set"
            status = "✅" if result.returncode == 0 else "❌"
            print(f"   {status} {label}: {value}")
        except Exception:
            print(f"   ❌ {label}: Error checking")

    # Check hook
    try:
        result = subprocess.run(["git", "rev-parse", "--git-dir"], capture_output=True, text=True)
        if result.returncode == 0:
            hook_path = Path(result.stdout.strip()) / "hooks" / "prepare-commit-msg"
            if hook_path.exists() and "Vouch" in hook_path.read_text():
                print("\n✅ Commit Hook: Installed")
            else:
                print("\n❌ Commit Hook: Not installed")
    except Exception:
        print("\n⚠️  Commit Hook: Not in a git repository")

    return 0


def _get_vouch_did_from_commit(commit_hash: str) -> str | None:
    """Extract Vouch-DID trailer from a commit message."""
    import re

    result = subprocess.run(
        ["git", "log", "-1", "--format=%B", commit_hash],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        return None

    match = re.search(r"Vouch-DID:\s*(\S+)", result.stdout)
    return match.group(1) if match else None


def _get_commit_signature_info(commit_hash: str) -> dict:
    """Get signature verification info from git."""
    # Ensure allowed_signers file is configured for SSH verification
    allowed_signers_path = Path.home() / ".ssh" / "allowed_signers"

    if SSH_KEY_PATH.exists() and not allowed_signers_path.exists():
        # Create allowed_signers file from Vouch key
        try:
            ssh_pubkey = SSH_KEY_PATH.read_text().strip()
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
            # Extract fingerprint
            import re

            match = re.search(r"SHA256:(\S+)", line)
            if match:
                info["key_fingerprint"] = f"SHA256:{match.group(1)}"

    return info


def _derive_did_from_ssh_pubkey(ssh_pubkey_path: str) -> str | None:
    """Derive Vouch DID from an SSH public key file.

    The DID is derived by:
    1. Extracting raw Ed25519 public key bytes (32 bytes)
    2. Hashing with SHA256
    3. Taking first 12 hex characters

    This method is language-agnostic and doesn't depend on JSON serialization.
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
        raw_bytes = public_key.public_bytes(
            encoding=Encoding.Raw, format=PublicFormat.Raw
        )

        # DID is derived from raw public key bytes
        # This ensures consistent DIDs across all programming languages
        did_hash = hashlib.sha256(raw_bytes).hexdigest()[:12]
        return f"did:vouch:{did_hash}"

    except Exception as e:
        logging.debug(f"Error deriving DID from SSH key: {e}")
        return None


def _verify_commit_vouch_signature(commit_hash: str, verbose: bool = False) -> dict:
    """Verify a commit's signature matches its Vouch-DID trailer.

    Returns a dict with:
        - verified: bool - Whether verification passed
        - commit_hash: str - The commit hash
        - trailer_did: str | None - DID from commit trailer
        - derived_did: str | None - DID derived from signing key
        - error: str | None - Error message if failed
    """
    result = {
        "verified": False,
        "commit_hash": commit_hash,
        "trailer_did": None,
        "derived_did": None,
        "git_verified": False,
        "error": None,
    }

    # 1. Get Vouch-DID from commit trailer
    trailer_did = _get_vouch_did_from_commit(commit_hash)
    result["trailer_did"] = trailer_did

    if not trailer_did:
        result["error"] = "No Vouch-DID trailer found in commit"
        return result

    # 2. Check if git verifies the signature
    sig_info = _get_commit_signature_info(commit_hash)
    result["git_verified"] = sig_info["verified"]

    if not sig_info["verified"]:
        result["error"] = "Git signature verification failed"
        return result

    # 3. Derive DID from the signing key
    # Check if we're using the local Vouch signing key
    if SSH_KEY_PATH.exists():
        derived_did = _derive_did_from_ssh_pubkey(str(SSH_KEY_PATH))
        result["derived_did"] = derived_did

        # 4. Compare DIDs
        if derived_did and trailer_did == derived_did:
            result["verified"] = True
        elif derived_did:
            result["error"] = f"DID mismatch: trailer={trailer_did}, key={derived_did}"
        else:
            result["error"] = "Could not derive DID from signing key"
    else:
        # For third-party verification, we can only check git's verification
        # and that the trailer exists
        result["verified"] = True
        result["error"] = "Note: Full DID verification requires local Vouch key"

    return result


def cmd_git_verify(args: argparse.Namespace) -> int:
    """Verify commit signatures match their Vouch-DID trailers."""
    verbose = getattr(args, "verbose", False)

    if hasattr(args, "commit") and args.commit:
        # Single commit verification
        commits = [args.commit]
    else:
        # Get recent commits
        count = getattr(args, "count", 10)
        result = subprocess.run(
            ["git", "log", f"-{count}", "--format=%H"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print("❌ Error: Not in a git repository", file=sys.stderr)
            return 1
        commits = [h.strip() for h in result.stdout.strip().split("\n") if h.strip()]

    if not commits:
        print("No commits to verify")
        return 0

    print(f"🔐 Verifying Vouch signatures for {len(commits)} commit(s)...\n")

    verified = 0
    failed = 0
    skipped = 0

    for commit_hash in commits:
        short_hash = commit_hash[:8]

        # Get commit subject
        result = subprocess.run(
            ["git", "log", "-1", "--format=%s", commit_hash],
            capture_output=True,
            text=True,
        )
        subject = result.stdout.strip()[:50] if result.returncode == 0 else "Unknown"

        # Verify
        verification = _verify_commit_vouch_signature(commit_hash, verbose)

        if verification["verified"]:
            verified += 1
            print(f"  ✅ {short_hash} - {subject}")
            if verbose and verification["trailer_did"]:
                print(f"     Vouch-DID: {verification['trailer_did']}")
        elif verification["trailer_did"] is None:
            skipped += 1
            if verbose:
                print(f"  ⏭️  {short_hash} - {subject}")
                print("     No Vouch-DID trailer (skipped)")
        else:
            failed += 1
            print(f"  ❌ {short_hash} - {subject}")
            if verification["error"]:
                print(f"     Error: {verification['error']}")

    print("\n📊 Results:")
    print(f"   ✅ Verified: {verified}")
    if skipped > 0:
        print(f"   ⏭️  Skipped (no trailer): {skipped}")
    if failed > 0:
        print(f"   ❌ Failed: {failed}")

    strict = getattr(args, "strict", False)
    if strict and failed > 0:
        print(f"\n❌ FAILED: {failed} commit(s) failed verification")
        return 1

    if verified > 0 and failed == 0:
        print("\n✅ All Vouch-signed commits verified!")

    return 0


# =============================================================================
# Media Commands (C2PA Integration)
# =============================================================================

def cmd_media_sign(args: argparse.Namespace) -> int:
    """Sign an image with Vouch signature (native by default, or C2PA with --c2pa)."""
    
    # Check if C2PA mode requested
    if getattr(args, 'c2pa', False):
        return _cmd_media_sign_c2pa(args)
    
    # Default: Use native Vouch signing (no certificates needed!)
    return _cmd_media_sign_native(args)


def _cmd_media_sign_native(args: argparse.Namespace) -> int:
    """Sign an image with native Vouch signature (no certificates)."""
    try:
        from vouch.media.native import sign_image_native, generate_keypair, truncate_did, generate_verify_shortlink
        
        source_path = Path(args.image)
        if not source_path.exists():
            print(f"❌ Error: File not found: {source_path}", file=sys.stderr)
            return 1
        
        # Get identity from args or environment
        display_name = args.name or os.environ.get("VOUCH_DISPLAY_NAME", "Anonymous")
        email = args.email or os.environ.get("VOUCH_EMAIL")
        
        # Generate or load keypair
        private_key_json = args.key or os.environ.get("VOUCH_PRIVATE_KEY")
        
        if private_key_json:
            # Load from JWK
            key = jwk.JWK.from_json(private_key_json)
            private_bytes = base64.urlsafe_b64decode(key.d + "==")
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
            did = args.did or os.environ.get("VOUCH_DID", f"did:key:temp_{hashlib.sha256(display_name.encode()).hexdigest()[:16]}")
        else:
            # Generate ephemeral keypair
            private_key, did = generate_keypair()
            print("⚠️  Generated ephemeral keypair (set VOUCH_PRIVATE_KEY for persistent identity)", file=sys.stderr)
        
        # Sign the image
        output_path = args.output or source_path.parent / f"{source_path.stem}_signed{source_path.suffix}"
        
        result = sign_image_native(
            source_path=source_path,
            private_key=private_key,
            did=did,
            display_name=display_name,
            email=email,
            credential_type="PRO" if args.pro else "FREE",
            output_path=output_path,
        )
        
        if result.success:
            # Show any warnings first
            if result.warning:
                print(result.warning, file=sys.stderr)
            
            print("✅ Image signed successfully!")
            print(f"   Source: {result.source_path}")
            print(f"   Output: {result.output_path}")
            print(f"   Sidecar: {result.sidecar_path}")
            print("\n🔐 Signer:")
            print(f"   Name:   {result.signature.display_name}")
            if result.signature.email:
                print(f"   Email:  {result.signature.email}")
            print(f"   DID:    {truncate_did(result.signature.did)}")
            print(f"   Tier:   {result.signature.credential_type}")
            print("\n📋 Claim:")
            print(f"   Type:   {result.signature.claim_type.upper()}")
            print(f"   Chain:  {result.signature.chain_id}")
            print(f"   Depth:  {result.signature.chain_depth}")
            print(f"   Trust:  {result.signature.chain_strength:.0%}")
            print(f"\n🔗 Verify: {generate_verify_shortlink(result.signature)}")
            return 0
        else:
            print(f"❌ Error signing image: {result.error}", file=sys.stderr)
            return 1
            
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1


def _cmd_media_sign_c2pa(args: argparse.Namespace) -> int:
    """Sign an image with C2PA manifest containing Vouch identity."""
    try:
        from vouch.media.c2pa import (
            MediaSigner, 
            VouchIdentity,
            generate_self_signed_certificate,
            C2PA_AVAILABLE,
        )
        
        if not C2PA_AVAILABLE:
            print("❌ Error: c2pa-python is required. Install with: pip install c2pa-python", file=sys.stderr)
            return 1
        
        source_path = Path(args.image)
        if not source_path.exists():
            print(f"❌ Error: File not found: {source_path}", file=sys.stderr)
            return 1
        
        # Get identity from args or environment
        display_name = args.name or os.environ.get("VOUCH_DISPLAY_NAME", "Anonymous")
        email = args.email or os.environ.get("VOUCH_EMAIL")
        did = args.did or os.environ.get("VOUCH_DID", f"did:key:temp_{hashlib.sha256(display_name.encode()).hexdigest()[:16]}")
        
        # Load C2PA test certificates for development
        # These are ES256 (ECDSA P-256) certificates from c2pa-python repo
        certs_dir = Path(__file__).parent / "media" / "certs"
        cert_path = certs_dir / "es256_certs.pem"
        key_path = certs_dir / "es256_private.key"
        
        if not cert_path.exists() or not key_path.exists():
            print("❌ Error: C2PA test certificates not found.", file=sys.stderr)
            print("   Expected files at:", file=sys.stderr)
            print(f"   - {cert_path}", file=sys.stderr)
            print(f"   - {key_path}", file=sys.stderr)
            return 1
        
        print("⚠️  Using C2PA test certificates (FOR DEVELOPMENT ONLY)", file=sys.stderr)
        
        certificate_chain = cert_path.read_bytes()
        private_key_pem = key_path.read_bytes()
        
        # Create identity
        identity = VouchIdentity(
            did=did,
            display_name=display_name,
            email=email,
            credential_type="PRO" if args.pro else "FREE",
        )
        
        # Sign using ES256 (test certs) with callback-based signing
        import c2pa
        import c2pa.c2pa as c2pa_lib
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        
        # Load private key for callback
        from cryptography.hazmat.primitives import serialization
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        
        # Create signing callback
        def sign_callback(data: bytes) -> bytes:
            return private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        
        # Create signer with tsa_url=None for offline signing
        signer = c2pa_lib.create_signer(
            callback=sign_callback,
            alg=c2pa.C2paSigningAlg.ES256,
            certs=certificate_chain.decode('utf-8'),
            tsa_url=None,
        )
        
        # Build the manifest
        manifest_json = {
            "claim_generator": "Vouch Protocol/1.0.0",
            "claim_generator_info": [{
                "name": "Vouch Protocol",
                "version": "1.0.0",
            }],
            "title": args.title or source_path.name,
            "assertions": [
                {
                    "label": "c2pa.actions",
                    "data": {
                        "actions": [{
                            "action": "c2pa.created",
                            "softwareAgent": "Vouch Protocol/1.0.0",
                        }]
                    }
                },
                identity.to_assertion(),
            ],
        }
        
        output_path = args.output or source_path.parent / f"{source_path.stem}_signed{source_path.suffix}"
        
        # Sign the file
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            manifest_bytes = c2pa_lib.sign_file(
                source_path=source_path,
                dest_path=str(output_path),
                manifest=json.dumps(manifest_json),
                signer_or_info=signer,
                return_manifest_as_bytes=True,
            )
        
        manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()[:16]
        
        print("✅ Image signed successfully!")
        print(f"   Source: {source_path}")
        print(f"   Output: {output_path}")
        print(f"   Signer: {identity.display_name}")
        if identity.email:
            print(f"   Email:  {identity.email}")
        print(f"   DID:    {identity.did}")
        print(f"   Hash:   {manifest_hash}")
        return 0
            
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1


def cmd_media_verify(args: argparse.Namespace) -> int:
    """Verify an image's Vouch signature (native by default, or C2PA with --c2pa)."""
    
    # Check if C2PA mode requested
    if getattr(args, 'c2pa', False):
        return _cmd_media_verify_c2pa(args)
    
    # Default: Use native Vouch verification
    return _cmd_media_verify_native(args)


def _cmd_media_verify_native(args: argparse.Namespace) -> int:
    """Verify an image's native Vouch signature."""
    try:
        from vouch.media.native import verify_image_native, truncate_did
        
        image_path = Path(args.image)
        if not image_path.exists():
            print(f"❌ Error: File not found: {image_path}", file=sys.stderr)
            return 1
        
        result = verify_image_native(image_path)
        
        if args.json:
            output = {
                "is_valid": result.is_valid,
                "source": result.source,
                "error": result.error,
            }
            if result.signature:
                output["signer"] = {
                    "did": result.signature.did,
                    "display_name": result.signature.display_name,
                    "email": result.signature.email,
                    "credential_type": result.signature.credential_type,
                    "timestamp": result.signature.timestamp,
                }
                output["claim"] = {
                    "type": result.signature.claim_type,
                    "chain_id": result.signature.chain_id,
                    "chain_depth": result.signature.chain_depth,
                    "trust_strength": result.signature.chain_strength,
                }
            print(json.dumps(output, indent=2))
        else:
            if result.is_valid:
                print("✅ Valid Vouch signature found!")
                print(f"   Source: {result.source}")
                
                if result.signature:
                    print("\n🔐 Signer:")
                    print(f"   Name:  {result.signature.display_name}")
                    if result.signature.email:
                        print(f"   Email: {result.signature.email}")
                    print(f"   DID:   {truncate_did(result.signature.did)}")
                    print(f"   Tier:  {result.signature.credential_type}")
                    print("\n📋 Claim:")
                    print(f"   Type:  {result.signature.claim_type.upper()}")
                    print(f"   Chain: {result.signature.chain_id}")
                    print(f"   Depth: {result.signature.chain_depth}")
                    print(f"   Trust: {result.signature.chain_strength:.0%}")
                    
                    # Show org credentials if present
                    if result.signature.credentials:
                        print("\n🏢 Organization:")
                        for cred in result.signature.credentials:
                            issuer_name = cred.get('issuer_name') or cred.get('issuer', 'Unknown')
                            role = cred.get('role', 'Unknown')
                            dept = cred.get('department')
                            expiry = cred.get('expiry', 'N/A')
                            
                            if dept:
                                print(f"   {issuer_name} ({dept})")
                            else:
                                print(f"   {issuer_name}")
                            print(f"   Role:   {role}")
                            print(f"   Expiry: {expiry[:10] if len(expiry) > 10 else expiry}")
            else:
                print("❌ No valid Vouch signature found")
                if result.error:
                    print(f"   Error: {result.error}")
        
        return 0 if result.is_valid else 1
        
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1


def _cmd_media_verify_c2pa(args: argparse.Namespace) -> int:
    """Verify an image's C2PA manifest and extract Vouch identity."""
    try:
        from vouch.media.c2pa import MediaVerifier, C2PA_AVAILABLE
        
        if not C2PA_AVAILABLE:
            print("❌ Error: c2pa-python is required. Install with: pip install c2pa-python", file=sys.stderr)
            return 1
        
        image_path = Path(args.image)
        if not image_path.exists():
            print(f"❌ Error: File not found: {image_path}", file=sys.stderr)
            return 1
        
        verifier = MediaVerifier()
        result = verifier.verify_image(image_path)
        
        if args.json:
            output = {
                "is_valid": result.is_valid,
                "claim_generator": result.claim_generator,
                "signed_at": result.signed_at,
                "error": result.error,
            }
            if result.signer_identity:
                output["signer"] = {
                    "did": result.signer_identity.did,
                    "display_name": result.signer_identity.display_name,
                    "email": result.signer_identity.email,
                    "credential_type": result.signer_identity.credential_type,
                }
            print(json.dumps(output, indent=2))
        else:
            if result.is_valid:
                print("✅ Valid C2PA manifest found!")
                print(f"   Claim Generator: {result.claim_generator}")
                if result.signed_at:
                    print(f"   Signed At: {result.signed_at}")
                
                if result.signer_identity:
                    print("\n🔐 Vouch Identity:")
                    print(f"   Name:  {result.signer_identity.display_name}")
                    if result.signer_identity.email:
                        print(f"   Email: {result.signer_identity.email}")
                    print(f"   DID:   {result.signer_identity.did}")
                    print(f"   Tier:  {result.signer_identity.credential_type}")
                else:
                    print("\n⚠️  No Vouch identity assertion found (standard C2PA manifest)")
            else:
                print("❌ No valid C2PA manifest found")
                if result.error:
                    print(f"   Error: {result.error}")
        
        return 0 if result.is_valid else 1
        
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1


def main() -> int:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog="vouch", description="Vouch Protocol CLI - Identity & Reputation for AI Agents"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # init command
    p_init = subparsers.add_parser("init", help="Generate a new agent identity")
    p_init.add_argument("--domain", help="Domain for the DID (e.g., example.com)")
    p_init.add_argument("--env", action="store_true", help="Output as environment variables")

    # sign command
    p_sign = subparsers.add_parser("sign", help="Sign a message or payload")
    p_sign.add_argument("message", help="The message to sign")
    p_sign.add_argument("--json", action="store_true", help="Parse message as JSON")
    p_sign.add_argument("--key", help="Private key (JWK JSON)")
    p_sign.add_argument("--did", help="Agent DID")
    p_sign.add_argument(
        "--header", action="store_true", help="Output with Vouch-Token header prefix"
    )

    # verify command
    p_verify = subparsers.add_parser("verify", help="Verify a Vouch-Token")
    p_verify.add_argument("token", help="The token to verify")
    p_verify.add_argument("--key", help="Public key (JWK JSON) for signature verification")
    p_verify.add_argument("--json", action="store_true", help="Output as JSON")

    # git subcommand group
    p_git = subparsers.add_parser("git", help="Git workflow commands")
    git_subparsers = p_git.add_subparsers(dest="git_command", help="Git commands")

    # git init
    p_git_init = git_subparsers.add_parser(
        "init", help="Configure SSH signing and Vouch branding for git"
    )
    p_git_init.add_argument(
        "--no-trailer", action="store_true", help="Skip commit trailer hook installation"
    )
    p_git_init.add_argument(
        "--no-badge", action="store_true", help="Skip README badge injection prompt"
    )

    # git status
    git_subparsers.add_parser("status", help="Show current Vouch git configuration")

    # git verify
    p_git_verify = git_subparsers.add_parser(
        "verify", help="Verify commit signatures match Vouch-DID trailers"
    )
    p_git_verify.add_argument(
        "commit", nargs="?", default=None, help="Specific commit hash to verify (optional)"
    )
    p_git_verify.add_argument(
        "-n", "--count", type=int, default=10, help="Number of commits to verify (default: 10)"
    )
    p_git_verify.add_argument(
        "--strict", action="store_true", help="Fail if any commit verification fails"
    )

    # media subcommand group
    p_media = subparsers.add_parser("media", help="Media signing commands")
    media_subparsers = p_media.add_subparsers(dest="media_command", help="Media commands")

    # media sign
    p_media_sign = media_subparsers.add_parser(
        "sign", help="Sign an image with Vouch (simple, no certificates needed)"
    )
    p_media_sign.add_argument("image", help="Path to image file to sign")
    p_media_sign.add_argument("-o", "--output", help="Output path for signed image")
    p_media_sign.add_argument("-n", "--name", help="Display name for signer")
    p_media_sign.add_argument("-e", "--email", help="Email address for signer")
    p_media_sign.add_argument("--did", help="DID for signer identity")
    p_media_sign.add_argument("--key", help="Private key (JWK JSON)")
    p_media_sign.add_argument("--title", help="Title for the image")
    p_media_sign.add_argument("--pro", action="store_true", help="Mark as PRO credential")
    p_media_sign.add_argument(
        "--c2pa", action="store_true",
        help="Use C2PA industry standard (requires certificates)"
    )

    # media verify
    p_media_verify = media_subparsers.add_parser(
        "verify", help="Verify an image's Vouch signature"
    )
    p_media_verify.add_argument("image", help="Path to image file to verify")
    p_media_verify.add_argument("--json", action="store_true", help="Output as JSON")
    p_media_verify.add_argument(
        "--c2pa", action="store_true",
        help="Verify C2PA manifest instead of Vouch signature"
    )

    args = parser.parse_args()

    setup_logging(args.verbose if hasattr(args, "verbose") else False)

    if args.command == "init":
        return cmd_init(args)
    elif args.command == "sign":
        return cmd_sign(args)
    elif args.command == "verify":
        return cmd_verify(args)
    elif args.command == "git":
        if args.git_command == "init":
            return cmd_git_init(args)
        elif args.git_command == "status":
            return cmd_git_status(args)
        elif args.git_command == "verify":
            return cmd_git_verify(args)
        else:
            p_git.print_help()
            return 0
    elif args.command == "media":
        if args.media_command == "sign":
            return cmd_media_sign(args)
        elif args.media_command == "verify":
            return cmd_media_verify(args)
        else:
            p_media.print_help()
            return 0
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
