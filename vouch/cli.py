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
        # Generate Ed25519 key
        key = jwk.JWK.generate(kty="OKP", crv="Ed25519")

        # Export keys
        private_key = key.export_private()
        public_key = key.export_public()

        # Build DID
        domain = args.domain if args.domain else "example.com"
        did = f"did:web:{domain}"

        if args.env:
            # Output as environment variable format
            print(f"export VOUCH_DID='{did}'")
            print(f"export VOUCH_PRIVATE_KEY='{private_key}'")
            print(f"# Public Key (for vouch.json): {public_key}", file=sys.stderr)
        else:
            print("🔑 NEW AGENT IDENTITY GENERATED\n")
            print(f"DID: {did}")
            print("\n--- PRIVATE KEY (Keep Secret / Set as Env Var) ---")
            print(private_key)
            print("\n--- PUBLIC KEY (Put this in vouch.json) ---")
            print(public_key)

        return 0

    except Exception as e:
        print(f"Error generating keys: {e}", file=sys.stderr)
        return 1


def cmd_sign(args: argparse.Namespace) -> int:
    """Sign a message or JSON payload."""
    # Get credentials
    private_key = args.key or os.environ.get("VOUCH_PRIVATE_KEY")
    did = args.did or os.environ.get("VOUCH_DID")

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
    private_key_json = os.environ.get("VOUCH_PRIVATE_KEY")
    did = os.environ.get("VOUCH_DID")

    if not private_key_json:
        # Generate new key if none exists
        key = jwk.JWK.generate(kty="OKP", crv="Ed25519")
        private_key_json = key.export_private()
        did = "did:vouch:" + hashlib.sha256(key.export_public().encode()).hexdigest()[:12]
    else:
        key = jwk.JWK.from_json(private_key_json)

    # Convert JWK to cryptography key for SSH export
    # Export the key as JSON and parse for 'd' parameter
    key_dict = json.loads(key.export_private())
    d_bytes = base64.urlsafe_b64decode(key_dict.get("d") + "==")

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
        else:
            p_git.print_help()
            return 0
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
