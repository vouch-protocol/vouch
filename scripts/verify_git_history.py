#!/usr/bin/env python3
"""
Vouch Git History Verification Script.

Verifies that commits contain Vouch-DID trailers for supply chain security.
Used in CI to enforce Vouch signing on pull requests.
"""

import subprocess
import sys
import re


def get_recent_commits(count: int = 10) -> list[dict]:
    """Get the last N commits with their messages."""
    result = subprocess.run(
        ["git", "log", f"-{count}", "--format=%H%n%B%n---COMMIT_END---"],
        capture_output=True,
        text=True,
    )
    
    if result.returncode != 0:
        print(f"Error getting git log: {result.stderr}", file=sys.stderr)
        return []
    
    commits = []
    current_hash = None
    current_message = []
    
    for line in result.stdout.split("\n"):
        if line == "---COMMIT_END---":
            if current_hash:
                commits.append({
                    "hash": current_hash,
                    "message": "\n".join(current_message).strip()
                })
            current_hash = None
            current_message = []
        elif current_hash is None:
            current_hash = line.strip()
        else:
            current_message.append(line)
    
    return commits


def verify_vouch_trailer(message: str) -> tuple[bool, str | None]:
    """
    Check if a commit message contains a Vouch-DID trailer.
    
    Returns:
        Tuple of (has_trailer, did_value)
    """
    # Look for Vouch-DID trailer
    match = re.search(r"Vouch-DID:\s*(\S+)", message)
    if match:
        return True, match.group(1)
    return False, None


def main() -> int:
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Verify Vouch trailers in git history")
    parser.add_argument(
        "-n", "--count", type=int, default=10,
        help="Number of commits to check (default: 10)"
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="Fail if any commit is missing Vouch-DID trailer"
    )
    parser.add_argument(
        "--report", action="store_true",
        help="Print detailed report"
    )
    
    args = parser.parse_args()
    
    commits = get_recent_commits(args.count)
    
    if not commits:
        print("No commits found to verify")
        return 0
    
    verified = 0
    unverified = 0
    
    print(f"🔍 Verifying last {len(commits)} commits...\n")
    
    for commit in commits:
        short_hash = commit["hash"][:8]
        has_trailer, did = verify_vouch_trailer(commit["message"])
        
        # Get first line of commit message
        first_line = commit["message"].split("\n")[0][:50]
        
        if has_trailer:
            verified += 1
            if args.report:
                print(f"  ✅ {short_hash} - {first_line}")
                print(f"     Vouch-DID: {did}")
        else:
            unverified += 1
            if args.report:
                print(f"  ❌ {short_hash} - {first_line}")
                print("     No Vouch-DID trailer")
    
    print(f"\n📊 Results: {verified}/{len(commits)} commits have Vouch-DID trailers")
    
    if args.strict and unverified > 0:
        print(f"\n❌ FAILED: {unverified} commit(s) missing Vouch-DID trailer")
        return 1
    
    if verified == len(commits):
        print("\n✅ All commits verified!")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
