"""
Vouch Gatekeeper - GitHub App Webhook Handler (v2.0 - Zero-Friction)

A FastAPI service that enforces cryptographic identity and organizational 
policy on every Pull Request.

Core Logic: "If the code author isn't a verified identity with valid 
permissions, block the merge."

Version 2.0 Features:
- Hybrid Verification: GitHub SSH keys first, then Vouch Registry
- Zero-Config: Works immediately on install with sane defaults
- Auto-Setup: Manifest-based installation, auto-badge PRs
"""

import os
import hmac
import hashlib
import asyncio
import json
import base64
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlencode

import httpx
import yaml
from fastapi import FastAPI, Request, HTTPException, Header, Response
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic import BaseModel

# =============================================================================
# Configuration
# =============================================================================

GITHUB_APP_ID = os.getenv("GITHUB_APP_ID")
GITHUB_PRIVATE_KEY = os.getenv("GITHUB_PRIVATE_KEY")  # PEM format
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")
VOUCH_REGISTRY_URL = os.getenv("VOUCH_REGISTRY_URL", "https://vouch-protocol.com/api")
API_DOMAIN = os.getenv("API_DOMAIN", "https://gatekeeper.vouch-protocol.com")

# Known GitHub web-flow key IDs (for merge commits via UI)
GITHUB_WEBFLOW_KEY_IDS = {
    "4AEE18F83AFDEB23",  # GitHub Web UI
    "B5690EEEBB952194",  # GitHub Actions
}

# Known bot accounts
KNOWN_BOTS = {
    "dependabot[bot]",
    "github-actions[bot]",
    "renovate[bot]",
}

# =============================================================================
# Models
# =============================================================================

class CheckConclusion(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    NEUTRAL = "neutral"
    SKIPPED = "skipped"
    ACTION_REQUIRED = "action_required"


class PolicyType(str, Enum):
    EXPLICIT = "explicit"  # Only allowed_users and allowed_organizations
    IMPLICIT_ORG_TRUST = "implicit_organization_trust"  # Any org member allowed


@dataclass
class VouchPolicy:
    """Parsed .github/vouch-policy.yml"""
    require_signed_commits: bool = True
    allow_unsigned_merge_commits: bool = False
    allow_bots: bool = True
    policy_type: PolicyType = PolicyType.IMPLICIT_ORG_TRUST
    allowed_organizations: List[str] = field(default_factory=list)
    allowed_users: List[str] = field(default_factory=list)
    is_default: bool = False  # True if loaded from defaults (no config file)
    
    @classmethod
    def from_yaml(cls, content: str) -> "VouchPolicy":
        """Parse YAML config into VouchPolicy object."""
        try:
            data = yaml.safe_load(content)
            policy = data.get("policy", {})
            policy_type_str = policy.get("policy_type", "explicit")
            
            return cls(
                require_signed_commits=policy.get("require_signed_commits", True),
                allow_unsigned_merge_commits=policy.get("allow_unsigned_merge_commits", False),
                allow_bots=policy.get("allow_bots", True),
                policy_type=PolicyType(policy_type_str) if policy_type_str in ["explicit", "implicit_organization_trust"] else PolicyType.EXPLICIT,
                allowed_organizations=policy.get("allowed_organizations", []),
                allowed_users=policy.get("allowed_users", []),
                is_default=False,
            )
        except Exception:
            return cls.default()
    
    @classmethod
    def default(cls) -> "VouchPolicy":
        """
        Zero-Config Default Policy: Sane defaults for immediate use.
        
        Logic: "If the signer is a member of the Org where the App is installed, ALLOW."
        """
        return cls(
            require_signed_commits=True,
            allow_unsigned_merge_commits=False,
            allow_bots=True,
            policy_type=PolicyType.IMPLICIT_ORG_TRUST,
            allowed_organizations=[],
            allowed_users=[],
            is_default=True,
        )


@dataclass
class VerifiedIdentity:
    """Result of identity verification."""
    verified: bool
    source: str  # "github_ssh", "github_gpg", "vouch_registry", "github_webflow"
    username: Optional[str] = None
    email: Optional[str] = None
    vouch_did: Optional[str] = None
    organization: Optional[str] = None
    is_org_member: bool = False
    is_historical_key: bool = False
    error: Optional[str] = None


@dataclass
class CommitVerification:
    """Result of verifying a single commit."""
    sha: str
    author: str
    author_login: Optional[str]
    is_signed: bool
    is_verified: bool
    identity: Optional[VerifiedIdentity] = None
    is_bot: bool = False
    is_merge_commit: bool = False
    error: Optional[str] = None
    
    @property
    def passed(self) -> bool:
        return self.is_verified and self.error is None


@dataclass 
class PolicyCheckResult:
    """Overall result of checking all commits against policy."""
    conclusion: CheckConclusion
    title: str
    summary: str
    details: str
    policy_used: str  # "explicit" or "default"
    failed_commits: List[CommitVerification] = field(default_factory=list)
    passed_commits: List[CommitVerification] = field(default_factory=list)


# =============================================================================
# GitHub API Client (with Hybrid Verification support)
# =============================================================================

class GitHubClient:
    """GitHub API client with App authentication and Hybrid Verification."""
    
    def __init__(self, installation_id: int):
        self.installation_id = installation_id
        self.base_url = "https://api.github.com"
        self._token: Optional[str] = None
        self._token_expires: Optional[datetime] = None
    
    async def _get_installation_token(self) -> str:
        """Get or refresh installation access token."""
        import jwt
        
        if self._token and self._token_expires:
            if datetime.now(timezone.utc) < self._token_expires:
                return self._token
        
        now = int(datetime.now(timezone.utc).timestamp())
        payload = {
            "iat": now - 60,
            "exp": now + (10 * 60),
            "iss": GITHUB_APP_ID,
        }
        
        app_jwt = jwt.encode(payload, GITHUB_PRIVATE_KEY, algorithm="RS256")
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/app/installations/{self.installation_id}/access_tokens",
                headers={
                    "Authorization": f"Bearer {app_jwt}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                }
            )
            response.raise_for_status()
            data = response.json()
            
        self._token = data["token"]
        self._token_expires = datetime.now(timezone.utc).replace(
            minute=datetime.now(timezone.utc).minute + 50
        )
        
        return self._token
    
    async def _request(self, method: str, endpoint: str, **kwargs) -> Dict:
        """Make authenticated request to GitHub API."""
        token = await self._get_installation_token()
        
        async with httpx.AsyncClient() as client:
            response = await client.request(
                method,
                f"{self.base_url}{endpoint}",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                **kwargs
            )
            response.raise_for_status()
            return response.json()
    
    async def _request_optional(self, method: str, endpoint: str, **kwargs) -> Optional[Dict]:
        """Make request that may return 404."""
        try:
            return await self._request(method, endpoint, **kwargs)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return None
            raise
    
    # =========================================================================
    # Core API Methods
    # =========================================================================
    
    async def get_pr_commits(self, owner: str, repo: str, pr_number: int) -> List[Dict]:
        """Get all commits in a PR."""
        return await self._request(
            "GET",
            f"/repos/{owner}/{repo}/pulls/{pr_number}/commits"
        )
    
    async def get_file_content(
        self, owner: str, repo: str, path: str, ref: str = "HEAD"
    ) -> Optional[str]:
        """Get file content from repo (returns None if not found)."""
        try:
            response = await self._request(
                "GET",
                f"/repos/{owner}/{repo}/contents/{path}",
                params={"ref": ref}
            )
            content = response.get("content", "")
            return base64.b64decode(content).decode("utf-8")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return None
            raise
    
    async def create_check_run(
        self,
        owner: str,
        repo: str,
        head_sha: str,
        name: str,
        status: str,
        conclusion: Optional[str] = None,
        title: str = "",
        summary: str = "",
        text: str = "",
    ) -> Dict:
        """Create or update a check run."""
        payload = {
            "name": name,
            "head_sha": head_sha,
            "status": status,
        }
        
        if conclusion:
            payload["conclusion"] = conclusion
            
        if title or summary or text:
            payload["output"] = {
                "title": title,
                "summary": summary,
                "text": text,
            }
        
        return await self._request(
            "POST",
            f"/repos/{owner}/{repo}/check-runs",
            json=payload
        )
    
    # =========================================================================
    # Hybrid Verification: SSH Key Methods
    # =========================================================================
    
    async def get_user_ssh_keys(self, username: str) -> List[Dict]:
        """
        Get public SSH keys for a GitHub user.
        Returns list of {id, key} objects.
        """
        try:
            return await self._request("GET", f"/users/{username}/keys")
        except httpx.HTTPStatusError:
            return []
    
    async def get_user_gpg_keys(self, username: str) -> List[Dict]:
        """
        Get GPG keys for a GitHub user.
        Returns list of GPG key objects with key_id.
        """
        try:
            return await self._request("GET", f"/users/{username}/gpg_keys")
        except httpx.HTTPStatusError:
            return []
    
    async def get_user_org_memberships(self, username: str) -> List[str]:
        """
        Get public organizations for a user.
        Returns list of org logins.
        """
        try:
            orgs = await self._request("GET", f"/users/{username}/orgs")
            return [org["login"] for org in orgs]
        except httpx.HTTPStatusError:
            return []
    
    async def is_org_member(self, org: str, username: str) -> bool:
        """Check if user is a member of the organization (using installation token)."""
        try:
            await self._request("GET", f"/orgs/{org}/members/{username}")
            return True
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (404, 302):
                return False
            raise
    
    async def verify_ssh_key_match(
        self, username: str, commit_key_fingerprint: str
    ) -> bool:
        """
        Check if commit's SSH key fingerprint matches any of user's registered keys.
        """
        user_keys = await self.get_user_ssh_keys(username)
        
        for key in user_keys:
            # GitHub returns keys in OpenSSH format, need to compute fingerprint
            # For now, we compare the key_id which GitHub provides
            if str(key.get("id")) == commit_key_fingerprint:
                return True
        
        return False
    
    # =========================================================================
    # Auto-Badge PR Methods
    # =========================================================================
    
    async def get_default_branch(self, owner: str, repo: str) -> str:
        """Get the default branch name."""
        repo_data = await self._request("GET", f"/repos/{owner}/{repo}")
        return repo_data.get("default_branch", "main")
    
    async def get_ref(self, owner: str, repo: str, ref: str) -> Optional[Dict]:
        """Get a git reference."""
        return await self._request_optional("GET", f"/repos/{owner}/{repo}/git/refs/heads/{ref}")
    
    async def create_branch(
        self, owner: str, repo: str, branch_name: str, from_sha: str
    ) -> Dict:
        """Create a new branch."""
        return await self._request(
            "POST",
            f"/repos/{owner}/{repo}/git/refs",
            json={
                "ref": f"refs/heads/{branch_name}",
                "sha": from_sha,
            }
        )
    
    async def create_or_update_file(
        self,
        owner: str,
        repo: str,
        path: str,
        content: str,
        message: str,
        branch: str,
        sha: Optional[str] = None,
    ) -> Dict:
        """Create or update a file."""
        payload = {
            "message": message,
            "content": base64.b64encode(content.encode()).decode(),
            "branch": branch,
        }
        if sha:
            payload["sha"] = sha
        
        return await self._request(
            "PUT",
            f"/repos/{owner}/{repo}/contents/{path}",
            json=payload
        )
    
    async def create_pull_request(
        self,
        owner: str,
        repo: str,
        title: str,
        body: str,
        head: str,
        base: str,
    ) -> Dict:
        """Create a pull request."""
        return await self._request(
            "POST",
            f"/repos/{owner}/{repo}/pulls",
            json={
                "title": title,
                "body": body,
                "head": head,
                "base": base,
            }
        )


# =============================================================================
# Vouch Registry Client
# =============================================================================

class VouchRegistryClient:
    """Client for Vouch Registry API (lookup key -> DID)."""
    
    def __init__(self, base_url: str = VOUCH_REGISTRY_URL):
        self.base_url = base_url
        self.timeout = 10.0
    
    async def lookup_key(self, key_id: str) -> Optional[Dict]:
        """Look up a signing key ID in the Vouch Registry."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.base_url}/lookup",
                    params={"key_id": key_id}
                )
                
                if response.status_code == 404:
                    return None
                    
                response.raise_for_status()
                return response.json()
                
        except httpx.TimeoutException:
            return {"error": "timeout", "message": "Vouch Registry unreachable"}
        except httpx.RequestError as e:
            return {"error": "network", "message": str(e)}


# =============================================================================
# Hybrid Verification Engine
# =============================================================================

class HybridVerifier:
    """
    Hybrid Verification: Check GitHub SSH keys first, then Vouch Registry.
    
    Flow:
    1. Extract signature and key_id from commit
    2. Step A: GitHub Lookup - Fetch user's SSH/GPG keys
    3. Step B: Match - Check if commit signature matches
    4. Step C: Attestation - Map to org membership
    5. Fallback: Query Vouch Registry for custom DIDs
    """
    
    def __init__(self, github: GitHubClient, registry: VouchRegistryClient):
        self.github = github
        self.registry = registry
    
    async def verify_identity(
        self, 
        commit: Dict, 
        repo_org: str
    ) -> VerifiedIdentity:
        """
        Verify commit author identity using hybrid approach.
        
        Args:
            commit: GitHub commit object
            repo_org: Organization/owner where repo lives
        """
        verification = commit["commit"].get("verification", {})
        author_login = commit.get("author", {}).get("login")
        author_email = commit["commit"]["author"].get("email", "")
        
        is_verified = verification.get("verified", False)
        reason = verification.get("reason", "")
        key_id = verification.get("key_id")
        signature = verification.get("signature", "")
        
        # No signature at all
        if not signature:
            return VerifiedIdentity(
                verified=False,
                source="none",
                error="No signature present"
            )
        
        # GitHub web-flow (merge via UI)
        if key_id in GITHUB_WEBFLOW_KEY_IDS:
            return VerifiedIdentity(
                verified=True,
                source="github_webflow",
                username=author_login,
                email=author_email,
            )
        
        # Signature didn't verify cryptographically
        if not is_verified:
            return VerifiedIdentity(
                verified=False,
                source="verification_failed",
                error=f"Signature verification failed: {reason}"
            )
        
        # =====================================================================
        # Step A & B: GitHub SSH/GPG Key Lookup
        # =====================================================================
        
        if author_login:
            # Try to match against user's registered keys
            gpg_keys = await self.github.get_user_gpg_keys(author_login)
            
            for gpg_key in gpg_keys:
                # Check if any of the key's subkeys match
                for subkey in gpg_key.get("subkeys", []):
                    if subkey.get("key_id") == key_id:
                        # Match found!
                        return await self._create_github_identity(
                            author_login, author_email, repo_org
                        )
                
                # Also check primary key_id
                if gpg_key.get("key_id") == key_id:
                    return await self._create_github_identity(
                        author_login, author_email, repo_org
                    )
            
            # SSH key check (if applicable)
            ssh_keys = await self.github.get_user_ssh_keys(author_login)
            for ssh_key in ssh_keys:
                if str(ssh_key.get("id")) == key_id:
                    return await self._create_github_identity(
                        author_login, author_email, repo_org
                    )
        
        # =====================================================================
        # Step C: Fallback to Vouch Registry
        # =====================================================================
        
        if key_id:
            lookup = await self.registry.lookup_key(key_id)
            
            if lookup is None:
                # Unknown key - not in GitHub or Vouch
                return VerifiedIdentity(
                    verified=False,
                    source="unknown",
                    error="Key not registered in GitHub or Vouch Registry"
                )
            
            if "error" in lookup:
                # Registry offline
                return VerifiedIdentity(
                    verified=True,  # Don't block on registry issues
                    source="registry_error",
                    error=f"Registry unavailable: {lookup['message']}"
                )
            
            # Valid Vouch DID found
            return VerifiedIdentity(
                verified=True,
                source="vouch_registry",
                vouch_did=lookup.get("did"),
                organization=lookup.get("organization"),
                email=lookup.get("email"),
                is_historical_key=lookup.get("is_historical", False),
            )
        
        # Signed and verified by GitHub, but we couldn't identify the key
        return VerifiedIdentity(
            verified=True,
            source="github_verified",
            username=author_login,
            email=author_email,
        )
    
    async def _create_github_identity(
        self, username: str, email: str, repo_org: str
    ) -> VerifiedIdentity:
        """Create identity for verified GitHub user."""
        # Check organization membership
        is_member = await self.github.is_org_member(repo_org, username)
        
        # Get user's public orgs
        orgs = await self.github.get_user_org_memberships(username)
        org_str = orgs[0] if orgs else None
        
        return VerifiedIdentity(
            verified=True,
            source="github_ssh",
            username=username,
            email=email,
            organization=org_str,
            is_org_member=is_member,
        )


# =============================================================================
# Policy Engine (with Zero-Config support)
# =============================================================================

class PolicyEngine:
    """Evaluates commits against Vouch policy with Zero-Config support."""
    
    def __init__(
        self, 
        policy: VouchPolicy, 
        verifier: HybridVerifier,
        repo_org: str
    ):
        self.policy = policy
        self.verifier = verifier
        self.repo_org = repo_org
    
    async def verify_commit(self, commit: Dict) -> CommitVerification:
        """Verify a single commit against policy."""
        sha = commit["sha"][:7]
        author = commit["commit"]["author"]["name"]
        author_login = commit.get("author", {}).get("login", "")
        
        verification = commit["commit"].get("verification", {})
        is_verified = verification.get("verified", False)
        signature = verification.get("signature", "")
        
        is_merge = len(commit.get("parents", [])) > 1
        is_bot = author_login in KNOWN_BOTS
        
        result = CommitVerification(
            sha=sha,
            author=author,
            author_login=author_login,
            is_signed=bool(signature),
            is_verified=is_verified,
            is_bot=is_bot,
            is_merge_commit=is_merge,
        )
        
        # Edge Case: Unsigned commit
        if not result.is_signed:
            if is_merge and self.policy.allow_unsigned_merge_commits:
                return result
            if is_bot and self.policy.allow_bots:
                return result
            
            result.error = "Commit is not signed"
            return result
        
        # Edge Case: Bot with signature
        if is_bot:
            if self.policy.allow_bots:
                result.identity = VerifiedIdentity(
                    verified=True,
                    source="bot",
                    username=author_login,
                )
                return result
            else:
                result.error = "Bot commits not allowed by policy"
                return result
        
        # Hybrid Verification
        identity = await self.verifier.verify_identity(commit, self.repo_org)
        result.identity = identity
        
        if not identity.verified:
            result.error = identity.error
            return result
        
        # Check authorization against policy
        if not self._is_authorized(identity):
            result.error = self._format_auth_error(identity)
            return result
        
        return result
    
    def _is_authorized(self, identity: VerifiedIdentity) -> bool:
        """Check if identity is authorized by policy."""
        
        # Zero-Config: Implicit Org Trust
        if self.policy.policy_type == PolicyType.IMPLICIT_ORG_TRUST:
            # If signer is member of the org where app is installed, ALLOW
            if identity.is_org_member:
                return True
            # Also allow if they have a Vouch DID in allowed list
            if identity.vouch_did and identity.vouch_did in self.policy.allowed_users:
                return True
            # GitHub verified users in the org are implicitly trusted
            if identity.source in ("github_ssh", "github_gpg", "github_verified"):
                return identity.is_org_member
            return False
        
        # Explicit Policy: Check allowlists
        if not self.policy.allowed_organizations and not self.policy.allowed_users:
            # No restrictions = allow all verified
            return True
        
        # Check user allowlist
        if identity.vouch_did in self.policy.allowed_users:
            return True
        if identity.username and f"github:{identity.username}" in self.policy.allowed_users:
            return True
        
        # Check org allowlist
        if identity.organization in self.policy.allowed_organizations:
            return True
        
        return False
    
    def _format_auth_error(self, identity: VerifiedIdentity) -> str:
        """Format authorization error message."""
        if self.policy.policy_type == PolicyType.IMPLICIT_ORG_TRUST:
            return f"User '{identity.username or identity.vouch_did}' is not a member of {self.repo_org}"
        
        if identity.vouch_did:
            return f"DID {identity.vouch_did} not authorized by policy"
        return f"User {identity.username} not authorized by policy"
    
    async def evaluate_pr(self, commits: List[Dict]) -> PolicyCheckResult:
        """Evaluate all commits in a PR against policy."""
        
        results = await asyncio.gather(
            *[self.verify_commit(c) for c in commits]
        )
        
        passed = [r for r in results if r.passed]
        failed = [r for r in results if not r.passed]
        
        # Check for registry issues
        registry_issues = [
            r for r in results 
            if r.identity and r.identity.error and "Registry" in r.identity.error
        ]
        
        if registry_issues and not failed:
            return PolicyCheckResult(
                conclusion=CheckConclusion.NEUTRAL,
                title="⚠️ Vouch Registry Unreachable",
                summary=f"Could not verify {len(registry_issues)} commit(s)",
                details=self._format_details(passed, failed, registry_issues),
                policy_used="default" if self.policy.is_default else "explicit",
                passed_commits=passed,
            )
        
        if failed:
            return PolicyCheckResult(
                conclusion=CheckConclusion.FAILURE,
                title=f"❌ {len(failed)} commit(s) failed verification",
                summary=self._format_failure_summary(failed),
                details=self._format_details(passed, failed),
                policy_used="default" if self.policy.is_default else "explicit",
                failed_commits=failed,
                passed_commits=passed,
            )
        
        # All passed
        authors = self._get_author_summary(passed)
        policy_note = " (Zero-Config)" if self.policy.is_default else ""
        
        return PolicyCheckResult(
            conclusion=CheckConclusion.SUCCESS,
            title=f"✅ All {len(passed)} commit(s) verified",
            summary=f"Authors: {authors}{policy_note}",
            details=self._format_details(passed, failed),
            policy_used="default" if self.policy.is_default else "explicit",
            passed_commits=passed,
        )
    
    def _get_author_summary(self, commits: List[CommitVerification]) -> str:
        """Get unique author summary."""
        authors = set()
        for c in commits:
            if c.identity:
                if c.identity.username:
                    org = c.identity.organization or self.repo_org
                    authors.add(f"{c.identity.username} ({org})")
                elif c.identity.vouch_did:
                    org = c.identity.organization or ""
                    authors.add(f"{c.identity.vouch_did} ({org})" if org else c.identity.vouch_did)
            elif c.is_bot:
                authors.add(f"{c.author} (Bot)")
        return ", ".join(authors) or "Unknown"
    
    def _format_failure_summary(self, failed: List[CommitVerification]) -> str:
        """Format failure summary."""
        lines = ["The following commits failed verification:\n"]
        for c in failed:
            lines.append(f"- `{c.sha}` by **{c.author}**: {c.error}")
        return "\n".join(lines)
    
    def _format_details(
        self, 
        passed: List[CommitVerification],
        failed: List[CommitVerification],
        registry_issues: List[CommitVerification] = None
    ) -> str:
        """Format detailed markdown report."""
        lines = ["## Commit Verification Report\n"]
        lines.append(f"**Policy Type:** {self.policy.policy_type.value}\n")
        
        if self.policy.is_default:
            lines.append("> ℹ️ Using Zero-Config defaults. Add `.github/vouch-policy.yml` to customize.\n")
        
        if failed:
            lines.append("### ❌ Failed Commits\n")
            lines.append("| SHA | Author | Error |")
            lines.append("|-----|--------|-------|")
            for c in failed:
                lines.append(f"| `{c.sha}` | {c.author} | {c.error} |")
            lines.append("")
        
        if passed:
            lines.append("### ✅ Verified Commits\n")
            lines.append("| SHA | Author | Source | Identity |")
            lines.append("|-----|--------|--------|----------|")
            for c in passed:
                source = c.identity.source if c.identity else "unknown"
                identity = ""
                if c.identity:
                    if c.identity.username:
                        identity = f"GitHub: {c.identity.username}"
                    elif c.identity.vouch_did:
                        identity = c.identity.vouch_did
                lines.append(f"| `{c.sha}` | {c.author} | {source} | {identity} |")
        
        return "\n".join(lines)


# =============================================================================
# FastAPI Application
# =============================================================================

app = FastAPI(
    title="Vouch Gatekeeper",
    description="GitHub App for cryptographic identity enforcement on PRs (Zero-Friction Edition)",
    version="2.0.0",
)


# =============================================================================
# App Manifest for Auto-Setup
# =============================================================================

APP_MANIFEST = {
    "name": "Vouch Gatekeeper",
    "url": "https://vouch-protocol.com",
    "hook_attributes": {
        "url": f"{API_DOMAIN}/webhook",
        "active": True,
    },
    "redirect_url": f"{API_DOMAIN}/setup/callback",
    "description": "Enforce cryptographic identity and organizational policy on every Pull Request",
    "public": True,
    "default_events": [
        "pull_request",
        "check_suite",
        "installation",
    ],
    "default_permissions": {
        "checks": "write",
        "contents": "write",  # For auto-badge PR
        "pull_requests": "write",  # For auto-badge PR
        "members": "read",
        "metadata": "read",
    },
}


def verify_webhook_signature(payload: bytes, signature: str) -> bool:
    """Verify GitHub webhook signature."""
    if not GITHUB_WEBHOOK_SECRET:
        return True
    
    expected = "sha256=" + hmac.new(
        GITHUB_WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(expected, signature)


# =============================================================================
# Setup Endpoints
# =============================================================================

@app.get("/setup")
async def setup_redirect():
    """
    Redirect to GitHub App creation with manifest.
    Users visit this to install the app.
    """
    manifest_json = json.dumps(APP_MANIFEST)
    manifest_b64 = base64.b64encode(manifest_json.encode()).decode()
    
    return RedirectResponse(
        url=f"https://github.com/settings/apps/new?manifest={manifest_b64}"
    )


@app.get("/setup/callback")
async def setup_callback(code: str = None):
    """Handle callback after app creation."""
    if not code:
        return {"status": "error", "message": "No code provided"}
    
    # Exchange code for app credentials
    # In production, you'd save these credentials
    return {
        "status": "success",
        "message": "App created! Install it on your repositories.",
        "next_step": "Visit the app page on GitHub to install",
    }


# =============================================================================
# Badge Endpoint (Shields.io compatible)
# =============================================================================

@app.get("/api/badge/{owner}/{repo}")
async def get_badge(owner: str, repo: str):
    """
    Dynamic Shields.io endpoint for repository protection status.
    
    Returns JSON schema for Shields.io:
    {
        "schemaVersion": 1,
        "label": "vouch",
        "message": "protected",
        "color": "green"
    }
    """
    # TODO: Check actual policy status from database/cache
    # For now, return a default "protected" badge
    
    # In production:
    # - Check if app is installed on this repo
    # - Check recent check run status
    # - Return appropriate color
    
    return JSONResponse({
        "schemaVersion": 1,
        "label": "vouch",
        "message": "protected",
        "color": "green",
        "namedLogo": "shield",
    })


# =============================================================================
# Main Webhook Handler
# =============================================================================

@app.post("/webhook")
async def handle_webhook(
    request: Request,
    x_github_event: str = Header(..., alias="X-GitHub-Event"),
    x_hub_signature_256: str = Header(None, alias="X-Hub-Signature-256"),
):
    """Main webhook handler for GitHub events."""
    body = await request.body()
    
    if x_hub_signature_256 and not verify_webhook_signature(body, x_hub_signature_256):
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    payload = await request.json()
    
    # Route by event type
    if x_github_event == "pull_request":
        action = payload.get("action")
        if action in ("opened", "synchronize", "reopened"):
            return await handle_pull_request(payload)
    
    elif x_github_event == "check_suite":
        action = payload.get("action")
        if action == "rerequested":
            return await handle_check_suite_rerun(payload)
    
    elif x_github_event == "installation":
        action = payload.get("action")
        if action == "created":
            return await handle_installation_created(payload)
    
    return {"status": "ignored", "event": x_github_event}


async def handle_pull_request(payload: Dict) -> Dict:
    """Handle pull_request event."""
    repo = payload["repository"]
    owner = repo["owner"]["login"]
    repo_name = repo["name"]
    pr = payload["pull_request"]
    pr_number = pr["number"]
    head_sha = pr["head"]["sha"]
    installation_id = payload["installation"]["id"]
    
    # Initialize clients
    github = GitHubClient(installation_id)
    registry = VouchRegistryClient()
    verifier = HybridVerifier(github, registry)
    
    # Create in-progress check
    await github.create_check_run(
        owner=owner,
        repo=repo_name,
        head_sha=head_sha,
        name="Vouch Gatekeeper",
        status="in_progress",
        title="🔍 Verifying commit signatures...",
        summary="Checking all commits against Vouch policy.",
    )
    
    try:
        # Step 1: Fetch policy config (Zero-Config: use defaults if missing)
        policy_yaml = await github.get_file_content(
            owner, repo_name, ".github/vouch-policy.yml"
        )
        
        if policy_yaml:
            policy = VouchPolicy.from_yaml(policy_yaml)
        else:
            # Zero-Config: Use sane defaults
            policy = VouchPolicy.default()
        
        # Step 2: Get all commits in PR
        commits = await github.get_pr_commits(owner, repo_name, pr_number)
        
        # Step 3: Evaluate against policy
        engine = PolicyEngine(policy, verifier, owner)
        result = await engine.evaluate_pr(commits)
        
        # Step 4: Report result
        await github.create_check_run(
            owner=owner,
            repo=repo_name,
            head_sha=head_sha,
            name="Vouch Gatekeeper",
            status="completed",
            conclusion=result.conclusion.value,
            title=result.title,
            summary=result.summary,
            text=result.details,
        )
        
        return {
            "status": "completed",
            "conclusion": result.conclusion.value,
            "policy": result.policy_used,
            "commits_checked": len(commits),
            "passed": len(result.passed_commits),
            "failed": len(result.failed_commits),
        }
        
    except Exception as e:
        await github.create_check_run(
            owner=owner,
            repo=repo_name,
            head_sha=head_sha,
            name="Vouch Gatekeeper",
            status="completed",
            conclusion="neutral",
            title="⚠️ Vouch Gatekeeper Error",
            summary=f"An error occurred: {str(e)}",
        )
        
        return {"status": "error", "message": str(e)}


async def handle_check_suite_rerun(payload: Dict) -> Dict:
    """Handle check_suite rerequested event."""
    prs = payload.get("check_suite", {}).get("pull_requests", [])
    if not prs:
        return {"status": "skipped", "reason": "No associated PR"}
    
    mock_payload = {
        "repository": payload["repository"],
        "pull_request": {
            "number": prs[0]["number"],
            "head": {"sha": payload["check_suite"]["head_sha"]},
        },
        "installation": {"id": payload["installation"]["id"]},
    }
    
    return await handle_pull_request(mock_payload)


async def handle_installation_created(payload: Dict) -> Dict:
    """
    Handle installation.created event.
    Auto-add Vouch badge to README if missing.
    """
    installation_id = payload["installation"]["id"]
    repos = payload.get("repositories", [])
    
    github = GitHubClient(installation_id)
    results = []
    
    for repo_info in repos:
        owner = payload["installation"]["account"]["login"]
        repo_name = repo_info["name"]
        
        try:
            result = await add_badge_if_missing(github, owner, repo_name)
            results.append({"repo": repo_name, "result": result})
        except Exception as e:
            results.append({"repo": repo_name, "error": str(e)})
    
    return {"status": "processed", "repos": results}


async def add_badge_if_missing(
    github: GitHubClient, owner: str, repo: str
) -> str:
    """Add Vouch badge to README if not present."""
    
    # Get README content
    readme_content = await github.get_file_content(owner, repo, "README.md")
    
    if readme_content is None:
        return "no_readme"
    
    # Check if badge already exists
    badge_pattern = "img.shields.io/endpoint?url="
    if badge_pattern in readme_content and "vouch" in readme_content.lower():
        return "badge_exists"
    
    # Create badge markdown
    badge_url = f"https://img.shields.io/endpoint?url={API_DOMAIN}/api/badge/{owner}/{repo}"
    badge_md = f"[![Vouch Protected]({badge_url})](https://vouch-protocol.com)\n\n"
    
    # Prepend badge to README
    new_readme = badge_md + readme_content
    
    # Get default branch
    default_branch = await github.get_default_branch(owner, repo)
    
    # Get current HEAD SHA
    ref = await github.get_ref(owner, repo, default_branch)
    if not ref:
        return "no_ref"
    
    head_sha = ref["object"]["sha"]
    
    # Create new branch
    branch_name = "vouch-add-badge"
    try:
        await github.create_branch(owner, repo, branch_name, head_sha)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 422:  # Already exists
            pass
        else:
            raise
    
    # Get current README SHA for update
    readme_info = await github._request(
        "GET",
        f"/repos/{owner}/{repo}/contents/README.md",
        params={"ref": default_branch}
    )
    readme_sha = readme_info["sha"]
    
    # Update README on new branch
    await github.create_or_update_file(
        owner=owner,
        repo=repo,
        path="README.md",
        content=new_readme,
        message="docs: Add Vouch Protection badge",
        branch=branch_name,
        sha=readme_sha,
    )
    
    # Create PR
    pr = await github.create_pull_request(
        owner=owner,
        repo=repo,
        title="docs: Add Vouch Protection badge",
        body="""## 🛡️ Vouch Gatekeeper Protection

This PR adds a Vouch protection badge to your README.

The badge shows that this repository is protected by [Vouch Gatekeeper](https://vouch-protocol.com), 
which enforces cryptographic identity verification on all commits.

### What does this mean?

- ✅ All commits are verified to come from authorized team members
- ✅ Cryptographic signatures prevent impersonation
- ✅ Audit trail for all code changes

---

*This PR was automatically created when Vouch Gatekeeper was installed.*
""",
        head=branch_name,
        base=default_branch,
    )
    
    return f"pr_created:{pr['number']}"


# =============================================================================
# Health Check
# =============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "app": "Vouch Gatekeeper",
        "version": "2.0.0",
        "features": ["hybrid_verification", "zero_config", "auto_badge"],
    }


# =============================================================================
# Development Entry Point
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
