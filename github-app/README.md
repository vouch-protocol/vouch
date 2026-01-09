# Vouch Gatekeeper - GitHub App (v2.0 - Zero-Friction)

**Enforce cryptographic identity and organizational policy on every Pull Request.**

Core Logic: *"If the code author isn't a verified identity with valid permissions, block the merge."*

## 🚀 Zero-Friction Features (v2.0)

| Feature | Description |
|---------|-------------|
| **Hybrid Verification** | GitHub SSH/GPG keys first, then Vouch Registry |
| **Zero-Config** | Works immediately on install - no YAML needed |
| **Auto-Setup** | One-click install via GitHub App Manifest |
| **Auto-Badge** | Automatically opens PR to add protection badge |

---

## Quick Start

### Option 1: One-Click Install (Recommended)

Visit: **`https://gatekeeper.vouch-protocol.com/setup`**

This redirects to GitHub with pre-configured manifest. Click install!

### Option 2: Manual Setup

```bash
# Install dependencies
pip install -e .

# Set environment variables
cp .env.example .env
# Edit .env with your GitHub App credentials

# Run locally
uvicorn main:app --reload --port 8000
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 VOUCH GATEKEEPER v2.0                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              HYBRID VERIFICATION                      │  │
│  │                                                       │  │
│  │   Commit Signature                                    │  │
│  │         │                                             │  │
│  │         ▼                                             │  │
│  │   ┌─────────────┐    ┌─────────────┐                 │  │
│  │   │  GitHub     │ ──▶│  Vouch      │                 │  │
│  │   │  SSH/GPG    │    │  Registry   │                 │  │
│  │   │  Lookup     │    │  (Fallback) │                 │  │
│  │   └─────────────┘    └─────────────┘                 │  │
│  │         │                   │                         │  │
│  │         ▼                   ▼                         │  │
│  │   "GitHub User: alice"  "DID: did:vouch:bob"         │  │
│  │                                                       │  │
│  └──────────────────────────────────────────────────────┘  │
│                           │                                 │
│                           ▼                                 │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              POLICY ENGINE                            │  │
│  │                                                       │  │
│  │   Zero-Config Default:                                │  │
│  │   "If signer is org member → ALLOW"                   │  │
│  │                                                       │  │
│  │   Explicit Policy (.github/vouch-policy.yml):         │  │
│  │   "Only allowed_organizations/allowed_users → ALLOW"  │  │
│  │                                                       │  │
│  └──────────────────────────────────────────────────────┘  │
│                           │                                 │
│                           ▼                                 │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              REPORTER                                 │  │
│  │                                                       │  │
│  │   ✅ All 12 commits verified                          │  │
│  │   Authors: alice (acme), bob (acme)                   │  │
│  │                                                       │  │
│  │   ❌ 2 commits failed verification                    │  │
│  │   - abc1234: User not in organization                 │  │
│  │                                                       │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Zero-Config Policy

When installed **without** a `.github/vouch-policy.yml` file, the app uses these sane defaults:

```yaml
policy:
  require_signed_commits: true
  allow_unsigned_merge_commits: false
  allow_bots: true
  policy_type: implicit_organization_trust
  # ^ If signer is an org member, ALLOW
```

This means:
- ✅ Any org member with a signed commit is allowed
- ✅ Bots (Dependabot, GitHub Actions) are allowed
- ❌ Unsigned commits are blocked
- ❌ Non-org-members are blocked

---

## Explicit Configuration

Add `.github/vouch-policy.yml` for custom rules:

```yaml
version: 1
policy:
  require_signed_commits: true
  allow_unsigned_merge_commits: true
  allow_bots: true
  policy_type: explicit  # Only allowlist entries
  
  allowed_organizations:
    - "did:vouch:mycompany"
    - "did:vouch:partner-org"
  
  allowed_users:
    - "did:vouch:contractor_bob"
    - "github:external-contributor"  # GitHub username prefix
```

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/webhook` | POST | GitHub webhook receiver |
| `/setup` | GET | Redirect to GitHub App install |
| `/setup/callback` | GET | Post-install callback |
| `/api/badge/{owner}/{repo}` | GET | Shields.io badge endpoint |
| `/health` | GET | Health check |

### Badge Usage

Add to your README:

```markdown
[![Vouch Protected](https://img.shields.io/endpoint?url=https://gatekeeper.vouch-protocol.com/api/badge/OWNER/REPO)](https://vouch-protocol.com)
```

---

## Edge Cases Handled

| Scenario | Handling |
|----------|----------|
| **Mixed Identity PR** | Lists each failing commit specifically |
| **Key Rotation** | Accepts historical keys with warning |
| **Dependabot/Bots** | Configurable via `allow_bots` |
| **Registry Offline** | Neutral status (doesn't block) |
| **Merge Commits** | Configurable via `allow_unsigned_merge_commits` |
| **No Config File** | Zero-Config defaults (org member trust) |
| **GitHub Key Match** | Verified via GitHub API, no Vouch registration needed |

---

## Hybrid Verification Flow

```
1. Extract signature key_id from commit
2. Step A: GitHub Lookup
   - GET /users/{username}/gpg_keys
   - GET /users/{username}/keys (SSH)
3. Step B: Match
   - Compare commit key_id to user's registered keys
4. Step C: Attestation
   - If match: "Verified GitHub User: {username}"
   - Check org membership via GET /orgs/{org}/members/{username}
5. Fallback: Vouch Registry
   - GET /api/lookup?key_id={key_id}
   - Returns: vouch_did, organization
```

---

## Auto-Badge PR

When installed on a repository, the app:

1. Fetches `README.md`
2. Checks for existing Vouch badge
3. If missing, creates branch `vouch-add-badge`
4. Opens PR: "docs: Add Vouch Protection badge"

The badge dynamically shows protection status via the `/api/badge` endpoint.

---

## Files

| File | Description |
|------|-------------|
| `main.py` | FastAPI app (1000+ lines) |
| `app-manifest.json` | GitHub App auto-setup manifest |
| `example-vouch-policy.yml` | Template config for repos |
| `pyproject.toml` | Python dependencies |
| `.env.example` | Environment variables |

---

## License

Apache-2.0
