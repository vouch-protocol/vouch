# Vouch Gatekeeper - Cloudflare Workers Edition

A GitHub App that enforces cryptographic identity on every Pull Request.

## Features

- ✅ **Zero-Config**: Works immediately with implicit org trust
- 🔐 **Webhook Signature Verification**: Validates GitHub webhook signatures
- 🔑 **JWT Authentication**: Uses GitHub App JWT for API calls
- 🏢 **Hybrid Verification**: GitHub GPG keys + Vouch Registry fallback
- ✅ **Check Runs**: Creates pass/fail check runs on PRs

## Deployment

### 1. Install Dependencies

```bash
cd github-app-worker
npm install
```

### 2. Login to Cloudflare

```bash
npx wrangler login
```

### 3. Set Secrets

```bash
wrangler secret put GITHUB_APP_ID
wrangler secret put GITHUB_PRIVATE_KEY
wrangler secret put GITHUB_WEBHOOK_SECRET
```

### 4. Deploy

```bash
npx wrangler deploy
```

### 5. Configure GitHub App

Update your GitHub App's webhook URL to:
```
https://gatekeeper.vouch-protocol.com/webhook
```

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `POST /webhook` | GitHub webhook handler |

## How It Works

1. PR is opened/updated
2. GitHub sends webhook to `/webhook`
3. Worker verifies webhook signature
4. Worker creates "in progress" check run
5. Worker fetches PR commits
6. For each commit:
   - Check if signed
   - Verify GPG key belongs to author
   - Check org membership
7. Worker creates pass/fail check run

## Policy Configuration

Create `.github/vouch-policy.yml` in your repo:

```yaml
policy:
  policy_type: implicit_organization_trust  # or "explicit"
  require_signed_commits: true
  allow_unsigned_merge_commits: false
  allow_bots: true
```

### Policy Types

- **implicit_organization_trust** (default): Any org member with signed commits is allowed
- **explicit**: Only users in `allowed_users` or `allowed_organizations` are allowed
