# Cloudflare Worker Deployment Guide

This guide explains how to deploy the Vouch Verify API to Cloudflare Workers.

## Prerequisites

- Cloudflare account with domain `vouch-protocol.com` added
- Node.js 18+ installed
- npm or yarn

## Step 1: Install Wrangler CLI

```bash
npm install -g wrangler
```

## Step 2: Login to Cloudflare

```bash
wrangler login
```

This will open a browser window to authenticate.

## Step 3: Create KV Namespace

```bash
cd cloudflare-worker
wrangler kv:namespace create "SIGNATURES"
```

This will output something like:
```
🌀 Creating namespace with title "vouch-verify-api-SIGNATURES"
✨ Success!
Add the following to your configuration file in your kv_namespaces array:
{ binding = "SIGNATURES", id = "abc123..." }
```

**Copy the `id` value** and update `wrangler.toml`:

```toml
[[kv_namespaces]]
binding = "SIGNATURES"
id = "YOUR_KV_NAMESPACE_ID"  # Replace with actual ID
```

## Step 4: Deploy the Worker

```bash
wrangler deploy
```

This will deploy to a URL like:
```
https://vouch-verify-api.<your-subdomain>.workers.dev
```

## Step 5: Set Up Custom Domain (Optional but Recommended)

1. Go to Cloudflare Dashboard → Workers & Pages
2. Select your `vouch-verify-api` worker
3. Go to Settings → Triggers
4. Add Route: `vouch-protocol.com/api/*`
5. Select your zone (`vouch-protocol.com`)

Now your API is accessible at:
- `https://vouch-protocol.com/api/sign`
- `https://vouch-protocol.com/api/verify/:id`

## Step 6: Configure Pro API Keys (Optional)

For pro tier support, add environment variable:

```bash
wrangler secret put PRO_API_KEYS
# Enter: key1,key2,key3 (comma-separated list)
```

## API Endpoints

### POST /api/sign

Store a new signature and get a short URL.

**Request:**
```json
{
  "text": "Content to sign",
  "email": "user@email.com",
  "key": "base64_public_key",
  "sig": "base64_signature"
}
```

**Response:**
```json
{
  "success": true,
  "id": "abc123",
  "url": "https://vouch-protocol.com/v/abc123",
  "expiresAt": "2027-01-06T00:00:00Z"
}
```

### GET /api/verify/:id

Retrieve a signature by short ID.

**Response:**
```json
{
  "success": true,
  "text": "Content that was signed",
  "email": "user@email.com",
  "key": "base64_public_key",
  "sig": "base64_signature",
  "created": "2026-01-06T00:00:00Z",
  "expiresAt": "2027-01-06T00:00:00Z",
  "tier": "free"
}
```

### GET /api/health

Health check endpoint.

## Rate Limits

Free tier (Cloudflare Workers):
- 100,000 requests/day
- 1GB KV storage

For higher limits, upgrade to Workers Paid plan ($5/month).

## Updating the Extension

After deploying, update the API URL in `browser-extension/background.js`:

```javascript
const API_BASE_URL = 'https://vouch-protocol.com/api';
```

Then reload the extension in Chrome.
