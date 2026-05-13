# Actions auth setup

The hosted Vouch agent accepts unauthenticated read traffic for `/audit`
and a small allow-list of intents for `/sign`. For production GPTs you
will want stronger guarantees.

## Option 1: No auth (public demo only)

In the Custom GPT builder, under "Actions" -> "Authentication", choose
**None**.

Caveats:
- Anyone running your GPT can call `/sign` with one of the allow-listed
  actions. The hosted agent rate-limits and audit-logs every call.
- Use for demos only. Do NOT point at a sign endpoint that signs
  high-stakes intents.

## Option 2: API Key (recommended for invite-only GPTs)

1. Provision an API key from your hosted agent operator (Vouch Pro).
2. In the GPT builder, under "Actions" -> "Authentication", choose
   **API Key**.
3. Auth Type: **Bearer**.
4. API Key: paste the value.

The GPT now sends `Authorization: Bearer <token>` on every Action call.
Tokens are scoped to a small set of allow-listed actions.

## Option 3: OAuth (for end-user identities)

Not yet supported. Each end user would need to authenticate against
the hosted agent and have their own scoped DID. Planned post-v0.2.

## Privacy

ChatGPT shows the user a one-time consent prompt the first time it
calls each operation. Users can revoke at any time from GPT settings.

The hosted agent logs every Action call with: requesting GPT id, intent,
credential id, timestamp. Logs are retained for 30 days for abuse
monitoring and then rotated.
