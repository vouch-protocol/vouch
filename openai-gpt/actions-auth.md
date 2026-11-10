# Actions auth setup

The hosted Vouch agent accepts unauthenticated read traffic for `/audit`
and a fixed set of signed actions for `/act`. For production GPTs you
will want stronger guarantees.

## Option 1: No auth (public demo only)

In the Custom GPT builder, under "Actions" -> "Authentication", choose
**None**.

Caveats:
- Anyone running your GPT can call `/act` with one of its fixed actions.
  The hosted agent builds every intent itself and audit-logs every
  credential it signs.
- Use for demos only. Do NOT point at an endpoint that signs
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
