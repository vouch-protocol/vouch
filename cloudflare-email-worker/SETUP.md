# Vouch email assistant — setup (30 minutes, all free)

Sets up `ask@vouch-protocol.com` to receive technical questions and auto-reply
using Gemini 1.5 Flash, with a copy forwarded to `ram@vouch-protocol.com`
for visibility.

## What you'll touch

1. Cloudflare dashboard — enable Email Routing, deploy a Worker
2. Google AI Studio — get a Gemini API key (free tier)
3. Resend.com — sign up, verify your domain
4. Your local terminal — `wrangler secret put` and `wrangler deploy`

## What it costs

Nothing at typical volume.

| Service | Free tier | Estimated usage |
|---|---|---|
| Cloudflare Email Workers | unlimited inbound | 100% of traffic |
| Gemini 1.5 Flash API | 1500 req/day | ~10-50/day |
| Resend (transactional email) | 3000 emails/month | ~10-50/day |
| Cloudflare Email Routing | unlimited | 100% of traffic |

If inbound spikes past those limits, costs are modest: Resend $20/month
for 50k emails, Gemini paid tier $0.075/M input tokens.

## Step 1 — Get a Gemini API key (2 minutes)

1. Open https://aistudio.google.com/app/apikey
2. Sign in with the Google account you want to be billed against (free tier
   is fine; no billing required to start)
3. Click **Create API key** → pick or create a project
4. Copy the key. It looks like `AIza...` and is ~40 chars

Save it as a wrangler secret in step 5.

## Step 2 — Sign up for Resend (5 minutes)

1. Open https://resend.com and sign up (free, no credit card)
2. **Add Domain** → `vouch-protocol.com`
3. Resend shows DNS records to add — copy them
4. In Cloudflare DNS for `vouch-protocol.com`, add:
   - One TXT record (SPF / Resend verification)
   - Three CNAME records (DKIM)
   - One MX record (only if Resend asks; you may already have one)
5. Back in Resend, click **Verify DNS records**. May take 5-30 min to propagate
6. Once verified: **API Keys** → **Create API key** → name it `vouch-email-assistant`,
   scope `Sending Access`, full access. Copy the key (`re_...`)

## Step 3 — Enable Cloudflare Email Routing (3 minutes)

1. Open the Cloudflare dashboard
2. Select the `vouch-protocol.com` zone
3. **Email** → **Email Routing** → click **Enable Email Routing**
4. Cloudflare offers to auto-add MX + SPF records. Accept
5. Add a **Destination address** (your personal Gmail or wherever you read mail).
   You will get a verification email — confirm it

## Step 4 — Deploy the Worker (5 minutes)

In your WSL terminal:

```bash
cd ~/vouch-protocol/cloudflare-email-worker
npm install
. "$HOME/.vouch/env"          # pulls CLOUDFLARE_API_TOKEN
npx wrangler deploy
```

You should see `Deployed vouch-email-assistant` and a worker URL (we don't
hit the URL directly; Email Routing invokes it on inbound mail).

## Step 5 — Set the secrets

```bash
npx wrangler secret put GEMINI_API_KEY    # paste the AIza... key
npx wrangler secret put RESEND_API_KEY    # paste the re_... key
npx wrangler secret put FORWARD_TO        # type ram@vouch-protocol.com
```

Each one prompts you. Paste the value, press Enter.

## Step 6 — Wire ask@ to the Worker (3 minutes)

1. Cloudflare dashboard → `vouch-protocol.com` → **Email** → **Email Routing** → **Routes** tab
2. Click **Create address** under "Custom addresses"
3. **Custom address:** `ask`
4. **Action:** **Send to a Worker**
5. **Destination:** select `vouch-email-assistant` from the dropdown
6. **Save**

## Step 7 — Smoke test

From your personal email, send a message to `ask@vouch-protocol.com`:

> Subject: Testing the assistant
>
> Hi — quick test. How does the Identity Sidecar prevent a prompt-injected
> LLM from signing arbitrary actions?

Within 10-30 seconds you should receive a Gemini-drafted reply explaining
the Brain/Passport split. A copy also lands in `ram@vouch-protocol.com`
inbox.

If nothing arrives:

```bash
npx wrangler tail vouch-email-assistant
```

Then send another test email. Live logs will show the error.

## Step 8 — Vacation responder for ram@ (5 minutes)

Separate from the Worker, set Gmail's vacation responder on
`ram@vouch-protocol.com` (the personal address) to:

```
I am on parental leave through September 2026.

For technical questions about Vouch, please email ask@vouch-protocol.com.
It's monitored by the Vouch Assistant (AI), which can answer most questions
within seconds. The reply is itself Vouch-signed.

For partnerships or media: I will respond when I return in October.

For urgent security disclosures: security@vouch-protocol.com (monitored).

Thanks for your patience.
```

That's it. The full stack is live.

## Operating it

- Spot-check the first 50 inbound emails after launch. If Gemini is being
  consistently weird about a class of question, tighten the SYSTEM_PROMPT
  in `src/worker.js` and redeploy.
- The `FORWARD_TO` copies let you sample replies without reading every one.
- During the break, you can disable the copies by deleting the FORWARD_TO
  secret: `npx wrangler secret delete FORWARD_TO`. The Worker will then
  reply silently and you won't get notifications.

## Updating the knowledge base

When new papers / blog posts go live, update the bullet list in
`SYSTEM_PROMPT` in `src/worker.js`. Then:

```bash
. "$HOME/.vouch/env"
npx wrangler deploy
```

Takes ~30 seconds. Zero downtime.

## If you want richer answers (RAG, optional, post-launch)

The current setup ships the entire knowledge base in the system prompt
(~300 tokens). For genuinely long-form answers — quoting paper sections,
embedding code snippets — you'd want a RAG step:

1. Store the corpus (papers, blog, README) as embeddings in Cloudflare
   Vectorize (free tier exists)
2. On each inbound email, embed the query, retrieve top-k passages
3. Include retrieved passages in the Gemini prompt

That's a follow-up, not required for launch.
