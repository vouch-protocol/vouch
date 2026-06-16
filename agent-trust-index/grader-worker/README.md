# Agent Trust Index grader worker

A small Cloudflare Worker that grades one agent's trust posture. The browser
cannot fetch an arbitrary domain's `did.json` (CORS blocks it), so the live
"grade your agent" form on the Index page calls this worker, which resolves the
DID server-side and returns the grade. It is a faithful port of the Python
`vouch grade` scoring, so the CLI and the web form give the same result.

No secrets, no storage. It only reads public `.well-known` documents.

## Endpoints

- `GET /grade?domain=example.com` returns the JSON report
  (`grade`, `score`, `signals`, `fixes`).
- `GET /badge?domain=example.com` returns an SVG badge.

CORS is open (`*`) because the responses are public and carry no secrets.

## Deploy

```bash
cd agent-trust-index/grader-worker
npm install -g wrangler   # if needed
wrangler login
wrangler deploy
```

That publishes it at `https://vouch-grader.<your-subdomain>.workers.dev`.

To serve it at a clean custom domain (recommended, and the default the website
form points at), add a route in the Cloudflare dashboard for
`grade.vouch-protocol.com`, or uncomment the `routes` block in `wrangler.toml`
and redeploy.

## Point the website at it

The form reads `NEXT_PUBLIC_GRADER_ENDPOINT` at build time and falls back to
`https://grade.vouch-protocol.com`. If you deploy to the workers.dev URL instead
of the custom domain, set that env var before the website build:

```bash
NEXT_PUBLIC_GRADER_ENDPOINT="https://vouch-grader.<your-subdomain>.workers.dev" \
  npm --prefix website run build
```

## Safety

The worker validates the domain (rejects IP literals, localhost, and internal
names) so it cannot be pointed at private infrastructure, and it caps each fetch
at six seconds.
