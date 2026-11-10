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

## Signals

The score is 60 points for a resolvable did:web and 40 for a usable
verification method. The extra signals come from `evidence.js`, the same checks
as `vouch/grade.py`, and each one carries its reason in `signals.reasons`:

- `pq_ready`: a well-formed ML-DSA-44 public key (Multikey with the ML-DSA-44
  multicodec, or a JWK with kty `AKP` and alg `ML-DSA-44`), controlled by the
  DID and listed in `assertionMethod`.
- `has_revocation`: a `BitstringStatusList` service whose https endpoint returns
  a BitstringStatusListCredential issued by the same DID, inside its validity
  period, with an `encodedList` that decodes and an `eddsa-jcs-2022` proof that
  verifies against an `assertionMethod` key of the DID document.
- `card_identity`: `verified` when the agent card's `vouchCredential` is issued
  by the domain's DID, bound to the card's `url`, and verifies against that DID
  document; `declared` when the card only names a DID; `no` otherwise.
  `has_card_identity` is true only for `verified`.

The shared vectors in `test-vectors/grade/` pin the signals and the reasons for
both implementations:

```bash
node --test agent-trust-index/grader-worker/test/
```

## Safety

The worker validates the domain (rejects IP literals, localhost, and internal
names) so it cannot be pointed at private infrastructure. Every fetch, including
the status-list URLs a DID document names, goes through `guardedFetchJson`:
https only, a host whose every A and AAAA answer (looked up over DNS-over-HTTPS)
is a public address, redirects followed by hand and re-checked hop by hop, a
size cap per document, and a time limit per fetch.
