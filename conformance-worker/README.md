# Vouch conformance worker

Cloudflare Worker that turns Vouch conformance from a self-declared claim into a
Vouch-verified, re-checkable result. It issues fresh per-session challenges,
re-checks submitted responses server-side with the canonical Vouch core (WASM),
derives the level, mints a signed `VouchConformanceCredential`, and serves the
badge. Because the worker recomputes every expected answer, a transcript cannot
be faked by replaying the public test vectors.

## Endpoints

- `POST /conformance/session` , body `{ implementation: { name, repo, commit, did?, publicKeyB64 }, levelRequested? }` returns `{ sessionId, expiresAt, challenges }`.
- `POST /conformance/session/{id}/submit` , body `{ responses: [{ challengeId, output }] }` returns `{ levelAchieved, checks, badgeUrl, verifyUrl, credential }`.
- `GET /conformance/{id}` , the stored result and signed credential, for re-verification.
- `GET /conformance/{id}/badge.svg` , the badge.

Checks re-checked today (L1): canonicalization and sign/verify are verified
cryptographically with the core; validity-window and nonce-replay are behavioural
(the implementation reports, the worker holds the expected answer). L2 and L3
challenges reuse the same shape and land next.

## Local check

```
npm install
node smoke.mjs
```

The smoke test runs the whole loop (issue, honest responses, re-check, mint,
verify) plus a cheating implementation that must be denied a level.

## Deploy

See the Cloudflare setup steps in the pull request / chat. In short: create the
KV namespace and set its id in `wrangler.toml`, set the issuer seed as a secret,
then `wrangler deploy`.
