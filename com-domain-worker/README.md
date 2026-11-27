# .com domain worker

The Vouch Protocol website lives at `vouch-protocol.org`. This small Cloudflare
Worker answers for the `vouch-protocol.com` apex so that every address already
in use keeps working.

It does two things.

**Pages redirect.** A request for a page gets a permanent redirect to the same
path and query on `vouch-protocol.org`. Old links, bookmarks, search results and
shared certificate pages all land in the right place.

**Identifiers stay on .com.** Some `.com` URLs are names that signed credentials
and resolvers depend on, so they keep answering on `.com` with an ordinary
response and no redirect:

- did:web documents: `/.well-known/did.json` and any `<name>/did.json`
  (`did:web:vouch-protocol.com`, `:contributors`, `:conformance`, `:adopters`).
- JSON-LD context and vocabulary URLs: `/contexts/`, `/schemas/`, `/ns/` and the
  other vocabulary prefixes listed in `worker.js`.
- Credential status lists under `/credentials/`.
- Everything else under `/.well-known/`.
- `/funding.json` and `/install.sh`.

For these the Worker fetches the same path from the site and returns it.

**JSON-LD documents.** A credential names its context without a file extension,
`https://vouch-protocol.com/contexts/v1`, and the site publishes it as
`contexts/v1.jsonld`. For a path under `/contexts/` or `/ns/` the Worker fetches
the matching `.jsonld` file and returns it as `application/ld+json`, readable
from any origin. The vocabulary those terms point into is served the same way at
`https://vouch-protocol.com/ns/v1`. The sources are
`website/public/contexts/v1.jsonld` and `website/public/ns/v1.jsonld`.

The verify pages (`/v/*`), the API (`/api/*`) and the C2PA endpoints
(`/.well-known/c2pa-*`) belong to the Workers in `cloudflare-worker/`. Their
routes are more specific than this one, so they keep matching first.

## Security boundary

- The Worker contacts one host only, the configured site origin. It follows a
  redirect from the site when the redirect stays on that origin and refuses it
  otherwise.
- It sends nothing from the caller to the site: no query string, cookies or
  authorization header.
- Identifier URLs accept `GET` and `HEAD` only, and only a short list of
  response headers is passed back.
- A page redirect always targets the site origin followed by the request path,
  so it cannot be steered to another host.
- A did:web document served here is the file published on the site. Trust in
  `did:web:vouch-protocol.com` rests, as before, on control of the `.com` zone
  and of the published site content.

No secrets, no storage.

## Test

```bash
node --test com-domain-worker/test/
```

## Deploy

Deploy it once the site is live on `vouch-protocol.org`.

```bash
cd com-domain-worker
npm install -g wrangler   # if needed
wrangler login
wrangler deploy
```

`SITE_ORIGIN` in `wrangler.toml` sets where pages redirect to and where
identifier files are fetched from.
