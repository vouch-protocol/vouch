# Vouch × ONDC — verifiable seller listings demo

A small, runnable demo aimed at a specific conversation: "what does Vouch do
for ONDC that ONDC can't already do?"

## What it is

Two HTML files plus a small JS library. No build step, no server, no API key.
Open them directly in any modern browser.

```
demos/ondc-seller-photo/
├── index.html         landing + framing for the demo
├── seller-app.html    Seller App: sign a product photo + listing fields
├── buyer-app.html     Buyer App: verify the bundle offline + try tamper modes
└── lib/
    └── vouch-browser.js   JCS, Ed25519, Multikey, Data Integrity proof
```

The crypto is **the same `eddsa-jcs-2022` cryptosuite** used by Vouch's Python
and TypeScript reference implementations — credentials produced here verify
in those impls and vice versa. This is not a toy.

## How to demo it (90 seconds, in front of someone)

1. Open `index.html`. Read the framing. (15 sec)
2. Click **Seller App**. The page generates your seller DID. Pick any image,
   click **Sign listing with Vouch**. Copy the bundle JSON. (30 sec)
3. Open `buyer-app.html` in another tab. Paste the bundle, drop the same
   image, click **Verify offline**. Watch the six checks pass. (15 sec)
4. Click each of the three tamper buttons — photo, title, signature — and
   watch a different check fail each time. (30 sec)

The point you want them to walk away with: **"the photo, the listing fields,
and the seller identity are bound together by a single signature any buyer
app can verify without calling anyone."**

## How to demo it locally (no server needed)

```bash
# WSL terminal, from the repo root
cd demos/ondc-seller-photo
python3 -m http.server 8765
```

Then open http://localhost:8765/ in your browser. The page works from
`file://` URLs too, but a local server avoids the `--allow-file-access`
flag for ES modules in some browsers.

## How to demo it to someone remote

Send them the `demos/ondc-seller-photo/` directory zipped, or — if you push
it to GitHub Pages — point them at the deployed URL. No backend needed.

## The ONDC pitch, in one paragraph

On ONDC, a single seller listing reaches buyers through dozens of buyer apps
the seller never sees, never authenticates with, and has no shared session
with. Today, those buyer apps can only trust the listing's claims as far as
they trust the seller app it came through. Vouch lets each listing carry its
own portable cryptographic proof — signer DID, listing ID, photo hash, title,
timestamp, all under one signature. Any buyer app, anywhere in the network,
can verify it offline. Tamper with any part and the proof breaks.

## Three failure modes the demo lets you trigger

| Button | What it does | Which check catches it |
|---|---|---|
| **Tamper with the photo** | Mutates last 16 bytes of the photo (SHA-256 changes) | "Photo SHA-256 matches the credential's bound hash" |
| **Tamper with the listing title** | Adds " — ACTUALLY FAKE" to the title field | "Ed25519 signature verifies" (canonical bytes differ) |
| **Flip one bit of the signature** | One character flip in the base58-encoded proofValue | "Ed25519 signature verifies" (Ed25519 rejection) |

After each tamper, click **Restore original** to recheck.

## Sample listing data (defaults in the form)

| Field | Default value |
|---|---|
| Listing ID | `L-789-saree-handblock` |
| Title | `Hand-block printed cotton saree` |
| Resource URN | `ondc://listing/L-789-saree-handblock` (auto-built) |
| Action | `list_product` |

Free to edit. The demo doesn't validate ONDC-specific schemas; that's a
production concern.

## Cryptographic specifics, for anyone who asks

- **Cryptosuite**: `eddsa-jcs-2022` (W3C VC Data Integrity)
- **Signature algorithm**: Ed25519 (RFC 8032)
- **Canonicalization**: RFC 8785 JSON Canonicalization Scheme (JCS)
- **Digest**: SHA-256
- **Key encoding**: W3C Multikey (multibase z-prefix + multicodec 0xed01 prefix)
- **DID method**: `did:web` with path segments (e.g.,
  `did:web:vouch-protocol.com:u:seller-12345`)
- **No external trust roots**: the buyer app verifies against the signer's
  own DID Document, which in this demo is bundled with the credential
  (in production, fetched once from the `did:web` URL).

## What's deliberately out of scope

This demo is intentionally narrow. It does NOT:

- Talk to any ONDC schema/API (would require ONDC tech office partnership)
- Persist signed listings server-side (browser localStorage only)
- Handle revocation (BitstringStatusList is in the protocol but excluded here)
- Show the State Verifiability layer (heartbeat, trust decay, validator quorum)
- Demonstrate the post-quantum hybrid cryptosuite

Those are the natural next conversations *if* this lands.

## What this proves about Vouch (the protocol)

The ONDC use case is a 3-day integration, not a 6-month project. The wire
crypto fits in ~200 lines of browser JS. The signing surface area for an
ONDC seller app is: "give me a DID and a private key, I'll attach a proof
to every listing." Buyer apps need ~50 lines of JS to verify, no backend.

If ONDC adopts this pattern, it's the first national-scale e-commerce network
with cryptographic per-artefact provenance. The story for a CTO is short:
"this works, here's the diff."
