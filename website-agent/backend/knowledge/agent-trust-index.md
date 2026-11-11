# The Agent Trust Index

The Agent Trust Index is an open benchmark published with Vouch. It scans public
AI agents and scores one question for each: can this agent prove who it is? It
measures adoption of provable identity in the wild, not whether an agent is good,
safe, or useful.

## What it measures

Each agent is scored out of 100:

- **60 points** for a resolvable cryptographic identity (a `did:web` that
  resolves to a DID document).
- **40 points** for that identity carrying a usable public key.

Grades: A is 90 or above, then B, C, D, and F below 40. An agent with no
resolvable identity scores zero.

## Checking the extra signals

`vouch grade <domain>`, the Agent Trust Index, and the web grader at
grade.vouch-protocol.com report three extra signals next to the score. Each one
is reported only when the evidence checks out, and each comes with a reason
(in the CLI text and in `--json` under `signals.reasons`).

- **Post-quantum.** The DID document lists a well-formed ML-DSA-44 public key
  (a Multikey with the ML-DSA-44 multicodec, or a JWK with `kty` `AKP` and
  `alg` `ML-DSA-44`), 1312 bytes, controlled by the DID and listed in
  `assertionMethod`.
- **Revocation.** The DID document has a `BitstringStatusList` service. Its
  https endpoint returns a `BitstringStatusListCredential` issued by the same
  DID, inside its validity period, with an `encodedList` that decodes and an
  `eddsa-jcs-2022` proof that verifies against an `assertionMethod` key.
- **Agent card.** `verified` when the card's `vouchCredential` is issued by the
  domain's DID, bound to the card URL, and verifies. `declared` when the card
  only names a DID. `no` otherwise. `--json` adds `card_identity`
  with this value, and `has_card_identity` is true only for `verified`.

The score stays 60 for the DID and 40 for the key. The fix lines in the output
say what was found, so you can see what to publish next. Every document is
fetched with `vouch.ssrf.fetch_json`: https only, public addresses, a pinned
connection, redirects re-checked, and limits on size and time.

## The first sweep

The first sweep drew its agents from the public Model Context Protocol registry
on 10 June 2026:

- **11,680** unique agents scanned
- **157** publish a resolvable `did:web` identity, about **1.3 percent**
- **98.7 percent** cannot prove who they are at all
- **69** of those 157 also carry a usable public key, a full grade A
- the 88 that resolve a DID but carry no usable key land around a C

The agents that can prove themselves are mostly finance and oracle agents: the
ones that handle money are the first to bother with identity.

## Where to point people

- The Index: `/agent-trust-index/`
- The methodology: `/agent-trust-index/methodology/`

The takeaway for a developer: provable identity is the floor, and almost nobody
has it yet. Adding a `did:web` and signing your agent's actions with Vouch puts
you in the top 1.3 percent on day one.
