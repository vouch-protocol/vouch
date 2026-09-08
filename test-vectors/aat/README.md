# AAT chain fixtures

Delegation-chain fixtures for the AAT ↔ Vouch adapter in
[`integrations/aat/`](../../integrations/aat/).

## How they were generated

Both fixtures were produced by [`generate.py`](generate.py) using the AAT
reference implementation ([`tenuo`](https://github.com/tenuo-ai/tenuo),
Apache-2.0), which the draft's Implementation Status appendix names as the
reference implementation of `draft-niyikiza-oauth-attenuating-agent-tokens-01`.
Nothing here is hand-built: the root is minted and the leaf is derived through
that implementation's own API, so the fixtures are exactly what it emits.

```bash
pip install tenuo
python3 test-vectors/aat/generate.py
```

| File | What it is |
|---|---|
| `valid-narrowing-chain.json` | Root grants `read_file` + `write_file` over `reports/*`. The leaf is derived offline by the holder and grants `read_file` only. Must verify. |
| `widening-chain.json` | A token minted by a third key claiming `delete_file`, spliced in behind a genuine root. Must fail verification. |
| `keys.json` | The test-only Ed25519 seeds used above, published deliberately - they protect nothing. The holder seed mints the proof-of-possession for a call against the valid chain. |

## Two things to know before relying on these

**They are not byte-reproducible.** Unlike `jcs/` or
`data-integrity-eddsa-jcs-2022/`, these are not a deterministic interop
contract. Warrant identifiers are UUIDv7-style and expiry is wall-clock, so
every run of `generate.py` produces different bytes. They are illustrative chain
fixtures.

**They expire.** The reference implementation caps a warrant's TTL at 90 days,
so a committed chain ages out. `_generated_at` in each file records when it was
made. The behavioural tests build their chains in-process for exactly this
reason; the fixture-backed test skips with a regeneration hint once the valid
chain has expired. The widening fixture stays meaningful either way, because
chain structure is checked before expiry.

## Why the widening fixture is a spliced token rather than a derived one

The obvious fixture would be a derived token that adds a tool or loosens a
constraint. The reference implementation will not produce one: `attenuate()`
raises `MonotonicityError` rather than minting a widened child, and the same
goes for loosening a pattern or dropping a constraint entirely. Refusing at
derivation is the stronger behaviour, but it means a widened *derived* token
cannot be created through the supported API.

So the fixture captures what an attacker can actually build - a token of their
own, claiming authority the root never granted, presented as though it descended
from that root. It is rejected on the draft's I5 cryptographic-linkage invariant:
the spliced token carries no `parent_hash` binding it to the root.

Derivation-time refusal is covered separately, in
`test_widened_scope_rejected`.

## Wire format

These are CBOR warrants from the reference implementation, **not** the draft's
JWT/JWS encoding. The draft's normative envelope is JWT; the reference
implementation is CBOR/COSE-native, which its Appendix E states plainly
("implementation-specific ... does not define a fully interoperable CWT
profile"). See [`integrations/aat/DESIGN.md`](../../integrations/aat/DESIGN.md)
§3 for why the adapter is built against the protocol model rather than the
encoding.
