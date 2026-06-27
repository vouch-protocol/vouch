# Vouch test vectors

Canonical, language-independent fixtures that define the cross-implementation
contract for Vouch Protocol. Python is the source of truth; every other language
(Go, TypeScript, Rust, and the wrappers) must reproduce these outputs exactly.

There are two families of vectors in this directory:

- **Spec-format vectors**, maintained by hand or by a per-folder `generate.py`:
  `jcs/`, `data-integrity-eddsa-jcs-2022/`, `hybrid-eddsa-mldsa44/`,
  `bitstring-status-list/`, `audit-trail/`, `robotics/`.
- **Runtime-module vectors** (this document), produced by one shared harness at
  [`scripts/gen_runtime_vectors.py`](../scripts/gen_runtime_vectors.py): one
  folder per runtime module that the ports in issues #94 through #105 implement.

## Runtime-module vectors

| Folder | Python module | Spec section | What it covers |
|---|---|---|---|
| `trust_entropy/` | `vouch.trust_entropy` | 11.5 | Time-decaying trust, half-life, time-to-threshold |
| `quorum/` | `vouch.quorum` | 11.6 | M-of-N validator coordination and trust aggregation |
| `merkle/` | `vouch.merkle` | 11.3 | Merkle tree, root, inclusion proofs (RFC 6962) |
| `canary/` | `vouch.canary` | 11.7 | Commit/reveal canary chain |
| `behavioral_attestation/` | `vouch.behavioral_attestation` | 11.3 | Per-interval behavioural digest and drift scorers |
| `heartbeat/` | `vouch.heartbeat` | 11.3 | Heartbeat request wire format and validation |

Folder names match the Python module names so a porter mapping "the
`trust_entropy` module" finds the same-named folder.

## Vector format

Each `vector.json` shares one shape, modelled on `jcs/vectors.json`:

```json
{
  "description": "human-readable summary a porter can consume without reading Python",
  "module": "vouch.<module>",
  "spec_reference": "Specification 11.x",
  "version": "1.0",
  "pinned": { "now": "2026-01-01T00:00:00Z", "uuid": "urn:uuid:...", "os_urandom": "..." },
  "cases": [
    { "name": "...", "function": "...", "input": { ... }, "expected": { ... } }
  ]
}
```

- `cases` is an ordered list. Each case names the `function` under test, the
  `input` that drives it, and the `expected` output to match.
- `pinned` appears only where a module reads a clock, a UUID, or randomness
  (`canary`, `heartbeat`, `quorum`, and the `now` used by `trust_entropy`).

### Byte encodings

Values follow the conventions the modules already emit, so a port can compare
against its own output directly:

- **Multibase base64url-no-pad** (prefix `u`): Merkle roots and proof siblings,
  canary commitments and reveals, `actionMerkleRoot`.
- **Hex** (lowercase, no prefix): raw 32-byte SHA-256 leaf and node hashes.
- **Base64** (standard, padded): fixed secret inputs, for example
  `canary` `secret_b64`.
- **ISO-8601 UTC** with a trailing `Z`: all timestamps.

## Regenerating

```bash
python scripts/gen_runtime_vectors.py
```

This rewrites all six `vector.json` files. Re-running it produces no diff.

## Determinism contract

The harness removes every source of non-determinism so the output is stable:

- The clock is pinned to **`2026-01-01T00:00:00Z`**. `trust_entropy` and
  `heartbeat` receive it through their existing `at_time` / `now` parameters;
  the `SessionVoucher` builder (`vouch/vc.py`) has its `datetime.now` pinned.
- The `SessionVoucher` UUID is pinned to
  **`urn:uuid:00000000-0000-4000-8000-000000000001`**.
- `os.urandom` (canary secrets) is pinned: the nth call (0-indexed) returns the
  single byte `(n + 1)` repeated to the requested length, and the counter resets
  for each vector. So the first canary secret is `0x01` repeated 32 times, the
  second is `0x02` repeated 32 times, and so on.

`tests/test_runtime_vectors.py` regenerates every vector in memory under the same
pinned context and asserts byte-for-byte equality with the committed file, so CI
fails the moment a module drifts from its vector.

## A note for porters on floats

The `trust_entropy` vectors carry the exact Python `float` results, which keeps
the Python self-check exact. Across languages, `exp()` and `log()` can differ by a
unit in the last place, so a Go or TypeScript port should compare these values
within a small tolerance (for example, `1e-12` absolute) rather than requiring
bit-identical floats. The structural vectors (merkle, canary, heartbeat, quorum)
are hash- and string-based and must match exactly.
