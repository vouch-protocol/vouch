# Revocation Reference

Two complementary mechanisms, used together in most production
deployments.

## DID-level revocation: kill an entire identity

When a private key is compromised or an agent is decommissioned, revoke
the whole DID. Every credential issued under that DID becomes invalid.

```python
from vouch import RevocationRegistry, RedisRevocationStore, RevocationRecord
import time

registry = RevocationRegistry(store=RedisRevocationStore(url="redis://prod:6379"))

await registry.revoke(RevocationRecord(
    did="did:web:compromised-agent.example.com",
    revoked_at=int(time.time()),
    reason="key_compromised",
    revoked_by="did:web:security-team.example.com",
))
```

Verifiers consult the registry on every verification. If the issuing
DID is revoked, the credential fails with reason `issuer_revoked`. Cache
TTL is configurable (default 60 seconds) to balance freshness against
verifier throughput.

Backends: `MemoryRevocationStore`, `RedisRevocationStore`, plus an
abstract `RevocationStoreInterface` for custom backends.

## Credential-level revocation: BitstringStatusList

When you need to retract one specific credential without invalidating
the rest of the agent's history, use BitstringStatusList. Compressed
bitstring at a stable URL, one bit per credential.

### Issuer side

Maintain a single `StatusList` per status purpose (revocation, or optionally suspension):

```python
from vouch import (
    Signer, StatusList, FilesystemStatusListStore,
    build_status_list_credential, build_status_list_entry,
    build_vouch_credential,
)

# Load or create the status list
store = FilesystemStatusListStore("/var/lib/vouch/status-1.json")
try:
    status_list = store.load()
except FileNotFoundError:
    status_list = StatusList(status_list_id="https://issuer.example/status/1")

signer = Signer.from_did("did:web:issuer.example")
```

#### Issue a credential with a status entry

```python
index = status_list.allocate_index()
store.save(status_list)  # persist the cursor

credential = build_vouch_credential(
    issuer_did="did:web:issuer.example",
    intent={"action": "...", "target": "...", "resource": "..."},
    credential_status=build_status_list_entry(
        status_list_credential="https://issuer.example/status/1",
        status_list_index=index,
    ),
)
signed_credential = signer.sign_credential(credential)
```

#### Revoke later

```python
status_list.revoke(index)
store.save(status_list)

# Re-sign and republish the status list credential
status_credential = build_status_list_credential(
    issuer_did="did:web:issuer.example",
    status_list=status_list,
)
signed_status_credential = signer.sign_credential(status_credential)

# Publish at the URL referenced by the original credential
# (typically PUT to your CDN / S3 / GitHub Pages)
```

### Verifier side

```python
from vouch import StatusListFetcher, verify_status

fetcher = StatusListFetcher(cache_ttl_seconds=300)

status_credential = fetcher.get(
    signed_credential["credentialStatus"]["statusListCredential"]
)

is_revoked = verify_status(
    credential_status=signed_credential["credentialStatus"],
    status_list_credential=status_credential,
)
```

The fetcher uses an in-memory TTL cache and issues conditional GETs
(`If-None-Match`, `If-Modified-Since`) so re-validation is cheap when
the list hasn't changed.

On verification failure, call `fetcher.get(url, force_refresh=True)` to
bypass the cache and fetch the latest list. This is the protocol-aligned
way to handle stale-cache scenarios.

## Persistence (issuer)

The bitstring AND the allocation cursor (`nextIndex`) need to survive
issuer restarts. Cursor is NOT recoverable from the encoded bitstring
alone; without it, an issuer restart would re-allocate already-used
indices.

```python
state = status_list.to_state_dict()
# {
#     "version": 1,
#     "status_list_id": "...",
#     "status_purpose": "revocation",
#     "length": 131072,
#     "next_index": 1024,
#     "encoded_list": "u..."
# }
# Save state to your durable store (Redis, Postgres, S3)

# On startup
status_list = StatusList.from_state_dict(state)
```

`FilesystemStatusListStore` is a reference store with atomic temp-file +
rename writes. Production deployments substitute Redis (`SET status:1
<state-json>`), Postgres (single row, `UPDATE` under `SELECT FOR UPDATE`),
or S3 (with ETag-based optimistic concurrency).

## Sizing

W3C BitstringStatusList §4.2 minimum bitstring length: 131,072 bits
(16 KiB uncompressed; ~50 bytes compressed when empty). That holds
131,072 credentials per status list.

For larger issuers, allocate a new status list as you approach
exhaustion. The `credentialStatus.statusListCredential` URL on each
credential identifies which list it belongs to.

Practical sizing: at 5-minute credential validity, one list covers about
a year of issuance at 0.4 credentials/minute, or one day at ~91/minute.
Plan list rotation accordingly.

## Cross-language

All three SDKs ship BitstringStatusList:

- Python: `vouch.status_list`
- TypeScript: `packages/sdk-ts/src/status-list.ts`
- Go: `go-sidecar/signer/status_list.go`

A cross-language test vector lives at
`test-vectors/bitstring-status-list/vector.json`. Python and TypeScript
produce byte-identical encoded output (both use zlib's DEFLATE).
Go's `compress/flate` produces a valid DEFLATE stream that decodes to
the same bitstring; the spec requires equivalence of the decompressed
bitstring, not the gzip envelope, so all three interop cleanly.

## Composition: when to use which

| Scenario | Use | Reason |
|---|---|---|
| Key compromised | DID-level | Kill everything that key signed |
| Agent decommissioned | DID-level | Cleaner than revoking N credentials individually |
| One bad action needs retraction | BitstringStatusList | Other credentials from same agent still valid |
| Compliance retraction of a specific transaction | BitstringStatusList | Audit log shows specific action retracted |
| Suspending an agent temporarily | BitstringStatusList suspension | Reinstate later by clearing the bit |
| Regulatory hold on a specific credential | BitstringStatusList | Per-credential granularity |

Most production deployments run both: DID registry for blanket kill
switches, BitstringStatusList for surgical per-credential operations.

## Cache TTL tuning

The fetcher's default TTL is 300 seconds (5 minutes). This means a
revocation event takes up to 5 minutes to propagate to a verifier that
already has the list cached.

For tighter SLAs, shorten the TTL or have verifiers consult the
issuer's webhook for invalidation events:

```python
fetcher = StatusListFetcher(cache_ttl_seconds=60)
```

For multi-instance verifier fleets, wrap the fetcher with a shared
cache (Redis) so an invalidation in one verifier becomes visible to
all of them immediately.

## Common errors

- **`credential_revoked: bit set at index N`**: working as intended.
  The issuer flipped the bit; verifier sees it. If unexpected, check
  the issuer's status list state and force-refresh the fetcher.
- **`status_list_unfetchable`**: HTTP fetch of the BitstringStatusListCredential
  failed (network, 404, etc.). The verifier should either fail-closed
  (reject the credential) or fall back per policy.
- **`status_list_signature_invalid`**: the published BitstringStatusListCredential
  itself has a bad signature. The verifier MUST verify the list's own
  Data Integrity proof BEFORE looking up the bit.
- **`status_purpose_mismatch`**: credential's `credentialStatus.statusPurpose`
  doesn't match the list's `credentialSubject.statusPurpose`. Wiring bug.
- **Issuer re-allocates the same index after restart**: the issuer
  didn't persist `nextIndex`. Restore from `to_state_dict` / `from_state_dict`
  pattern or use `FilesystemStatusListStore`.
