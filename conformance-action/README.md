# Vouch conformance action

Run the Vouch conformance test in your CI and get back a level (L1 to L3) and a
Vouch-verified, re-checkable badge. The action asks the conformance worker for a
fresh challenge set, answers each challenge with the implementation under test,
and submits the transcript. The worker re-checks every response server-side with
the canonical core, so a pass cannot be faked by replaying the public vectors,
and the result is bound to the repo and commit the action ran in.

## Usage

```yaml
name: Conformance
on: [push]
jobs:
  conformance:
    runs-on: ubuntu-latest
    steps:
      - uses: vouch-protocol/vouch/conformance-action@main
        id: vouch
      - run: echo "Level ${{ steps.vouch.outputs.level }} - ${{ steps.vouch.outputs.badge_url }}"
```

Outputs: `level`, `badge_url`, `verify_url`. The step also writes a summary with
the per-check result and, on a pass, the badge and verify links.

## Testing your own implementation

The reference answers challenges with the published `vouch-protocol` package.
- To test a specific version or your fork, set `package` to it (any pip target).
- To test a non-Python port, replace the four `respond_*` functions in
  `client.py` with your SDK's calls; the session and submit plumbing is the same.

## Checks

Today the worker re-checks the L1 set: canonicalization and sign/verify are
verified cryptographically with the core; validity-window and nonce-replay are
behavioural, with the worker holding the expected answer. L2 and L3 reuse the
same challenge shape.
