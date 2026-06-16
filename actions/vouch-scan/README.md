# Vouch Gatekeeper leak check (GitHub Action)

A drop-in GitHub Action that runs `vouch scan` on every pull request and fails
the check if it finds leaked Vouch key material: a private key in a file, a seed
in an environment variable, or a DID document that accidentally carries a private
key. It is the Action half of the Gatekeeper; the [GitHub App](../../github-app/)
is the other half for org-wide installs and richer PR comments.

## Usage

Add this workflow to your repository at `.github/workflows/vouch-leak-check.yml`:

```yaml
name: Vouch leak check
on: [pull_request]

jobs:
  leak-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: vouch-protocol/vouch/actions/vouch-scan@main
```

That is the whole setup. The check turns red on a detected leak.

## Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Path to scan. |
| `severity` | `critical` | Fail when a finding is at or above this severity (`critical`, `high`, `medium`, `low`). |
| `version` | latest | Pin a specific `vouch-protocol` version. |

Example pinning the version and lowering the threshold:

```yaml
      - uses: vouch-protocol/vouch/actions/vouch-scan@main
        with:
          severity: high
          version: "1.6.3"
```

## What it detects

The same engine as the `vouch scan` CLI and the Gatekeeper App: Vouch-shaped
Ed25519 private JWKs, seed environment variables, hybrid post-quantum private
keys, and DID documents that mistakenly include private key material. See
[PAD-058](../../docs/disclosures/PAD-058-automated-key-rotation-on-leak-detection.md)
for the detection pattern set.
