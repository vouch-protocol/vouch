# Vouch leak & secret scan (GitHub Action)

A drop-in GitHub Action that runs `vouch scan` on every pull request and fails
the check if it finds leaked key material. Out of the box it catches
**Vouch-shaped** secrets that generic scanners miss (a private key in a file, a
seed in an environment variable, or a DID document that accidentally carries a
private key). Flip on the `secrets` input and it *also* catches the **common
provider secrets** any repo can leak — AWS, GitHub, Stripe, PEM keys, and more —
so it is useful even to a project that has never heard of Vouch.

It is the Action half of the Gatekeeper; the [GitHub App](../../github-app/) is
the other half for org-wide installs and richer PR comments.

## Usage

Add this workflow to your repository at `.github/workflows/vouch-scan.yml`:

```yaml
name: Vouch scan
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: vouch-protocol/vouch-scan-action@v1
        with:
          secrets: "true"   # also scan for common provider secrets
```

That is the whole setup. The check turns red on a detected leak.

> **From the Marketplace / standalone repo:** reference
> `vouch-protocol/vouch-scan-action@v1`. That repo is a mirror of this directory
> (the Marketplace requires `action.yml` at a repo root). From inside this
> monorepo you can equivalently use `vouch-protocol/vouch/actions/vouch-scan@main`.

## Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Path to scan. |
| `severity` | `critical` | Fail when a finding is at or above this severity (`critical`, `high`, `medium`, `low`). |
| `secrets` | `false` | Also scan for common provider secrets, not just Vouch-shaped key material. |
| `version` | latest | Pin a specific `vouch-protocol` version. |

Example pinning the version and lowering the threshold:

```yaml
      - uses: vouch-protocol/vouch-scan-action@v1
        with:
          secrets: "true"
          severity: high
          version: "1.6.3"
```

## What it detects

The same engine as the `vouch scan` CLI and the Gatekeeper App.

**Always on — Vouch-shaped key material** (see
[PAD-058](../../docs/disclosures/PAD-058-automated-key-rotation-on-leak-detection.md)):
Ed25519 private JWKs, seed environment variables, hybrid post-quantum private
keys, and DID documents that mistakenly include private key material.

**With `secrets: "true"` — common provider secrets:** AWS access keys and secret
keys, GitHub tokens (classic and fine-grained), GitLab PATs, Slack tokens and
webhooks, Google API keys, Stripe live keys, SendGrid keys, npm tokens, OpenAI
and Anthropic API keys, and PEM-encoded private key blocks. Each pattern anchors
on a vendor-assigned prefix to keep false positives low enough for a blocking
CI check. Stripe *test* keys are intentionally not flagged.

Enabling `secrets` never lowers what the default mode catches — Vouch detection
always runs; the provider patterns are added on top.
