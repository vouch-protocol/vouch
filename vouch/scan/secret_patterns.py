"""Generic provider-secret detection patterns (opt-in).

The Vouch leak scanner exists to catch Vouch-shaped key material that
generic scanners miss (JWK-with-`d`, seed-near-config). But the same
file-walking engine is just as good at catching the *common* secrets any
repository can leak — AWS keys, GitHub tokens, Stripe keys, PEM private
keys. Shipping those patterns turns `vouch scan` into a scanner a project
adopts on its own merits, with Vouch key detection riding along for free.

These patterns are NOT applied by default. The CLI enables them with
`vouch scan --secrets`, and the GitHub Action exposes them via the
`secrets:` input. Keeping them opt-in means an existing Gatekeeper
install never changes its pass/fail behavior without the maintainer
asking for it.

Design rules, to keep false positives low enough for CI gating:

- Anchor on a vendor-assigned prefix (``AKIA``, ``ghp_``, ``sk_live_``).
  We never try to flag a bare high-entropy string — that is the job of an
  entropy scanner and produces too much noise for a blocking check.
- Prefer CRITICAL only for material that is a live credential by shape.
  Webhook URLs and prefix-only OpenAI keys, which carry more ambiguity,
  are graded HIGH so the default `--exit-nonzero-on critical` gate does
  not trip on them.
"""

from __future__ import annotations

import re

from .patterns import Kind, Severity, VouchPattern


# AWS access key IDs use a fixed set of 4-letter type prefixes followed by
# 16 uppercase-alphanumeric characters.
AWS_ACCESS_KEY_ID_RE = re.compile(
    r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[0-9A-Z]{16}\b"
)

# AWS secret access keys are 40 base64-ish chars with no fixed prefix, so we
# only flag one when it is assigned to an obviously-named field. Matching a
# bare 40-char token would fire on hashes and unrelated blobs.
AWS_SECRET_ACCESS_KEY_RE = re.compile(
    r"(?i)aws_secret_access_key\b\s*[:=]\s*[\"']?[A-Za-z0-9/+]{40}[\"']?"
)

# GitHub personal/OAuth/app/refresh tokens: ghp_, gho_, ghu_, ghs_, ghr_.
GITHUB_TOKEN_RE = re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b")

# GitHub fine-grained PATs.
GITHUB_FINE_GRAINED_PAT_RE = re.compile(r"\bgithub_pat_[0-9A-Za-z]{22}_[0-9A-Za-z]{59}\b")

# GitLab personal access tokens.
GITLAB_PAT_RE = re.compile(r"\bglpat-[0-9A-Za-z_-]{20}\b")

# Slack tokens (bot/user/app/refresh/legacy).
SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b")

# Slack incoming-webhook URLs embed the workspace + secret path.
SLACK_WEBHOOK_RE = re.compile(
    r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z_]{16,}"
)

# Google API keys.
GOOGLE_API_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")

# Stripe live secret/restricted keys. Test keys (sk_test_) are excluded to
# avoid failing CI on intentionally-public fixtures.
STRIPE_SECRET_KEY_RE = re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b")

# SendGrid API keys.
SENDGRID_API_KEY_RE = re.compile(r"\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b")

# npm automation/publish tokens.
NPM_TOKEN_RE = re.compile(r"\bnpm_[0-9A-Za-z]{36}\b")

# Anthropic API keys (checked before the broader OpenAI pattern below).
ANTHROPIC_API_KEY_RE = re.compile(r"\bsk-ant-[0-9A-Za-z_-]{20,}\b")

# OpenAI API keys. `sk-` (hyphen) distinguishes these from Stripe's `sk_`
# (underscore). Graded HIGH because the prefix is short enough to admit the
# occasional false positive; require length to limit that.
OPENAI_API_KEY_RE = re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}\b")

# PEM private key blocks (RSA/EC/OpenSSH/DSA/PGP/encrypted, or unlabeled
# PKCS#8). The BEGIN marker alone is a reliable signal.
PRIVATE_KEY_PEM_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----"
)


_ROTATE = "Revoke and rotate this credential at the issuing provider, then purge it from git history (e.g. git filter-repo) and move it to a secret manager."


GENERIC_SECRET_PATTERNS: list[VouchPattern] = [
    VouchPattern(
        kind=Kind.AWS_ACCESS_KEY_ID,
        pattern=AWS_ACCESS_KEY_ID_RE,
        severity=Severity.CRITICAL,
        description="AWS access key ID",
        remediation=_ROTATE,
    ),
    VouchPattern(
        kind=Kind.AWS_SECRET_ACCESS_KEY,
        pattern=AWS_SECRET_ACCESS_KEY_RE,
        severity=Severity.CRITICAL,
        description="AWS secret access key assigned to an aws_secret_access_key field",
        remediation=_ROTATE,
    ),
    VouchPattern(
        kind=Kind.GITHUB_TOKEN,
        pattern=GITHUB_TOKEN_RE,
        severity=Severity.CRITICAL,
        description="GitHub access token (personal/OAuth/app/refresh)",
        remediation=_ROTATE,
    ),
    VouchPattern(
        kind=Kind.GITHUB_FINE_GRAINED_PAT,
        pattern=GITHUB_FINE_GRAINED_PAT_RE,
        severity=Severity.CRITICAL,
        description="GitHub fine-grained personal access token",
        remediation=_ROTATE,
    ),
    VouchPattern(
        kind=Kind.GITLAB_PAT,
        pattern=GITLAB_PAT_RE,
        severity=Severity.CRITICAL,
        description="GitLab personal access token",
        remediation=_ROTATE,
    ),
    VouchPattern(
        kind=Kind.SLACK_TOKEN,
        pattern=SLACK_TOKEN_RE,
        severity=Severity.CRITICAL,
        description="Slack API token",
        remediation=_ROTATE,
    ),
    VouchPattern(
        kind=Kind.SLACK_WEBHOOK,
        pattern=SLACK_WEBHOOK_RE,
        severity=Severity.HIGH,
        description="Slack incoming-webhook URL (carries a postable secret path)",
        remediation=_ROTATE,
    ),
    VouchPattern(
        kind=Kind.GOOGLE_API_KEY,
        pattern=GOOGLE_API_KEY_RE,
        severity=Severity.CRITICAL,
        description="Google API key",
        remediation=_ROTATE,
    ),
    VouchPattern(
        kind=Kind.STRIPE_SECRET_KEY,
        pattern=STRIPE_SECRET_KEY_RE,
        severity=Severity.CRITICAL,
        description="Stripe live secret/restricted key",
        remediation=_ROTATE,
    ),
    VouchPattern(
        kind=Kind.SENDGRID_API_KEY,
        pattern=SENDGRID_API_KEY_RE,
        severity=Severity.CRITICAL,
        description="SendGrid API key",
        remediation=_ROTATE,
    ),
    VouchPattern(
        kind=Kind.NPM_TOKEN,
        pattern=NPM_TOKEN_RE,
        severity=Severity.CRITICAL,
        description="npm access token",
        remediation=_ROTATE,
    ),
    VouchPattern(
        kind=Kind.ANTHROPIC_API_KEY,
        pattern=ANTHROPIC_API_KEY_RE,
        severity=Severity.CRITICAL,
        description="Anthropic API key",
        remediation=_ROTATE,
    ),
    VouchPattern(
        kind=Kind.OPENAI_API_KEY,
        pattern=OPENAI_API_KEY_RE,
        severity=Severity.HIGH,
        description="OpenAI API key (sk- prefix)",
        remediation=_ROTATE,
    ),
    VouchPattern(
        kind=Kind.PRIVATE_KEY_PEM,
        pattern=PRIVATE_KEY_PEM_RE,
        severity=Severity.CRITICAL,
        description="PEM-encoded private key block",
        remediation=_ROTATE,
    ),
]
