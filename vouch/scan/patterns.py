"""Detection patterns for Vouch-shaped private key material.

Each pattern is keyed on the `kind` (the structured failure mode it
represents) and carries:

- a compiled regex
- a severity level
- a human-readable remediation message

The pattern set is the OSS surface of PAD-058. New patterns are
added by extending VOUCH_PATTERNS; the detector uses them uniformly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Pattern


class Severity(str, Enum):
    """Severity levels, intended for CI gating policy."""

    CRITICAL = "critical"  # private key material that can sign credentials
    HIGH = "high"  # config that implies a key path; verify on review
    MEDIUM = "medium"  # vouch-specific filename or suspicious env-var name
    LOW = "low"  # informational; pattern-shaped but possibly benign


class Kind(str, Enum):
    """Structured failure kinds — stable across versions for tooling."""

    ED25519_PRIVATE_JWK = "vouch_ed25519_private_jwk"
    ED25519_PRIVATE_MULTIBASE = "vouch_ed25519_private_multibase"
    HYBRID_PQ_PRIVATE_KEY = "vouch_hybrid_pq_private_key"
    SEED_ENV_VAR = "vouch_seed_env_var"
    DID_DOC_WITH_PRIVATE_KEY = "vouch_did_doc_with_private_key"
    VOUCH_CONFIG_FILENAME = "vouch_config_filename"
    MNEMONIC_NEAR_VOUCH_CONFIG = "vouch_mnemonic_near_config"

    # Generic provider-secret kinds (opt-in via `vouch scan --secrets`).
    # These let the same engine that catches Vouch-shaped key material also
    # catch the common cloud/SaaS credentials any repository can leak, so
    # the scanner is useful even to a project that has never heard of Vouch.
    AWS_ACCESS_KEY_ID = "aws_access_key_id"
    AWS_SECRET_ACCESS_KEY = "aws_secret_access_key"
    GITHUB_TOKEN = "github_token"
    GITHUB_FINE_GRAINED_PAT = "github_fine_grained_pat"
    GITLAB_PAT = "gitlab_pat"
    SLACK_TOKEN = "slack_token"
    SLACK_WEBHOOK = "slack_webhook"
    GOOGLE_API_KEY = "google_api_key"
    STRIPE_SECRET_KEY = "stripe_secret_key"
    SENDGRID_API_KEY = "sendgrid_api_key"
    NPM_TOKEN = "npm_token"
    OPENAI_API_KEY = "openai_api_key"
    ANTHROPIC_API_KEY = "anthropic_api_key"
    PRIVATE_KEY_PEM = "private_key_pem"


@dataclass(frozen=True)
class VouchPattern:
    """One detection pattern."""

    kind: Kind
    pattern: Pattern[str]
    severity: Severity
    description: str
    remediation: str
    # If True, this pattern matches across multiple lines.
    multiline: bool = False


# Ed25519 JWK with private component `d`. The `d` field is the
# 32-byte private seed, base64url-encoded (43 or 44 chars).
ED25519_PRIVATE_JWK_RE = re.compile(
    r'"kty"\s*:\s*"OKP"[^}]{0,200}?"crv"\s*:\s*"Ed25519"[^}]{0,200}?"d"\s*:\s*"[A-Za-z0-9_-]{43,44}"',
    re.IGNORECASE,
)

# Multibase-encoded Ed25519 private key. Base58btc-encoded, ~45-52 chars
# after the leading `z`.
ED25519_PRIVATE_MULTIBASE_RE = re.compile(
    r'"privateKeyMultibase"\s*:\s*"z[1-9A-HJ-NP-Za-km-z]{45,52}"'
)

# Hybrid PQ private keypair (ED25519 + ML-DSA-44 concatenation, encoded multibase u-prefix).
HYBRID_PQ_PRIVATE_KEY_RE = re.compile(
    r'"privateKeyHybridMultibase"\s*:\s*"u[A-Za-z0-9_-]{3300,3500}"'
)

# Seed env vars (VOUCH_ED25519_SEED, ED25519_SEED, ED25519_PRIVATE_KEY_HEX, etc.).
# Value is 32 bytes hex (64 hex chars).
SEED_ENV_VAR_RE = re.compile(
    r"\b(VOUCH_ED25519_SEED|ED25519_SEED|ED25519_PRIVATE_KEY(?:_HEX)?|VOUCH_PRIVATE_SEED)"
    r'(?:\s*[:=]\s*|\s+is\s+)["\']?[0-9a-fA-F]{64}["\']?'
)

# DID Document verificationMethod with private key material.
DID_DOC_PRIVATE_KEY_RE = re.compile(
    r'"verificationMethod"\s*:\s*\[[^\]]*?"private(?:KeyJwk|KeyMultibase|KeyHybridMultibase|KeyHex)"',
    re.DOTALL,
)

# Vouch-specific config filenames that often carry keys.
VOUCH_CONFIG_FILENAME_RE = re.compile(
    r"^(?:.*/)?(?:vouch\.(?:json|jwk|key)|agent\.(?:jwk|key)|.*\.vouch\.(?:json|jwk|key))$",
    re.IGNORECASE,
)

# BIP-39 mnemonic phrase near a vouch-sidecar reference. The BIP-39
# wordlist has 2048 words; matching the full list here would explode
# the pattern. Instead, we look for sequences of 12 or 24 lowercase
# words (each 3-8 chars) on a line and check for proximity to
# "vouch-sidecar" or "VOUCH_SIDECAR" within 5 lines.
MNEMONIC_LINE_RE = re.compile(
    r"^\s*(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}\s*$",
    re.MULTILINE,
)


VOUCH_PATTERNS: list[VouchPattern] = [
    VouchPattern(
        kind=Kind.ED25519_PRIVATE_JWK,
        pattern=ED25519_PRIVATE_JWK_RE,
        severity=Severity.CRITICAL,
        description="Ed25519 private JWK detected (JWK with kty=OKP, crv=Ed25519, and private 'd' field)",
        remediation=(
            "Rotate the corresponding DID immediately. Generate a new Ed25519 keypair, "
            "update the DID Document, and revoke the leaked DID via the revocation registry."
        ),
    ),
    VouchPattern(
        kind=Kind.ED25519_PRIVATE_MULTIBASE,
        pattern=ED25519_PRIVATE_MULTIBASE_RE,
        severity=Severity.CRITICAL,
        description="Ed25519 private key in multibase form (privateKeyMultibase field with base58btc encoding)",
        remediation=(
            "Rotate the corresponding DID immediately. Multibase private keys are equivalent "
            "to JWK 'd' material — same urgency, same response."
        ),
    ),
    VouchPattern(
        kind=Kind.HYBRID_PQ_PRIVATE_KEY,
        pattern=HYBRID_PQ_PRIVATE_KEY_RE,
        severity=Severity.CRITICAL,
        description="Hybrid Ed25519+ML-DSA-44 private keypair (PAD-040 cryptosuite)",
        remediation=(
            "Rotate to a fresh hybrid keypair. Per PAD-058's never-downgrade rule, the "
            "replacement MUST be at least hybrid; do not downgrade to classical Ed25519."
        ),
    ),
    VouchPattern(
        kind=Kind.SEED_ENV_VAR,
        pattern=SEED_ENV_VAR_RE,
        severity=Severity.CRITICAL,
        description="Ed25519 seed in an environment-variable assignment",
        remediation=(
            "Move the seed to a secret manager (AWS Secrets Manager, HashiCorp Vault, "
            "Kubernetes Secrets). Do not commit raw seeds. Rotate the DID after removal."
        ),
    ),
    VouchPattern(
        kind=Kind.DID_DOC_WITH_PRIVATE_KEY,
        pattern=DID_DOC_PRIVATE_KEY_RE,
        severity=Severity.CRITICAL,
        description="DID Document carrying a private key field in verificationMethod",
        remediation=(
            "Strip the private key field. A published DID Document MUST only contain "
            "publicKey* fields. Rotate immediately since the document is publicly resolvable."
        ),
    ),
    VouchPattern(
        kind=Kind.VOUCH_CONFIG_FILENAME,
        pattern=VOUCH_CONFIG_FILENAME_RE,
        severity=Severity.MEDIUM,
        description="Vouch-specific config filename — verify the file does not contain private key material",
        remediation=(
            "Add the file to .gitignore if it carries keys. Move keys to a secret manager. "
            "Keep only the DID and configuration metadata in tracked files."
        ),
    ),
    VouchPattern(
        kind=Kind.MNEMONIC_NEAR_VOUCH_CONFIG,
        pattern=MNEMONIC_LINE_RE,
        severity=Severity.HIGH,
        description="Word sequence shaped like a 12/24-word mnemonic phrase",
        remediation=(
            "If this is a real mnemonic, treat it as compromised: rotate the derived DID "
            "and migrate. Mnemonic phrases must never appear in tracked code."
        ),
    ),
]
