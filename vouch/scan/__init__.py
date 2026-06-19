"""Vouch leak scanner.

A static analyzer that detects Vouch-Protocol-shaped cryptographic
key material in source repositories. Generic secret scanners
(TruffleHog, gitleaks, GitHub Secret Scanning) miss Vouch-shaped
material because the shape is JWK-with-`d`-field or seed-near-Vouch-
config rather than the high-entropy prefixed-string shape they look
for.

This module implements PAD-058's detection stage. The rotation
pipeline (stages 2-6) is the commercial Pro tier; this module is
the OSS detector.

Usage from Python:

    from vouch.scan import scan_path, Finding, Severity

    findings = scan_path("./my-repo")
    for f in findings:
        print(f.kind, f.file, f.line, f.severity)

Usage from CLI:

    vouch scan ./my-repo
    vouch scan ./my-repo --json
    vouch scan ./my-repo --exit-nonzero-on critical
"""

from .detector import scan_path, scan_text, scan_file, Finding, Severity, Kind
from .patterns import VOUCH_PATTERNS, VouchPattern
from .secret_patterns import GENERIC_SECRET_PATTERNS


def patterns_for(include_secrets: bool = False) -> list[VouchPattern]:
    """Return the pattern set to scan with.

    Default is Vouch-shaped key material only. With `include_secrets`,
    the common provider-secret patterns (AWS, GitHub, Stripe, PEM keys,
    and more) are appended, turning the scanner into a general-purpose
    secret scanner with Vouch detection still included.
    """
    if include_secrets:
        return [*VOUCH_PATTERNS, *GENERIC_SECRET_PATTERNS]
    return list(VOUCH_PATTERNS)


__all__ = [
    "scan_path",
    "scan_text",
    "scan_file",
    "Finding",
    "Severity",
    "Kind",
    "VOUCH_PATTERNS",
    "GENERIC_SECRET_PATTERNS",
    "VouchPattern",
    "patterns_for",
]
