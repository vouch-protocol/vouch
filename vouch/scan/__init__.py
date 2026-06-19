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

__all__ = [
    "scan_path",
    "scan_text",
    "scan_file",
    "Finding",
    "Severity",
    "Kind",
    "VOUCH_PATTERNS",
    "VouchPattern",
]
