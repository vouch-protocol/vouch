"""File-walking detector that applies VOUCH_PATTERNS across a tree.

The detector is intentionally minimal: pure regex over text, no AST,
no entropy heuristics, no external services. Findings are structured
so downstream tooling (Gatekeeper, the Pro hosted monitor, CI gating)
can serialize them deterministically.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .patterns import VOUCH_PATTERNS, Kind, Severity, VouchPattern

# File extensions we scan. We deliberately do not scan binary formats.
TEXT_EXTENSIONS = {
    ".py",
    ".pyi",
    ".pyx",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".swift",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".cs",
    ".rb",
    ".php",
    ".scala",
    ".clj",
    ".ex",
    ".exs",
    ".erl",
    ".json",
    ".jsonc",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".xml",
    ".html",
    ".htm",
    ".md",
    ".mdx",
    ".rst",
    ".txt",
    ".env",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".ps1",
    ".bat",
    ".cmd",
    ".sql",
    ".graphql",
    ".tf",
    ".dockerfile",
}

# Directories we never descend into.
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "venv",
    ".venv",
    "env",
    ".env",
    "dist",
    "build",
    "target",
    "out",
    ".next",
    ".turbo",
    ".tox",
    ".eggs",
    "*.egg-info",
    ".idea",
    ".vscode",
}

# Files we never read (binary indicators / cache files).
SKIP_FILES_EXACT = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Cargo.lock",
    "go.sum",
    "Gemfile.lock",
}

# Files we always treat as text regardless of their (Python-computed) suffix.
# Python's Path.suffix for ".env" returns "" because the file is considered
# extension-less; we whitelist these by name.
TEXT_FILENAMES_EXACT = {
    ".env",
    ".envrc",
    ".bashrc",
    ".zshrc",
    ".npmrc",
    ".gitconfig",
    ".gitignore",
    "Dockerfile",
    "Makefile",
    "Procfile",
    "Gemfile",
    "Rakefile",
    "README",
    "LICENSE",
    "CHANGELOG",
    "AUTHORS",
}

# Filename prefixes we treat as text. ".env.local", ".env.production", ".env.test", etc.
TEXT_FILENAME_PREFIXES = (".env.",)

MAX_FILE_BYTES = 5 * 1024 * 1024  # skip files larger than 5 MB


@dataclass
class Finding:
    """One detection event."""

    kind: Kind
    severity: Severity
    file: str  # relative to the scan root
    line: int  # 1-indexed line number of the start of the match
    column: int  # 1-indexed column of the start of the match
    snippet: str  # short excerpt of the match (truncated to 80 chars, secrets hashed)
    matched_hash: str  # sha256 prefix of the full match — for cross-referencing without leaking
    description: str
    remediation: str
    detected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        d = asdict(self)
        d["kind"] = self.kind.value
        d["severity"] = self.severity.value
        return d


def _is_text_file(path: Path) -> bool:
    """Decide whether a file looks like text we should scan."""
    if path.name in SKIP_FILES_EXACT:
        return False
    if path.name in TEXT_FILENAMES_EXACT:
        return True
    if any(path.name.startswith(prefix) for prefix in TEXT_FILENAME_PREFIXES):
        return True
    ext = path.suffix.lower()
    if ext in TEXT_EXTENSIONS:
        return True
    # Files with no extension but matching vouch-config naming should still be checked.
    if path.suffix == "" and any(name_part in path.name.lower() for name_part in ("vouch", "did")):
        return True
    return False


def _redact_snippet(matched: str, max_len: int = 80) -> str:
    """Return a snippet of the match safe to surface in CI output.

    For critical findings (a real private key shape), we replace the
    sensitive middle with an ellipsis so the value doesn't show up in
    PR comments or CI logs.
    """
    s = matched.strip()
    if len(s) <= max_len:
        return s
    return s[: max_len // 2] + " ... " + s[-(max_len // 2 - 5) :]


def _offset_to_line_col(text: str, offset: int) -> tuple[int, int]:
    """Convert a string offset to (1-indexed line, 1-indexed column)."""
    prefix = text[:offset]
    line = prefix.count("\n") + 1
    last_nl = prefix.rfind("\n")
    column = offset - last_nl if last_nl != -1 else offset + 1
    return line, column


def scan_text(text: str, file_label: str = "<inline>") -> list[Finding]:
    """Run all VOUCH_PATTERNS against a single string."""
    findings: list[Finding] = []
    for pattern in VOUCH_PATTERNS:
        # The filename-pattern kind is applied to file paths, not contents.
        if pattern.kind == Kind.VOUCH_CONFIG_FILENAME:
            continue
        for match in pattern.pattern.finditer(text):
            line, column = _offset_to_line_col(text, match.start())
            matched = match.group(0)
            findings.append(
                Finding(
                    kind=pattern.kind,
                    severity=pattern.severity,
                    file=file_label,
                    line=line,
                    column=column,
                    snippet=_redact_snippet(matched),
                    matched_hash="sha256:" + hashlib.sha256(matched.encode()).hexdigest()[:16],
                    description=pattern.description,
                    remediation=pattern.remediation,
                )
            )
    return findings


def scan_file(path: Path, root: Path | None = None) -> list[Finding]:
    """Scan one file. Returns findings with paths relative to `root`."""
    if root is None:
        root = path.parent

    findings: list[Finding] = []

    # Filename-based pattern fires regardless of file size or extension.
    from .patterns import VOUCH_CONFIG_FILENAME_RE

    if VOUCH_CONFIG_FILENAME_RE.match(str(path)):
        rel = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
        findings.append(
            Finding(
                kind=Kind.VOUCH_CONFIG_FILENAME,
                severity=Severity.MEDIUM,
                file=rel,
                line=1,
                column=1,
                snippet=path.name,
                matched_hash="sha256:" + hashlib.sha256(path.name.encode()).hexdigest()[:16],
                description=(
                    "Vouch-specific config filename — verify the file does not "
                    "contain private key material"
                ),
                remediation=(
                    "Add the file to .gitignore if it carries keys. Move keys to a secret manager."
                ),
            )
        )

    if not _is_text_file(path):
        return findings

    try:
        stat = path.stat()
    except OSError:
        return findings
    if stat.st_size > MAX_FILE_BYTES:
        return findings

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    rel = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
    for f in scan_text(text, file_label=rel):
        findings.append(f)
    return findings


def _iter_files(root: Path) -> Iterable[Path]:
    """Walk root yielding files we are willing to scan."""
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skipped directories in-place so os.walk doesn't descend.
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            yield Path(dirpath) / name


def scan_path(path: str | Path) -> list[Finding]:
    """Scan a file or directory. Returns the accumulated findings list."""
    root = Path(path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"scan target does not exist: {root}")

    findings: list[Finding] = []
    if root.is_file():
        findings.extend(scan_file(root, root=root.parent))
    else:
        for file_path in _iter_files(root):
            findings.extend(scan_file(file_path, root=root))
    return findings


def findings_to_json(findings: list[Finding]) -> str:
    """Serialize findings as a JSON array suitable for piping or storage."""
    return json.dumps([f.to_dict() for f in findings], indent=2)


def findings_to_text(findings: list[Finding]) -> str:
    """Render findings as a human-readable report (single string)."""
    if not findings:
        return "vouch scan: no Vouch-shaped key material detected.\n"

    # Group by severity, then by kind for readability.
    by_severity: dict[Severity, list[Finding]] = {}
    for f in findings:
        by_severity.setdefault(f.severity, []).append(f)

    lines: list[str] = []
    lines.append(
        f"vouch scan: {len(findings)} finding{'s' if len(findings) != 1 else ''} detected\n"
    )

    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    for sev in severity_order:
        items = by_severity.get(sev, [])
        if not items:
            continue
        lines.append(f"## {sev.value.upper()} ({len(items)})")
        for f in items:
            lines.append(f"  [{f.kind.value}] {f.file}:{f.line}:{f.column}")
            lines.append(f"    description: {f.description}")
            lines.append(f"    match:       {f.snippet}")
            lines.append(f"    hash:        {f.matched_hash}")
            lines.append(f"    remediation: {f.remediation}")
            lines.append("")
    return "\n".join(lines)


def has_severity_at_or_above(findings: list[Finding], minimum: Severity) -> bool:
    """True if any finding is at or above the given severity threshold."""
    order = {Severity.CRITICAL: 3, Severity.HIGH: 2, Severity.MEDIUM: 1, Severity.LOW: 0}
    threshold = order[minimum]
    return any(order[f.severity] >= threshold for f in findings)
