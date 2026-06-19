"""Environment-driven configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _load_dotenv() -> None:
    """Minimal .env loader so we do not require an extra dependency.

    Reads website-agent/.env (one level above the backend package) and
    populates os.environ for any key that is not already set. Quotes are
    stripped; blank lines and comments are ignored.
    """
    candidates = [
        Path(__file__).resolve().parent.parent.parent / ".env",       # website-agent/.env
        Path(__file__).resolve().parent.parent / ".env",              # backend/.env
        Path.cwd() / ".env",
    ]
    for path in candidates:
        if not path.exists():
            continue
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip("'\"")
            if key and key not in os.environ:
                os.environ[key] = value


_load_dotenv()


@dataclass(frozen=True)
class Config:
    sidecar_url: str = field(default_factory=lambda: os.getenv("VOUCH_SIDECAR_URL", "http://localhost:8877"))
    anthropic_api_key: str | None = field(default_factory=lambda: os.getenv("ANTHROPIC_API_KEY"))
    anthropic_model: str = field(default_factory=lambda: os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6"))
    knowledge_dir: Path = field(
        default_factory=lambda: Path(os.getenv("VOUCH_KNOWLEDGE_DIR", str(Path(__file__).parent.parent / "knowledge")))
    )
    index_dir: Path = field(
        default_factory=lambda: Path(os.getenv("VOUCH_INDEX_DIR", str(Path(__file__).parent.parent / ".index")))
    )
    audit_log_path: Path = field(
        default_factory=lambda: Path(os.getenv("VOUCH_AUDIT_LOG", str(Path(__file__).parent.parent / ".audit.jsonl")))
    )
    agent_did: str = field(default_factory=lambda: os.getenv("VOUCH_AGENT_DID", "did:web:agent.vouch-protocol.org"))
    cors_allow_origins: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            o.strip() for o in os.getenv("VOUCH_CORS_ORIGINS", "http://localhost:3000,https://vouch-protocol.org").split(",") if o.strip()
        )
    )
    max_context_chunks: int = 6
    chunk_chars: int = 1200
    chunk_overlap: int = 200


CONFIG = Config()
