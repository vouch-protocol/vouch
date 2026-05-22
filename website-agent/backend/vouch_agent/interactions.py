"""Interaction log: every chat exchange is captured for quality analysis.

Storage: a single SQLite file at $VOUCH_INTERACTIONS_DB (default:
/data/interactions.db when a Fly volume is mounted, else ./interactions.db).
Append-only writes; no edits. Privacy: IPs are truncated to /24 (IPv4) or
/48 (IPv6); a 2-letter country code is captured when available; no
auth-bearer tokens or cookies are stored.

Schema:

    CREATE TABLE interactions (
        id              TEXT PRIMARY KEY,    -- uuid
        timestamp       TEXT NOT NULL,       -- ISO 8601 UTC
        question        TEXT NOT NULL,
        response        TEXT NOT NULL,       -- full streamed reply joined
        sources_json    TEXT,                -- JSON list of {source, score}
        ip_truncated    TEXT,                -- /24 of IPv4, /48 of IPv6
        country         TEXT,                -- ISO 3166-1 alpha-2 if known
        user_agent      TEXT,                -- truncated to 240 chars
        feedback_rating INTEGER,             -- 1 = helpful, -1 = unhelpful, NULL = no feedback
        feedback_comment TEXT,
        feedback_at     TEXT                 -- ISO 8601 UTC
    );

The CRUD surface stays minimal: `start_interaction` records an in-progress
chat as a row with question + IP only, returns an id the streaming
endpoint passes back to the client in the `meta` event. `complete_interaction`
fills response + sources after the stream finishes. `record_feedback`
adds the user's rating + optional comment.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from ipaddress import ip_address, IPv4Address, IPv6Address
from pathlib import Path
from typing import Any, Iterator

_DB_LOCK = threading.Lock()


def _default_db_path() -> Path:
    explicit = os.getenv("VOUCH_INTERACTIONS_DB")
    if explicit:
        return Path(explicit)
    # Prefer a mounted volume (Fly's default mount path is /data)
    if Path("/data").is_dir():
        return Path("/data/interactions.db")
    return Path(__file__).parent.parent / ".interactions.db"


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def truncate_ip(raw: str | None) -> str | None:
    """Return the network prefix (privacy-respecting): /24 for IPv4, /48 for IPv6."""
    if not raw:
        return None
    raw = raw.split(",")[0].strip()  # X-Forwarded-For may have list
    try:
        addr = ip_address(raw)
    except ValueError:
        return None
    if isinstance(addr, IPv4Address):
        octets = raw.split(".")
        return ".".join(octets[:3]) + ".0/24"
    if isinstance(addr, IPv6Address):
        # First three hextets, zero-pad the rest, /48
        parts = raw.split(":")
        return ":".join(parts[:3]) + "::/48"
    return None


class InteractionLog:
    """Thin wrapper over a SQLite file with append-only semantics."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _default_db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        with _DB_LOCK:
            conn = sqlite3.connect(str(self.path))
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            finally:
                conn.close()

    def _ensure_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS interactions (
                    id              TEXT PRIMARY KEY,
                    timestamp       TEXT NOT NULL,
                    question        TEXT NOT NULL,
                    response        TEXT,
                    sources_json    TEXT,
                    ip_truncated    TEXT,
                    country         TEXT,
                    user_agent      TEXT,
                    feedback_rating INTEGER,
                    feedback_comment TEXT,
                    feedback_at     TEXT,
                    from_followup_of TEXT
                );
                CREATE INDEX IF NOT EXISTS interactions_ts_idx ON interactions(timestamp);
                CREATE INDEX IF NOT EXISTS interactions_feedback_idx
                    ON interactions(feedback_rating) WHERE feedback_rating IS NOT NULL;
                """
            )
            # Existing Fly volumes already have the table without the new
            # column. ALTER TABLE ADD COLUMN is cheap on SQLite and safe to
            # run on every startup once it succeeds (subsequent runs raise
            # OperationalError, which we swallow).
            try:
                conn.execute("ALTER TABLE interactions ADD COLUMN from_followup_of TEXT")
            except sqlite3.OperationalError:
                pass
            conn.execute(
                "CREATE INDEX IF NOT EXISTS interactions_followup_idx "
                "ON interactions(from_followup_of) "
                "WHERE from_followup_of IS NOT NULL"
            )

    def start_interaction(
        self,
        *,
        question: str,
        ip: str | None,
        country: str | None,
        user_agent: str | None,
        from_followup_of: str | None = None,
    ) -> str:
        interaction_id = str(uuid.uuid4())
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO interactions
                    (id, timestamp, question, ip_truncated, country, user_agent,
                     from_followup_of)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    interaction_id,
                    _iso_now(),
                    question[:8000],
                    truncate_ip(ip),
                    (country or "")[:2].upper() or None,
                    (user_agent or "")[:240] or None,
                    (from_followup_of or None),
                ),
            )
        return interaction_id

    def complete_interaction(
        self,
        interaction_id: str,
        *,
        response: str,
        sources: list[dict[str, Any]] | None,
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                UPDATE interactions
                   SET response = ?, sources_json = ?
                 WHERE id = ? AND response IS NULL
                """,
                (
                    response[:64000],
                    json.dumps(sources or []),
                    interaction_id,
                ),
            )

    def record_feedback(
        self,
        interaction_id: str,
        *,
        rating: int,
        comment: str | None,
    ) -> bool:
        if rating not in (-1, 1):
            return False
        with self._conn() as conn:
            cur = conn.execute(
                """
                UPDATE interactions
                   SET feedback_rating = ?, feedback_comment = ?, feedback_at = ?
                 WHERE id = ?
                """,
                (rating, (comment or "")[:2000] or None, _iso_now(), interaction_id),
            )
            return cur.rowcount > 0

    def recent(
        self,
        *,
        limit: int = 50,
        only_with_feedback: bool = False,
    ) -> list[dict[str, Any]]:
        sql = """
            SELECT id, timestamp, question, response, sources_json,
                   ip_truncated, country, user_agent,
                   feedback_rating, feedback_comment, feedback_at,
                   from_followup_of
              FROM interactions
        """
        if only_with_feedback:
            sql += " WHERE feedback_rating IS NOT NULL"
        sql += " ORDER BY timestamp DESC LIMIT ?"
        with self._conn() as conn:
            rows = conn.execute(sql, (max(1, min(limit, 500)),)).fetchall()
        return [
            {
                "id": r["id"],
                "timestamp": r["timestamp"],
                "question": r["question"],
                "response": r["response"],
                "sources": json.loads(r["sources_json"] or "[]"),
                "ip_truncated": r["ip_truncated"],
                "country": r["country"],
                "user_agent": r["user_agent"],
                "feedback_rating": r["feedback_rating"],
                "feedback_comment": r["feedback_comment"],
                "feedback_at": r["feedback_at"],
                "from_followup_of": r["from_followup_of"],
            }
            for r in rows
        ]

    def summary(self) -> dict[str, Any]:
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM interactions").fetchone()[0]
            with_fb = conn.execute(
                "SELECT COUNT(*) FROM interactions WHERE feedback_rating IS NOT NULL"
            ).fetchone()[0]
            pos = conn.execute(
                "SELECT COUNT(*) FROM interactions WHERE feedback_rating = 1"
            ).fetchone()[0]
            neg = conn.execute(
                "SELECT COUNT(*) FROM interactions WHERE feedback_rating = -1"
            ).fetchone()[0]
            followup_clicks = conn.execute(
                "SELECT COUNT(*) FROM interactions WHERE from_followup_of IS NOT NULL"
            ).fetchone()[0]
            countries = [
                row[0]
                for row in conn.execute(
                    "SELECT DISTINCT country FROM interactions WHERE country IS NOT NULL"
                )
            ]
        return {
            "total_interactions": total,
            "with_feedback": with_fb,
            "thumbs_up": pos,
            "thumbs_down": neg,
            "followup_clicks": followup_clicks,
            "countries_seen": sorted(countries),
        }


_LOG: InteractionLog | None = None


def log() -> InteractionLog:
    global _LOG
    if _LOG is None:
        _LOG = InteractionLog()
    return _LOG
