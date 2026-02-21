"""
Vouch Shield - Flight Recorder (Audit Logger).

Logs all agent actions for compliance and forensics.
Integrates with the existing Vouch auditor infrastructure.
"""

import os
import json
import time
import logging
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)


class EventType(Enum):
    """Types of logged events."""

    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    ERROR = "ERROR"
    SESSION_START = "SESSION_START"
    SESSION_END = "SESSION_END"


@dataclass
class LogEntry:
    """A single audit log entry."""

    timestamp: str
    event: str
    did: Optional[str] = None
    tool: Optional[str] = None
    args: Optional[Dict[str, Any]] = None
    reason: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        return {k: v for k, v in asdict(self).items() if v is not None}

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())


class FlightRecorder:
    """
    Records all agent actions for audit and compliance.

    Example:
        >>> recorder = FlightRecorder()
        >>> recorder.allowed("did:vouch:agent", "read_file", {"path": "/data"})
        >>> recorder.blocked("did:vouch:bad", "run_command", "DID not trusted")
        >>> stats = recorder.get_stats()
    """

    def __init__(
        self,
        log_path: Optional[str] = None,
        max_file_size: int = 10 * 1024 * 1024,  # 10 MB
        buffer_size: int = 100,
    ):
        """
        Initialize the flight recorder.

        Args:
            log_path: Path to the log file.
            max_file_size: Maximum size before rotation (bytes).
            buffer_size: Number of entries to buffer before flush.
        """
        self._log_path = log_path or self._default_log_path()
        self._max_file_size = max_file_size
        self._buffer_size = buffer_size
        self._buffer: List[LogEntry] = []

        self._ensure_directory()

    def _default_log_path(self) -> str:
        """Get default log path."""
        vouch_dir = Path.home() / ".vouch" / "logs"
        vouch_dir.mkdir(parents=True, exist_ok=True)
        return str(vouch_dir / "flight_recorder.log")

    def _ensure_directory(self) -> None:
        """Ensure log directory exists."""
        Path(self._log_path).parent.mkdir(parents=True, exist_ok=True)

    def log(
        self,
        event: EventType,
        did: Optional[str] = None,
        tool: Optional[str] = None,
        args: Optional[Dict[str, Any]] = None,
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log an event."""
        entry = LogEntry(
            timestamp=datetime.utcnow().isoformat() + "Z",
            event=event.value,
            did=did,
            tool=tool,
            args=args,
            reason=reason,
            metadata=metadata,
        )

        self._buffer.append(entry)

        # Immediate flush for important events
        if event in (EventType.BLOCKED, EventType.ERROR):
            self.flush()
        elif len(self._buffer) >= self._buffer_size:
            self.flush()

    def allowed(self, did: str, tool: str, args: Optional[Dict[str, Any]] = None) -> None:
        """Log an allowed action."""
        self.log(EventType.ALLOWED, did=did, tool=tool, args=args)

    def blocked(
        self,
        did: str,
        tool: str,
        reason: str,
        args: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log a blocked action."""
        self.log(EventType.BLOCKED, did=did, tool=tool, reason=reason, args=args)

    def error(self, message: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Log an error."""
        self.log(EventType.ERROR, reason=message, metadata=metadata)

    def session_start(self, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Log session start."""
        self.log(EventType.SESSION_START, metadata=metadata)

    def session_end(self, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Log session end."""
        self.log(EventType.SESSION_END, metadata=metadata)

    def flush(self) -> None:
        """Flush buffer to disk."""
        if not self._buffer:
            return

        try:
            entries = self._buffer[:]
            self._buffer.clear()

            with open(self._log_path, "a") as f:
                for entry in entries:
                    f.write(entry.to_json() + "\n")

            self._rotate_if_needed()
        except Exception as e:
            logger.error(f"Flight recorder flush failed: {e}")

    def _rotate_if_needed(self) -> None:
        """Rotate log file if it exceeds max size."""
        try:
            if os.path.getsize(self._log_path) > self._max_file_size:
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                rotated = self._log_path.replace(".log", f".{timestamp}.log")
                os.rename(self._log_path, rotated)
                logger.info(f"Rotated log to {rotated}")
        except Exception:
            pass

    def read_recent(self, count: int = 100) -> List[LogEntry]:
        """Read recent log entries."""
        try:
            if not os.path.exists(self._log_path):
                return []

            with open(self._log_path, "r") as f:
                lines = f.readlines()[-count:]

            entries = []
            for line in lines:
                try:
                    data = json.loads(line.strip())
                    entries.append(LogEntry(**data))
                except Exception:
                    pass

            return entries
        except Exception:
            return []

    def get_stats(self) -> Dict[str, int]:
        """Get statistics from the log."""
        entries = self.read_recent(10000)
        return {
            "allowed": sum(1 for e in entries if e.event == "ALLOWED"),
            "blocked": sum(1 for e in entries if e.event == "BLOCKED"),
            "errors": sum(1 for e in entries if e.event == "ERROR"),
            "total": len(entries),
        }

    def shutdown(self) -> None:
        """Flush and close the recorder."""
        self.session_end()
        self.flush()
