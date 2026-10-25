"""SQLite persistence for structured audit events.

The audit log records operational metadata, not secrets or entire raw logs. Each
call uses a transaction. If an audit write fails, ``AuditError`` is raised so the
caller can stop a controlled action rather than silently proceed.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


class AuditError(RuntimeError):
    """Raised when audit storage cannot be initialized or written."""


_SENSITIVE_KEY_PARTS = (
    "api_key",
    "apikey",
    "token",
    "password",
    "passwd",
    "secret",
    "credential",
    "authorization",
    "private_key",
)
_REDACTED = "[REDACTED]"


def _redact(value: Any) -> Any:
    """Recursively redact mapping values whose field names indicate secrets."""
    if isinstance(value, Mapping):
        sanitized: dict[str, Any] = {}
        for key, child in value.items():
            key_text = str(key)
            normalized = key_text.casefold().replace("-", "_")
            if any(part in normalized for part in _SENSITIVE_KEY_PARTS):
                sanitized[key_text] = _REDACTED
            else:
                sanitized[key_text] = _redact(child)
        return sanitized
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise AuditError("Naive datetimes are not allowed in audit details")
        return value.astimezone(timezone.utc).isoformat()
    raise AuditError(f"Unsupported audit detail value type: {type(value).__name__}")


class AuditLogger:
    """Thread-safe SQLite audit logger with a small query API."""

    def __init__(self, database_path: str | Path) -> None:
        self.database_path = str(database_path)
        self._lock = threading.RLock()
        if self.database_path != ":memory:":
            path = Path(self.database_path).expanduser().resolve()
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise AuditError("Could not create audit database directory") from exc
            self.database_path = str(path)
        try:
            self._connection = sqlite3.connect(
                self.database_path,
                timeout=5.0,
                check_same_thread=False,
            )
            self._connection.row_factory = sqlite3.Row
            self._initialize_schema()
        except sqlite3.Error as exc:
            raise AuditError("Could not initialize audit database") from exc

    def _initialize_schema(self) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp_utc TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    action_id TEXT,
                    details_json TEXT NOT NULL
                )
                """
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_incident "
                "ON audit_events (incident_id, event_id)"
            )

    def record_event(
        self,
        event_type: str,
        incident_id: str,
        details: Mapping[str, Any],
        action_id: str | None = None,
    ) -> int:
        """Persist an event and return its database ID."""
        if not isinstance(event_type, str) or not event_type.strip():
            raise AuditError("event_type must be a non-empty string")
        if not isinstance(incident_id, str) or not incident_id.strip():
            raise AuditError("incident_id must be a non-empty string")
        if action_id is not None and (
            not isinstance(action_id, str) or not action_id.strip()
        ):
            raise AuditError("action_id must be None or a non-empty string")
        if not isinstance(details, Mapping):
            raise AuditError("details must be a mapping")

        try:
            safe_details = _redact(details)
            details_json = json.dumps(
                safe_details,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise AuditError("Audit details are not JSON-serializable") from exc

        timestamp = datetime.now(timezone.utc).isoformat()
        try:
            with self._lock, self._connection:
                cursor = self._connection.execute(
                    """
                    INSERT INTO audit_events
                        (timestamp_utc, event_type, incident_id,
                         action_id, details_json)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (timestamp, event_type, incident_id, action_id, details_json),
                )
                return int(cursor.lastrowid)
        except sqlite3.Error as exc:
            raise AuditError("Could not write audit event") from exc

    def list_events(
        self,
        *,
        incident_id: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Return recent events in insertion order, optionally filtered by incident."""
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 10_000
        ):
            raise ValueError("limit must be an integer between 1 and 10000")
        try:
            with self._lock:
                if incident_id is None:
                    rows = self._connection.execute(
                        """
                        SELECT event_id, timestamp_utc, event_type, incident_id,
                               action_id, details_json
                        FROM audit_events ORDER BY event_id ASC LIMIT ?
                        """,
                        (limit,),
                    ).fetchall()
                else:
                    rows = self._connection.execute(
                        """
                        SELECT event_id, timestamp_utc, event_type, incident_id,
                               action_id, details_json
                        FROM audit_events WHERE incident_id = ?
                        ORDER BY event_id ASC LIMIT ?
                        """,
                        (incident_id, limit),
                    ).fetchall()
        except sqlite3.Error as exc:
            raise AuditError("Could not read audit events") from exc

        return [
            {
                "event_id": row["event_id"],
                "timestamp_utc": row["timestamp_utc"],
                "event_type": row["event_type"],
                "incident_id": row["incident_id"],
                "action_id": row["action_id"],
                "details": json.loads(row["details_json"]),
            }
            for row in rows
        ]

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "AuditLogger":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()
