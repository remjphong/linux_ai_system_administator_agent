"""Audit — ghi mọi quyết định policy, action, verification vào SQLite."""
from __future__ import annotations

import logging
import sqlite3
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = "audit.db"


class AuditLogger:
    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        action_type TEXT,
                        target TEXT,
                        decision TEXT,
                        details TEXT
                    )
                    """
                )
                conn.commit()
        except sqlite3.Error as exc:
            logger.error("Không khởi tạo được audit DB: %s", exc)

    def log_event(
        self,
        event_type: str,
        action_type: str = "",
        target: str = "",
        decision: str = "",
        details: str = "",
    ) -> bool:
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO audit_events
                        (timestamp, event_type, action_type, target, decision, details)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        datetime.now().isoformat(),
                        event_type,
                        action_type,
                        target,
                        decision,
                        details,
                    ),
                )
                conn.commit()
            return True
        except sqlite3.Error as exc:
            logger.error("Ghi audit thất bại: %s", exc)
            return False

    def fetch_all(self) -> list[dict]:
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM audit_events ORDER BY id ASC"
                ).fetchall()
                return [dict(r) for r in rows]
        except sqlite3.Error as exc:
            logger.error("Đọc audit thất bại: %s", exc)
            return []
