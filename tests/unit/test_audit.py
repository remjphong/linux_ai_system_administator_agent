"""Test AuditLogger — đối chiếu event trong SQLite."""
from __future__ import annotations

import sqlite3

from linux_admin.control.audit import AuditLogger


def test_init_db_creates_table(tmp_path):
    """Khởi tạo AuditLogger phải tạo bảng audit_events."""
    db_path = tmp_path / "test_audit.db"
    AuditLogger(db_path=db_path)

    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_events'"
        )
        assert cursor.fetchone() is not None


def test_log_event_persists_to_db(tmp_path):
    """Event ghi vào DB phải đọc lại được."""
    db_path = tmp_path / "test_audit.db"
    audit = AuditLogger(db_path=db_path)

    ok = audit.log_event(
        event_type="policy_decision",
        action_type="restart_service",
        target="test-app",
        decision="deny",
        details="Test reason",
    )
    assert ok is True

    events = audit.fetch_all()
    assert len(events) == 1
    assert events[0]["event_type"] == "policy_decision"
    assert events[0]["decision"] == "deny"
    assert events[0]["target"] == "test-app"


def test_multiple_events_ordered(tmp_path):
    """Nhiều event phải giữ thứ tự theo id."""
    db_path = tmp_path / "test_audit.db"
    audit = AuditLogger(db_path=db_path)

    audit.log_event("event1", decision="allow")
    audit.log_event("event2", decision="deny")
    audit.log_event("event3", decision="success")

    events = audit.fetch_all()
    assert len(events) == 3
    assert [e["event_type"] for e in events] == ["event1", "event2", "event3"]


def test_fetch_all_empty_on_fresh_db(tmp_path):
    """DB mới phải trả list rỗng."""
    db_path = tmp_path / "test_audit.db"
    audit = AuditLogger(db_path=db_path)
    assert audit.fetch_all() == []
