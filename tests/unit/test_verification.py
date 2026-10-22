from __future__ import annotations

from linux_admin.control.audit import AuditLogger
from linux_admin.verification.recovery_manager import handle_recovery


def test_recovery_success_first_attempt(tmp_path):
    audit = AuditLogger(db_path=tmp_path / "audit.db")
    outcome = handle_recovery(
        action_type="restart_service",
        target="test-app",
        attempt_action=lambda: True,
        verify=lambda: True,
        audit=audit,
    )
    assert outcome.recovered is True
    assert outcome.attempts == 1


def test_recovery_exhausted(tmp_path):
    audit = AuditLogger(db_path=tmp_path / "audit.db")
    outcome = handle_recovery(
        action_type="restart_service",
        target="test-app",
        attempt_action=lambda: True,
        verify=lambda: False,
        audit=audit,
        max_retries=2,
    )
    assert outcome.recovered is False
    assert outcome.attempts == 2
    assert outcome.final_status == "failed"

