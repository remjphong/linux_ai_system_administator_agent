"""Unit test cho Executor — chứng minh fail-closed ở mọi bước.

Bao phủ:
- Policy deny → không gọi tool.
- Policy yêu cầu approval nhưng thiếu → không gọi tool.
- Có approval → dispatch được gọi (mock, không chạm systemd thật).
- Audit ghi event khi deny.
"""
from __future__ import annotations

import pytest
import yaml

from linux_admin.control.approval import ApprovalManager
from linux_admin.control.audit import AuditLogger
from linux_admin.control.executor import Executor
from linux_admin.control.policy_engine import PolicyEngine
from linux_admin.core.contracts import ActionRequest, ToolResult


@pytest.fixture
def exec_ctx(tmp_path):
    """Policy cho test: restart allowed=true (cần approval), delete_files deny.

    Dùng schema thật của nhóm trưởng (policy + actions).
    """
    policy_cfg = {
        "policy": {
            "default_decision": "deny",
            "require_approval_for_disruptive_actions": True,
            "allow_privilege_escalation": False,
        },
        "actions": {
            "inspect_system": {"allowed": True, "requires_approval": False},
            "restart_service": {"allowed": True, "requires_approval": True},
            "delete_files": {"allowed": False, "requires_approval": True},
        },
    }
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(yaml.safe_dump(policy_cfg))

    services_file = tmp_path / "services.yaml"
    services_file.write_text(
        yaml.safe_dump(
            {
                "allowed_services": ["test-app"],
                "test_service_for_restart": "test-app",
                "systemctl_timeout": 30,
            }
        )
    )

    policy = PolicyEngine(policy_path=policy_file, services_path=services_file)
    approvals = ApprovalManager(ttl_seconds=60)
    audit = AuditLogger(db_path=tmp_path / "audit.db")
    return Executor(policy=policy, approvals=approvals, audit=audit), approvals


# --------------------------------------------------------------------- deny
def test_denied_action_not_dispatched(exec_ctx):
    """delete_files.allowed=false → status denied, không dispatch."""
    executor, _ = exec_ctx
    result = executor.execute(ActionRequest("delete_files", "/tmp/x"))
    assert result.ok is False
    assert result.status == "denied"
    assert result.policy_decision is not None
    assert result.policy_decision.allowed is False


def test_unknown_action_denied_by_default(exec_ctx):
    """Action không khai báo → default_decision=deny."""
    executor, _ = exec_ctx
    result = executor.execute(ActionRequest("format_disk", "/dev/sda"))
    assert result.ok is False
    assert result.status == "denied"


# ---------------------------------------------------------------- approval
def test_requires_approval_blocks_without_grant(exec_ctx):
    """restart_service.allowed=true nhưng requires_approval=true, chưa grant → approval_required."""
    executor, _ = exec_ctx
    result = executor.execute(ActionRequest("restart_service", "test-app"))
    assert result.ok is False
    assert result.status == "approval_required"


def test_approved_action_reaches_dispatch(exec_ctx, monkeypatch):
    """Sau approval, executor phải gọi được tool adapter.

    Dùng monkeypatch để KHÔNG gọi systemctl thật trên máy test.
    """
    executor, approvals = exec_ctx

    from linux_admin.tools.services import RestartServiceTool

    def fake_execute(self, service_name, is_dry_run=False, timeout=30):
        return ToolResult(
            success=True,
            tool_name=self.name,
            data={"service": service_name, "mocked": True},
        )

    monkeypatch.setattr(RestartServiceTool, "execute", fake_execute)

    approvals.request("restart_service", "test-app", {})
    approvals.grant("restart_service", "test-app", {})

    result = executor.execute(ActionRequest("restart_service", "test-app"))
    assert result.ok is True
    assert result.status == "success"
    assert result.data.get("mocked") is True


# ------------------------------------------------------------------- audit
def test_audit_written_on_deny(exec_ctx):
    """Khi policy deny, audit phải có event với decision=deny."""
    executor, _ = exec_ctx
    executor.execute(ActionRequest("delete_files", "/tmp/x"))
    events = executor.audit.fetch_all()
    assert any(e["decision"] == "deny" for e in events)


def test_audit_written_on_approval_missing(exec_ctx):
    """Khi thiếu approval, audit phải có event approval_missing."""
    executor, _ = exec_ctx
    executor.execute(ActionRequest("restart_service", "test-app"))
    events = executor.audit.fetch_all()
    assert any(e["event_type"] == "approval_missing" for e in events)


def test_audit_written_on_success(exec_ctx, monkeypatch):
    """Khi dispatch thành công, audit phải có action_result decision=success."""
    executor, approvals = exec_ctx

    from linux_admin.tools.services import RestartServiceTool

    def fake_execute(self, service_name, is_dry_run=False, timeout=30):
        return ToolResult(
            success=True, tool_name=self.name, data={"mocked": True}
        )

    monkeypatch.setattr(RestartServiceTool, "execute", fake_execute)

    approvals.request("restart_service", "test-app", {})
    approvals.grant("restart_service", "test-app", {})
    executor.execute(ActionRequest("restart_service", "test-app"))

    events = executor.audit.fetch_all()
    success_events = [
        e
        for e in events
        if e["event_type"] == "action_result" and e["decision"] == "success"
    ]
    assert len(success_events) == 1
