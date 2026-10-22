"""Test tích hợp Executor + AuditLogger — đối chiếu event thực tế trong DB.

Mục tiêu:
- Deny → DB có policy_decision=deny, KHÔNG có action_start.
- Thiếu approval → DB có approval_missing, KHÔNG có action_start.
- Success → DB có action_start + action_result=success.
- Thứ tự event đúng.
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
def ctx(tmp_path):
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


def test_deny_flow_audit_events(ctx):
    """Deny → DB có policy_decision=deny, KHÔNG có action_start."""
    executor, _ = ctx
    executor.execute(ActionRequest("delete_files", "/tmp/x"))

    events = executor.audit.fetch_all()
    event_types = [e["event_type"] for e in events]

    assert "policy_decision" in event_types
    assert "action_start" not in event_types
    assert any(
        e["event_type"] == "policy_decision" and e["decision"] == "deny"
        for e in events
    )


def test_approval_missing_flow_audit_events(ctx):
    """Thiếu approval → DB có approval_missing, KHÔNG có action_start."""
    executor, _ = ctx
    executor.execute(ActionRequest("restart_service", "test-app"))

    events = executor.audit.fetch_all()
    event_types = [e["event_type"] for e in events]

    assert "approval_missing" in event_types
    assert "action_start" not in event_types


def test_success_flow_audit_events(ctx, monkeypatch):
    """Success → DB có action_start + action_result=success."""
    executor, approvals = ctx

    from linux_admin.tools.services import RestartServiceTool

    def fake_execute(self, service_name, is_dry_run=False, timeout=30):
        return ToolResult(success=True, tool_name=self.name, data={"mocked": True})

    monkeypatch.setattr(RestartServiceTool, "execute", fake_execute)

    approvals.request("restart_service", "test-app", {})
    approvals.grant("restart_service", "test-app", {})

    executor.execute(ActionRequest("restart_service", "test-app"))

    events = executor.audit.fetch_all()
    event_types = [e["event_type"] for e in events]

    assert "action_start" in event_types
    assert "action_result" in event_types
    assert any(
        e["event_type"] == "action_result" and e["decision"] == "success"
        for e in events
    )


def test_full_flow_event_order(ctx, monkeypatch):
    """Thứ tự event phải đúng: policy_decision → action_start → action_result."""
    executor, approvals = ctx

    from linux_admin.tools.services import RestartServiceTool

    def fake_execute(self, service_name, is_dry_run=False, timeout=30):
        return ToolResult(success=True, tool_name=self.name, data={})

    monkeypatch.setattr(RestartServiceTool, "execute", fake_execute)

    approvals.request("restart_service", "test-app", {})
    approvals.grant("restart_service", "test-app", {})
    executor.execute(ActionRequest("restart_service", "test-app"))

    events = executor.audit.fetch_all()
    event_types = [e["event_type"] for e in events]

    idx_policy = event_types.index("policy_decision")
    idx_start = event_types.index("action_start")
    idx_result = event_types.index("action_result")

    assert idx_policy < idx_start < idx_result
