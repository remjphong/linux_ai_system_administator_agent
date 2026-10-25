import pytest
import yaml

from linux_admin.contracts import ActionRequest
from linux_admin.control import ApprovalManager, ControlledExecutor, PolicyEngine


@pytest.fixture
def test_env(tmp_path):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        yaml.safe_dump({
            "policy": {"default_decision": "deny"},
            "actions": {
                "restart_service": {"allowed": True, "requires_approval": True},
                "inspect_system": {"allowed": True, "requires_approval": False},
            },
        })
    )
    services_file = tmp_path / "services.yaml"
    services_file.write_text(
        yaml.safe_dump({
            "services": {"allowlist": ["test-app"], "restart_enabled": True},
        })
    )
    policy = PolicyEngine(policy_path=policy_file, services_path=services_file)
    approvals = ApprovalManager()
    executor = ControlledExecutor(policy=policy, approvals=approvals)
    return executor, approvals

def test_action_without_rule_denied(test_env):
    executor, _ = test_env
    req = ActionRequest(action_name="hack_system", arguments={}, reason="test")
    decision, tool_res = executor.execute(req)
    assert decision.outcome == "deny"
    assert tool_res is None

def test_service_outside_allowlist_denied(test_env):
    executor, _ = test_env
    req = ActionRequest(action_name="restart_service", arguments={"service_name": "mysql"}, reason="test")
    decision, _tool_res = executor.execute(req)
    assert decision.outcome == "deny"
    assert "allowlist" in decision.reason

def test_restart_requires_approval(test_env):
    executor, _ = test_env
    req = ActionRequest(action_name="restart_service", arguments={"service_name": "test-app", "dry_run": True}, reason="test")
    decision, _tool_res = executor.execute(req)
    assert decision.outcome == "approval_required"
    assert _tool_res is None

def test_approval_success(test_env):
    executor, approvals = test_env
    req = ActionRequest(action_name="restart_service", arguments={"service_name": "test-app", "dry_run": True}, reason="test")
    approvals.grant(req)
    _decision, tool_res = executor.execute(req)
    assert tool_res is not None
    assert tool_res.status == "success"

def test_approval_wrong_params_rejected(test_env):
    executor, approvals = test_env
    req_ok = ActionRequest(action_name="restart_service", arguments={"service_name": "test-app"}, reason="ok")
    approvals.grant(req_ok)
    req_hacked = ActionRequest(action_name="restart_service", arguments={"service_name": "test-app", "force": True}, reason="hacked")
    object.__setattr__(req_hacked, "action_id", req_ok.action_id)
    decision, tool_res = executor.execute(req_hacked)
    assert decision.outcome == "approval_required"
    assert tool_res is None

def test_approval_for_action_a_not_usable_for_action_b(test_env):
    executor, approvals = test_env
    req_a = ActionRequest(action_name="restart_service", arguments={"service_name": "test-app", "dry_run": True}, reason="A")
    approvals.grant(req_a)
    req_b = ActionRequest(action_name="restart_service", arguments={"service_name": "test-app", "dry_run": True}, reason="B")
    decision, tool_res = executor.execute(req_b)
    assert decision.outcome == "approval_required"
    assert tool_res is None

def test_dry_run_does_not_call_systemctl(test_env, monkeypatch):
    executor, approvals = test_env
    calls = {"n": 0}
    def fake_restart(service_name, is_dry_run=True, timeout=30):
        from linux_admin.contracts import ToolResult
        calls["n"] += 1
        assert is_dry_run is True
        return ToolResult(tool_name="restart_service", status="success", data={"dry_run": True})
    monkeypatch.setattr("linux_admin.tools.services.restart_service", fake_restart)
    req = ActionRequest(action_name="restart_service", arguments={"service_name": "test-app", "dry_run": True}, reason="test dry-run")
    approvals.grant(req)
    executor.execute(req)
    assert calls["n"] == 1
