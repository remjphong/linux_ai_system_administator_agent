from __future__ import annotations

import pytest
import yaml

from linux_admin.control.policy_engine import PolicyEngine


@pytest.fixture
def policy_yaml(tmp_path):
    """Tạo policy.yaml đúng schema nhóm trưởng, dạng tham số hóa."""
    def _make(restart_allowed=False, inspect_allowed=True):
        cfg = {
            "policy": {
                "default_decision": "deny",
                "require_approval_for_disruptive_actions": True,
                "allow_privilege_escalation": False,
            },
            "actions": {
                "inspect_system": {
                    "allowed": inspect_allowed,
                    "requires_approval": False,
                },
                "read_service_logs": {
                    "allowed": True,
                    "requires_approval": False,
                },
                "restart_service": {
                    "allowed": restart_allowed,
                    "requires_approval": True,
                },
                "delete_files": {
                    "allowed": False,
                    "requires_approval": True,
                },
            },
        }
        p = tmp_path / "policy.yaml"
        p.write_text(yaml.safe_dump(cfg))
        return p
    return _make


@pytest.fixture
def services_yaml(tmp_path):
    p = tmp_path / "services.yaml"
    p.write_text(yaml.safe_dump({
        "allowed_services": ["nginx", "test-app", "ssh"],
        "test_service_for_restart": "test-app",
        "systemctl_timeout": 30,
    }))
    return p


def test_restart_blocked_when_allowed_false(policy_yaml, services_yaml):
    """Schema thật: restart_service.allowed = false → DENY tuyệt đối."""
    p = policy_yaml(restart_allowed=False)
    eng = PolicyEngine(policy_path=p, services_path=services_yaml)
    d = eng.evaluate_action("restart_service", "test-app")
    assert d.allowed is False
    assert "allowed: false" in d.reason or "bị chặn" in d.reason


def test_restart_requires_approval_when_allowed_true(policy_yaml, services_yaml):
    """Khi nhóm trưởng đổi allowed: true → cần approval, chưa allow tuyệt đối."""
    p = policy_yaml(restart_allowed=True)
    eng = PolicyEngine(policy_path=p, services_path=services_yaml)
    d = eng.evaluate_action("restart_service", "test-app")
    assert d.allowed is True
    assert d.requires_approval is True


def test_inspect_system_allowed_no_approval(policy_yaml, services_yaml):
    p = policy_yaml()
    eng = PolicyEngine(policy_path=p, services_path=services_yaml)
    d = eng.evaluate_action("inspect_system")
    assert d.allowed is True
    assert d.requires_approval is False


def test_delete_files_denied(policy_yaml, services_yaml):
    p = policy_yaml()
    eng = PolicyEngine(policy_path=p, services_path=services_yaml)
    d = eng.evaluate_action("delete_files", "/etc/passwd")
    assert d.allowed is False


def test_unknown_action_uses_default_deny(policy_yaml, services_yaml):
    p = policy_yaml()
    eng = PolicyEngine(policy_path=p, services_path=services_yaml)
    d = eng.evaluate_action("format_disk", "/dev/sda")
    assert d.allowed is False
    assert "default_decision" in d.reason or "không được khai báo" in d.reason


def test_privilege_escalation_denied(policy_yaml, services_yaml):
    p = policy_yaml()
    eng = PolicyEngine(policy_path=p, services_path=services_yaml)
    d = eng.evaluate_action("sudo", "anything")
    assert d.allowed is False
    assert "Privilege escalation" in d.reason


def test_fail_closed_missing_files(tmp_path):
    eng = PolicyEngine(
        policy_path=tmp_path / "missing.yaml",
        services_path=tmp_path / "missing2.yaml",
    )
    d = eng.evaluate_action("inspect_system")
    # Không có actions block → default_decision = deny (vì thiếu config)
    assert d.allowed is False
def test_restart_service_outside_allowlist_denied(policy_yaml, services_yaml):
    """restart_service với service không có trong allowlist → deny."""
    p = policy_yaml(restart_allowed=True)
    eng = PolicyEngine(policy_path=p, services_path=services_yaml)
    d = eng.evaluate_action("restart_service", "mysql")
    assert d.allowed is False
    assert "allowlist" in d.reason


def test_restart_service_in_allowlist_but_not_test_service_denied(
    policy_yaml, services_yaml
):
    """restart_service với service trong allowlist nhưng không phải test service → deny."""
    p = policy_yaml(restart_allowed=True)
    eng = PolicyEngine(policy_path=p, services_path=services_yaml)
    d = eng.evaluate_action("restart_service", "nginx")
    assert d.allowed is False
    assert "test-app" in d.reason
