from __future__ import annotations

from linux_admin.control.approval import ApprovalManager


def test_request_then_grant_then_check():
    m = ApprovalManager(ttl_seconds=60)
    m.request("restart_service", "test-app", {"x": 1})
    assert m.check("restart_service", "test-app", {"x": 1}) is False
    m.grant("restart_service", "test-app", {"x": 1})
    assert m.check("restart_service", "test-app", {"x": 1}) is True


def test_wrong_parameters_do_not_match():
    m = ApprovalManager(ttl_seconds=60)
    m.request("restart_service", "test-app", {"x": 1})
    m.grant("restart_service", "test-app", {"x": 1})
    assert m.check("restart_service", "test-app", {"x": 2}) is False


def test_expired_approval_rejected():
    m = ApprovalManager(ttl_seconds=0)
    m.request("restart_service", "test-app")
    m.grant("restart_service", "test-app")
    assert m.check("restart_service", "test-app") is False

