"""Policy/approval/executor boundary tests; no test restarts a real service."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from linux_admin.audit import AuditError
from linux_admin.config import ActionPolicy
from linux_admin.contracts import ActionRequest, ApprovalRecord, ToolResult, ToolSpec
from linux_admin.control import ApprovalManager, ControlledExecutor, PolicyEngine
from linux_admin.registry import ToolRegistry


class CountingRestartTool:
    spec = ToolSpec(
        name="restart_service",
        description="Test double for the state-changing restart adapter.",
        parameters={
            "type": "object",
            "properties": {"service_name": {"type": "string", "minLength": 1}},
            "required": ["service_name"],
            "additionalProperties": False,
        },
        risk_level="high",
        changes_system=True,
        requires_approval=True,
    )

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def execute(self, **kwargs: Any) -> ToolResult:
        self.calls.append(dict(kwargs))
        return ToolResult(
            tool_name=self.spec.name,
            status="success",
            data={"service_name": kwargs["service_name"], "executed": True},
        )


def _enabled_config(config, *, dry_run: bool = False, allow_restart: bool = True):
    actions = dict(config.policy.actions)
    actions["restart_service"] = ActionPolicy(
        allowed=allow_restart,
        requires_approval=True,
    )
    policy = replace(config.policy, actions=actions)
    services = replace(
        config.services,
        allowlist=("demo-web.service",),
        restart_enabled=allow_restart,
    )
    agent = replace(config.agent, mode="assisted", dry_run=dry_run)
    return replace(config, agent=agent, policy=policy, services=services)


def _request(service_name: str = "demo-web.service") -> ActionRequest:
    return ActionRequest(
        action_name="restart_service",
        arguments={"service_name": service_name},
        reason="Investigate a failed test service",
    )


def test_policy_denies_actions_in_observe_mode(app_config) -> None:
    registry = ToolRegistry()
    tool = CountingRestartTool()
    registry.register(tool)
    request = _request()

    decision = PolicyEngine(app_config, registry).evaluate(request)

    assert decision.outcome == "deny"
    assert "observe" in decision.reason
    assert tool.calls == []


def test_policy_denies_service_outside_allowlist(app_config) -> None:
    config = _enabled_config(app_config)
    registry = ToolRegistry()
    tool = CountingRestartTool()
    registry.register(tool)

    decision = PolicyEngine(config, registry).evaluate(_request("unlisted.service"))

    assert decision.outcome == "deny"
    assert "allowlist" in decision.reason


def test_policy_denies_when_action_is_disabled(app_config) -> None:
    config = _enabled_config(app_config, allow_restart=False)
    registry = ToolRegistry()
    registry.register(CountingRestartTool())

    decision = PolicyEngine(config, registry).evaluate(_request())

    assert decision.outcome == "deny"


def test_dry_run_never_invokes_state_changing_tool(app_config, audit_logger) -> None:
    config = _enabled_config(app_config, dry_run=True)
    registry = ToolRegistry()
    tool = CountingRestartTool()
    registry.register(tool)

    result = ControlledExecutor(config, registry, audit_logger).execute(_request())

    assert result.status == "denied"
    assert result.data["dry_run"] is True
    assert result.data["executed"] is False
    assert tool.calls == []
    events = audit_logger.list_events(incident_id=f"action:{result.data['action_id']}")
    assert any(event["event_type"] == "action.dry_run" for event in events)


def test_real_action_requires_matching_approval_and_logs_result(
    app_config, audit_logger
) -> None:
    config = _enabled_config(app_config, dry_run=False)
    registry = ToolRegistry()
    tool = CountingRestartTool()
    registry.register(tool)
    executor = ControlledExecutor(config, registry, audit_logger)
    request = _request()

    missing_approval = executor.execute(request)
    assert missing_approval.status == "denied"
    assert tool.calls == []

    approval = ApprovalManager().create_record(
        request,
        approved=True,
        approver="operator",
        reason="Approved for the isolated test service",
    )
    result = executor.execute(request, approval)

    assert result.ok is True
    assert tool.calls == [{"service_name": "demo-web.service"}]
    events = audit_logger.list_events(incident_id=f"action:{request.action_id}")
    event_types = [event["event_type"] for event in events]
    assert "action.policy_decision" in event_types
    assert "action.approved" in event_types
    assert "action.execution_started" in event_types
    assert "action.execution_finished" in event_types


def test_approval_for_different_fingerprint_is_rejected(
    app_config, audit_logger
) -> None:
    config = _enabled_config(app_config, dry_run=False)
    registry = ToolRegistry()
    tool = CountingRestartTool()
    registry.register(tool)
    request = _request()
    mismatched = ApprovalRecord(
        action_id=request.action_id,
        action_fingerprint="not-the-request-fingerprint",
        approved=True,
        approver="operator",
        reason="Invalid approval for test",
    )

    result = ControlledExecutor(config, registry, audit_logger).execute(request, mismatched)

    assert result.status == "denied"
    assert tool.calls == []


def test_rejected_approval_is_audited_and_never_invokes_action(
    app_config, audit_logger
) -> None:
    config = _enabled_config(app_config, dry_run=False)
    registry = ToolRegistry()
    tool = CountingRestartTool()
    registry.register(tool)

    request = _request()
    approval = ApprovalManager().create_record(
        request,
        approved=False,
        approver="operator",
        reason="Operator declined the proposal",
    )

    result = ControlledExecutor(config, registry, audit_logger).execute(
        request, approval
    )

    assert result.status == "denied"
    assert result.data["approval_rejected"] is True
    assert result.data["executed"] is False
    assert tool.calls == []

    events = audit_logger.list_events(
        incident_id=f"action:{request.action_id}"
    )
    rejected = [
        event for event in events
        if event["event_type"] == "action.rejected"
    ]

    assert len(rejected) == 1
    details = rejected[0]["details"]
    assert details["approver"] == "operator"
    assert details["rejection_reason"] == "Operator declined the proposal"
    assert details["executed"] is False
    assert not any(
        event["event_type"] == "action.execution_started"
        for event in events
    )


def test_rejection_audit_failure_never_invokes_action(
    app_config, audit_logger
) -> None:
    config = _enabled_config(app_config, dry_run=False)
    registry = ToolRegistry()
    tool = CountingRestartTool()
    registry.register(tool)
    request = _request()

    approval = ApprovalManager().create_record(
        request,
        approved=False,
        approver="operator",
        reason="Operator declined the proposal",
    )

    class FailingRejectionAudit:
        def record_event(self, **kwargs):
            if kwargs.get("event_type") == "action.rejected":
                raise AuditError("simulated rejection audit failure")
            return audit_logger.record_event(**kwargs)

    result = ControlledExecutor(
        config, registry, FailingRejectionAudit()
    ).execute(request, approval)

    assert result.status == "failed"
    assert result.data["executed"] is False
    assert result.data["audit_failed_before_execution"] is True
    assert "Could not audit the rejection" in result.error
    assert tool.calls == []

    events = audit_logger.list_events(
        incident_id=f"action:{request.action_id}"
    )
    assert not any(
        event["event_type"] == "action.execution_started"
        for event in events
    )


def test_denied_console_approval_is_not_authorization() -> None:
    request = _request()
    manager = ApprovalManager()
    record = manager.request_console_approval(
        request,
        input_fn=lambda _prompt: "no",
        output_fn=lambda _line: None,
    )

    assert record.approved is False
    assert manager.matches(request, record) is False


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        ("APPROVE", True),
        ("APPROVE ", False),
        (" APPROVE", False),
        ("approve", False),
        ("no", False),
        ("", False),
    ],
)
def test_console_approval_requires_exact_confirmation_word(
    answer: str, expected: bool
) -> None:
    request = _request()
    record = ApprovalManager().request_console_approval(
        request,
        input_fn=lambda _prompt: answer,
        output_fn=lambda _line: None,
    )

    assert record.approved is expected


def test_audit_failure_blocks_action_before_execution(app_config) -> None:
    class BrokenAudit:
        def record_event(self, **kwargs: Any) -> int:
            raise OSError("database unavailable")

    config = _enabled_config(app_config, dry_run=False)
    registry = ToolRegistry()
    tool = CountingRestartTool()
    registry.register(tool)

    result = ControlledExecutor(config, registry, BrokenAudit()).execute(_request())

    assert result.status == "failed"
    assert result.data["executed"] is False
    assert tool.calls == []


def test_console_approval_denies_when_input_is_unavailable() -> None:
    request = _request()
    manager = ApprovalManager()

    def unavailable_input(_prompt: str) -> str:
        raise EOFError

    record = manager.request_console_approval(
        request,
        input_fn=unavailable_input,
        output_fn=lambda _line: None,
    )

    assert record.approved is False
    assert manager.matches(request, record) is False


def test_approved_controlled_restart_uses_fixed_systemctl_arguments(
    app_config, audit_logger, monkeypatch
) -> None:
    from types import SimpleNamespace

    import linux_admin.tools.services as services_module
    from linux_admin.tools.services import RestartServiceTool

    config = _enabled_config(app_config, dry_run=False)
    registry = ToolRegistry()
    registry.register(RestartServiceTool(config))
    monkeypatch.setattr(services_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        services_module.shutil, "which", lambda _name: "/usr/bin/systemctl"
    )
    captured: dict[str, Any] = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(services_module.subprocess, "run", fake_run)
    request = _request()
    approval = ApprovalManager().create_record(
        request,
        approved=True,
        approver="operator",
        reason="Explicitly approved for isolated integration test",
    )

    result = ControlledExecutor(config, registry, audit_logger).execute(request, approval)

    assert result.ok is True
    assert result.data["executed"] is True
    assert result.data["verified"] is False
    assert captured["command"] == [
        "/usr/bin/systemctl",
        "restart",
        "demo-web.service",
    ]
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["timeout"] > 0


@pytest.mark.parametrize(
    ("verification_healthy", "fail_verification_audit"),
    [
        (False, False),
        (True, True),
    ],
)
def test_cli_verification_and_verification_audit_failure(
    app_config,
    monkeypatch,
    capsys,
    verification_healthy: bool,
    fail_verification_audit: bool,
) -> None:
    import json
    import sys
    from types import SimpleNamespace

    import linux_admin.main as cli

    config = replace(
        app_config,
        agent=replace(
            app_config.agent,
            mode="assisted",
            dry_run=False,
        ),
    )

    audit_events: list[str] = []
    verification_calls: list[tuple[str, dict]] = []
    execution_calls: list[str] = []

    class FakeAudit:
        def record_event(self, **kwargs):
            event_type = kwargs["event_type"]
            audit_events.append(event_type)
            if (
                fail_verification_audit
                and event_type == "action.verification_finished"
            ):
                raise AuditError("simulated verification audit failure")
            return 1

        def close(self):
            pass

    class FakeRegistry:
        def invoke(self, tool_name, arguments):
            verification_calls.append((tool_name, arguments))
            return ToolResult(
                tool_name=tool_name,
                status="success" if verification_healthy else "failed",
                error=None if verification_healthy else "Service health check failed",
                data={
                    "healthy": verification_healthy,
                    "active_state": "active" if verification_healthy else "failed",
                    "verification_attempts": [
                        {"attempt": 1, "healthy": verification_healthy}
                    ],
                    "recovery_action_retried": False,
                },
            )

    class FakePolicyEngine:
        def __init__(self, *_args, **_kwargs):
            pass

        def evaluate(self, _request):
            return SimpleNamespace(outcome="approval_required")

    class FakeApprovalManager:
        def request_console_approval(self, _request):
            return SimpleNamespace(approved=True)

    class FakeExecutor:
        def __init__(self, *_args, **_kwargs):
            pass

        def execute(self, request, _approval=None):
            execution_calls.append(request.action_name)
            return ToolResult(
                tool_name=request.action_name,
                status="failed",
                error="Restart timed out; service state must be checked",
                data={
                    "service_name": request.arguments["service_name"],
                    "executed": True,
                },
            )

    class FakeRecoveryManager:
        def __init__(self, **_kwargs):
            pass

        def verify_until_healthy(self, check):
            return check()

        @staticmethod
        def handle_recovery_failure(**_kwargs):
            return {
                "status": "recovery_failed",
                "automatic_follow_up_action": False,
            }

    audit = FakeAudit()
    registry = FakeRegistry()

    monkeypatch.setattr(cli, "load_config", lambda: config)
    monkeypatch.setattr(cli, "register_builtin_tools", lambda *_args: registry)
    monkeypatch.setattr(cli, "AuditLogger", lambda *_args: audit)
    monkeypatch.setattr(cli, "PolicyEngine", FakePolicyEngine)
    monkeypatch.setattr(cli, "ApprovalManager", FakeApprovalManager)
    monkeypatch.setattr(cli, "ControlledExecutor", FakeExecutor)
    monkeypatch.setattr(cli, "RecoveryManager", FakeRecoveryManager)
    monkeypatch.setattr(
        sys,
        "argv",
        ["linux-admin", "--restart-service", "demo-web.service"],
    )

    exit_code = cli.main()
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert execution_calls == ["restart_service"]
    assert verification_calls == [
        (
            "verify_service_health",
            {"service_name": "demo-web.service"},
        )
    ]
    assert output["verification"]["data"]["healthy"] is verification_healthy
    assert "action.verification_finished" in audit_events

    if verification_healthy:
        assert output["verification_audit_error"] is True
        assert "recovery_disposition" not in output
    else:
        assert output["recovery_disposition"]["status"] == "recovery_failed"
        assert (
            output["recovery_disposition"]["automatic_follow_up_action"] is False
        )

def test_cli_investigate_reports_diagnosis_only_problem_resolution(
    app_config, monkeypatch, capsys
) -> None:
    import json
    import sys

    import linux_admin.main as cli
    from linux_admin.contracts import IncidentContext

    request = "Check endpoint https://example.com/"
    config = replace(
        app_config,
        audit=replace(app_config.audit, enabled=False),
    )

    class FakeAgent:
        def __init__(self, **_kwargs):
            pass

        def run(self, user_request):
            incident = IncidentContext(user_request=user_request)
            incident.status = "completed"
            incident.steps = 2
            incident.findings.append(
                "Diagnosis: Endpoint reachable "
                "(classification=endpoint_reachable, confidence=high)."
            )
            incident.evidence.extend(
                [
                    ToolResult(
                        tool_name="check_tcp_connectivity",
                        status="success",
                        data={
                            "host": "example.com",
                            "port": 443,
                            "reachable": True,
                        },
                    ),
                    ToolResult(
                        tool_name="check_http_endpoint",
                        status="success",
                        data={
                            "url": "https://example.com/",
                            "host": "example.com",
                            "port": 443,
                            "reachable": True,
                            "healthy": True,
                            "status_code": 200,
                        },
                    ),
                ]
            )
            return incident

    monkeypatch.setattr(cli, "load_config", lambda: config)
    monkeypatch.setattr(cli, "register_builtin_tools", lambda *_args: ToolRegistry())
    monkeypatch.setattr(cli, "Agent", FakeAgent)
    monkeypatch.setattr(
        sys, "argv", ["linux-admin", "--investigate", request]
    )

    exit_code = cli.main()
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["status"] == "completed"
    assert output["remediation"]["status"] == "not_proposed"
    assert output["remediation"]["problem_resolution"]["status"] == "diagnosis_only"
    assert output["remediation"]["problem_resolution"]["resolved"] is False


@pytest.mark.parametrize(
    (
        "endpoint_healthy",
        "endpoint_status",
        "expected_remediation_status",
        "expected_resolution",
        "expected_exit_code",
    ),
    [
        (False, 503, "recovery_failed", "partially_resolved", 1),
        (True, 200, "verified_recovered", "resolved", 0),
    ],
)
def test_cli_reports_resolution_from_service_and_endpoint_checks(
    app_config,
    monkeypatch,
    capsys,
    endpoint_healthy: bool,
    endpoint_status: int,
    expected_remediation_status: str,
    expected_resolution: str,
    expected_exit_code: int,
) -> None:
    import json
    import sys

    import linux_admin.main as cli
    import linux_admin.remediation_workflow as remediation_module
    from linux_admin.contracts import IncidentContext

    service = "demo-web.service"
    url = "http://127.0.0.1:18080/health"
    request = (
        f"Investigate {service} and endpoint {url}; "
        "fix if the service is failed"
    )

    config = _enabled_config(app_config, dry_run=False, allow_restart=True)

    class FakeAudit:
        def record_event(self, **_kwargs):
            return 1

        def close(self):
            pass

    audit = FakeAudit()

    class FakeAgent:
        def __init__(self, **_kwargs):
            pass

        def run(self, user_request):
            incident = IncidentContext(user_request=user_request)
            incident.status = "completed"
            incident.steps = 2
            incident.findings.extend(
                [
                    "Diagnosis: Service failed and endpoint unhealthy.",
                    (
                        "Diagnosis: HTTP server error "
                        "(classification=http_server_error, confidence=high)."
                    ),
                ]
            )
            incident.evidence.extend(
                [
                    ToolResult(
                        tool_name="get_service_status",
                        status="success",
                        data={
                            "service_name": service,
                            "load_state": "loaded",
                            "active_state": "failed",
                            "sub_state": "failed",
                            "result": "exit-code",
                        },
                    ),
                ]
            )
            return incident

    class FakeRestartTool:
        spec = ToolSpec(
            name="restart_service",
            description="Test-only state-changing restart",
            parameters={
                "type": "object",
                "properties": {"service_name": {"type": "string"}},
                "required": ["service_name"],
                "additionalProperties": False,
            },
            risk_level="high",
            changes_system=True,
            requires_approval=True,
        )

        def __init__(self):
            self.call_count = 0

        def execute(self, service_name):
            self.call_count += 1
            return ToolResult(
                tool_name=self.spec.name,
                status="success",
                data={"service_name": service_name, "executed": True},
            )

    class FakeServiceVerifier:
        spec = ToolSpec(
            name="verify_service_health",
            description="Test-only service health verification",
            parameters={
                "type": "object",
                "properties": {"service_name": {"type": "string"}},
                "required": ["service_name"],
                "additionalProperties": False,
            },
        )

        def execute(self, service_name):
            return ToolResult(
                tool_name=self.spec.name,
                status="success",
                data={
                    "service_name": service_name,
                    "healthy": True,
                    "active_state": "active",
                },
            )

    class FakeEndpointVerifier:
        spec = ToolSpec(
            name="verify_endpoint",
            description="Test-only endpoint health verification",
            parameters={
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
                "additionalProperties": False,
            },
        )

        def __init__(self, healthy: bool, status_code: int):
            self.healthy = healthy
            self.status_code = status_code
            self.urls = []

        def execute(self, url):
            self.urls.append(url)
            return ToolResult(
                tool_name=self.spec.name,
                status="success",
                data={
                    "url": url,
                    "healthy": self.healthy,
                    "reachable": True,
                    "status_code": self.status_code,
                },
            )

    registry = ToolRegistry()
    restart_tool = FakeRestartTool()
    endpoint_verifier = FakeEndpointVerifier(
        healthy=endpoint_healthy,
        status_code=endpoint_status,
    )
    registry.register(restart_tool)
    registry.register(FakeServiceVerifier())
    registry.register(endpoint_verifier)

    # Create a real approval record, but simulate operator acceptance.
    class FakeApprovalManager:
        def request_console_approval(self, action_request, **_kwargs):
            return ApprovalManager().create_record(
                action_request,
                approved=True,
                approver="integration-test",
                reason="Approved by automated integration test",
            )

    monkeypatch.setattr(cli, "load_config", lambda: config)
    monkeypatch.setattr(cli, "register_builtin_tools", lambda *_args: registry)
    monkeypatch.setattr(cli, "AuditLogger", lambda *_args: audit)
    monkeypatch.setattr(cli, "Agent", FakeAgent)
    monkeypatch.setattr(
        remediation_module, "ApprovalManager", FakeApprovalManager
    )
    monkeypatch.setattr(
        sys, "argv", ["linux-admin", "--investigate", request]
    )

    exit_code = cli.main()
    output = json.loads(capsys.readouterr().out)
    remediation = output["remediation"]
    resolution = remediation["problem_resolution"]

    assert exit_code == expected_exit_code
    assert restart_tool.call_count == 1
    assert remediation["status"] == expected_remediation_status
    assert remediation["verification"]["data"]["healthy"] is True
    assert (
        remediation["endpoint_verification"]["data"]["healthy"]
        is endpoint_healthy
    )
    assert (
        remediation["endpoint_verification"]["data"]["status_code"]
        == endpoint_status
    )
    expected_url_calls = [url] if endpoint_healthy else [url, url]
    assert endpoint_verifier.urls == expected_url_calls
    assert resolution["status"] == expected_resolution
    assert resolution["resolved"] is endpoint_healthy
    assert {
        item["target"]: item["healthy"]
        for item in resolution["checks"]
    } == {
        "service_state": True,
        "original_endpoint": endpoint_healthy,
    }

@pytest.mark.parametrize(
    (
        "scenario",
        "allow_restart",
        "expected_remediation",
        "expected_resolution",
        "failure_event",
        "expected_exit_code",
        "expected_audit_event",
    ),
    [
        ("dry_run", True, "dry_run_no_change", "not_attempted",
         None, 0, "action.dry_run"),
        ("rejected", True, "rejected", "rejected",
         None, 0, "action.rejected"),
        ("policy_blocked", False, "blocked_by_policy", "blocked_by_policy",
         None, 0, "action.denied"),
        ("audit_fail_dry_run", True, "audit_failure_before_execution",
         "not_attempted", "action.dry_run", 1, "action.dry_run"),
        ("audit_fail_rejected", True, "audit_failure_before_execution",
         "not_attempted", "action.rejected", 1, "action.rejected"),
        ("audit_fail_policy_denial", False, "audit_failure_before_execution",
         "not_attempted", "action.denied", 1, "action.denied"),
    ],
)
def test_cli_investigate_dry_run_and_rejection_never_execute(
    app_config,
    monkeypatch,
    capsys,
    scenario: str,
    allow_restart: bool,
    expected_remediation: str,
    expected_resolution: str,
    failure_event: str | None,
    expected_exit_code: int,
    expected_audit_event: str,
) -> None:
    import json
    import sys

    import linux_admin.main as cli
    import linux_admin.remediation_workflow as remediation_module
    from linux_admin.audit import AuditError
    from linux_admin.contracts import IncidentContext

    service = "demo-web.service"
    request = f"Investigate {service} and fix if failed"
    config = _enabled_config(
        app_config,
        dry_run=scenario in {"dry_run", "audit_fail_dry_run"},
        allow_restart=allow_restart,
    )
    config = replace(
        config,
        audit=replace(config.audit, enabled=True),
    )

    class FakeAudit:
        def __init__(self):
            self.events = []
            self.attempts = []

        def record_event(self, **kwargs):
            event = dict(kwargs)
            self.attempts.append(event)
            if kwargs.get("event_type") == failure_event:
                raise AuditError("simulated audit write failure")
            self.events.append(event)
            return 1

        def close(self):
            pass

    audit = FakeAudit()

    class FakeAgent:
        def __init__(self, **_kwargs):
            pass

        def run(self, user_request):
            incident = IncidentContext(user_request=user_request)
            incident.status = "completed"
            incident.steps = 1
            incident.findings.append(
                "Diagnosis: the requested service is failed."
            )
            incident.evidence.append(
                ToolResult(
                    tool_name="get_service_status",
                    status="success",
                    data={
                        "service_name": service,
                        "load_state": "loaded",
                        "active_state": "failed",
                        "sub_state": "failed",
                        "result": "exit-code",
                    },
                )
            )
            return incident

    class FakeRestartTool:
        spec = ToolSpec(
            name="restart_service",
            description="Test-only restart; must not execute in this test",
            parameters={
                "type": "object",
                "properties": {"service_name": {"type": "string"}},
                "required": ["service_name"],
                "additionalProperties": False,
            },
            risk_level="high",
            changes_system=True,
            requires_approval=True,
        )

        def __init__(self):
            self.call_count = 0

        def execute(self, service_name):
            self.call_count += 1
            return ToolResult(
                tool_name=self.spec.name,
                status="success",
                data={"service_name": service_name, "executed": True},
            )

    registry = ToolRegistry()
    restart_tool = FakeRestartTool()
    registry.register(restart_tool)

    class FakeApprovalManager:
        def request_console_approval(self, action_request, **_kwargs):
            return ApprovalManager().create_record(
                action_request,
                approved=False,
                approver="integration-test",
                reason="Operator declined the proposal",
            )

    monkeypatch.setattr(cli, "load_config", lambda: config)
    monkeypatch.setattr(cli, "register_builtin_tools", lambda *_args: registry)
    monkeypatch.setattr(cli, "AuditLogger", lambda *_args: audit)
    monkeypatch.setattr(cli, "Agent", FakeAgent)
    monkeypatch.setattr(
        remediation_module, "ApprovalManager", FakeApprovalManager
    )
    monkeypatch.setattr(
        sys, "argv", ["linux-admin", "--investigate", request]
    )

    exit_code = cli.main()
    output = json.loads(capsys.readouterr().out)
    remediation = output["remediation"]

    assert exit_code == expected_exit_code
    assert remediation["status"] == expected_remediation
    assert (
        remediation["problem_resolution"]["status"]
        == expected_resolution
    )
    assert remediation["problem_resolution"]["resolved"] is False
    assert remediation["changes_made"] is False
    assert restart_tool.call_count == 0

    action_attempts = [
        event for event in audit.attempts
        if str(event.get("event_type", "")).startswith("action.")
    ]
    assert action_attempts
    assert all(
        event["incident_id"] == output["incident_id"]
        for event in action_attempts
    )

    persisted_types = [
        event["event_type"] for event in audit.events
        if str(event.get("event_type", "")).startswith("action.")
    ]
    attempted_types = [
        event["event_type"] for event in action_attempts
    ]

    if failure_event is None:
        assert expected_audit_event in persisted_types
    else:
        assert failure_event in attempted_types
        assert failure_event not in persisted_types
        assert (
            remediation["action"]["data"]["audit_failed_before_execution"]
            is True
        )

    assert "action.execution_started" not in attempted_types


def test_verification_target_requires_one_unambiguous_explicit_url() -> None:
    import linux_admin.main as cli

    url = "http://127.0.0.1:18080/health"

    assert cli._select_verification_target(
        f"Check endpoint {url}; fix it if needed"
    ) == (url, True)

    assert cli._select_verification_target(
        f"Check {url} and https://example.com/"
    ) == (None, True)

    assert cli._select_verification_target(
        f"Check {url} and then check {url}"
    ) == (None, True)

    assert cli._select_verification_target(
        "Investigate the service status"
    ) == (None, False)

@pytest.mark.parametrize(
    ("investigation_status", "expected_exit_code"),
    [
        ("failed", 1),
        ("inconclusive", 0),
    ],
)
def test_cli_propagates_incomplete_investigation_status(
    app_config,
    monkeypatch,
    capsys,
    investigation_status: str,
    expected_exit_code: int,
) -> None:
    import json
    import sys

    import linux_admin.main as cli
    from linux_admin.contracts import IncidentContext

    request = "Investigate general system condition"
    config = replace(
        app_config,
        audit=replace(app_config.audit, enabled=False),
    )

    class FakeAgent:
        def __init__(self, **_kwargs):
            pass

        def run(self, user_request):
            incident = IncidentContext(
                user_request=user_request,
                status=investigation_status,
            )
            incident.findings.append(
                f"Simulated investigation status={investigation_status}."
            )
            return incident

    monkeypatch.setattr(cli, "load_config", lambda: config)
    monkeypatch.setattr(
        cli, "register_builtin_tools", lambda *_args: ToolRegistry()
    )
    monkeypatch.setattr(cli, "Agent", FakeAgent)
    monkeypatch.setattr(
        sys, "argv", ["linux-admin", "--investigate", request]
    )

    exit_code = cli.main()
    output = json.loads(capsys.readouterr().out)

    assert exit_code == expected_exit_code
    assert output["status"] == investigation_status
    assert output["remediation"]["status"] == "not_proposed"
    assert (
        output["remediation"]["problem_resolution"]["status"]
        == "not_attempted"
    )
    assert output["remediation"]["problem_resolution"]["resolved"] is False
    assert output["remediation"]["changes_made"] is False


@pytest.mark.parametrize(
    ("incident_status", "remediation_status", "expected_exit_code"),
    [
        ("completed", "not_proposed", 0),
        ("completed", "dry_run_no_change", 0),
        ("completed", "rejected", 0),
        ("completed", "blocked_by_policy", 0),
        ("completed", "verified_recovered", 0),
        ("completed", "execution_failed", 1),
        ("completed", "recovery_failed", 1),
        ("completed", "audit_failure_after_execution", 1),
        ("failed", "not_proposed", 1),
        ("inconclusive", "not_proposed", 0),
        ("completed", "audit_failure_before_execution", 1),
    ],
)
def test_investigation_exit_code_separates_operation_from_resolution(
    incident_status: str,
    remediation_status: str,
    expected_exit_code: int,
) -> None:
    import linux_admin.main as cli

    assert (
        cli._investigation_exit_code(incident_status, remediation_status)
        == expected_exit_code
    )

def test_unknown_follow_up_answers_are_recognized():
    from linux_admin.main import _is_unknown_follow_up_answer

    for answer in (
        "không xác định",
        " Chưa biết. ",
        "không rõ",
        "unknown",
        "I don't know",
    ):
        assert _is_unknown_follow_up_answer(answer)


def test_specific_follow_up_answers_are_not_treated_as_unknown():
    from linux_admin.main import _is_unknown_follow_up_answer

    for answer in (
        "nginx.service",
        "Ứng dụng của tôi chạy bằng systemd unit api.service",
        "The endpoint is served by nginx",
    ):
        assert not _is_unknown_follow_up_answer(answer)

def test_test_only_follow_up_answer_is_not_operational_context():
    from linux_admin.main import _is_test_only_follow_up_answer

    answer = (
        "Tên unit giả lập là test-only-clarification.service; "
        "chỉ dùng để kiểm thử, không yêu cầu khởi động dịch vụ."
    )
    assert _is_test_only_follow_up_answer(answer)


def test_real_service_context_is_not_misclassified_as_test_only():
    from linux_admin.main import _is_test_only_follow_up_answer

    assert not _is_test_only_follow_up_answer(
        "Endpoint được cung cấp bởi nginx.service; không được restart."
    )


# ============================================================================
# KHÁNH — Policy tests cho 6 tool read-only mới (theo bảng phân công)
# ============================================================================

NEW_READONLY_ACTIONS = [
    "list_all_mounts",
    "get_io_stats",
    "list_listening_ports",
    "get_kernel_log",
    "check_auth_log",
    "list_top_processes",
]


@pytest.mark.parametrize("action", NEW_READONLY_ACTIONS)
def test_new_readonly_action_has_explicit_policy_rule(app_config, action: str) -> None:
    """6 tool read-only mới phải có rule tường minh trong policy (không rơi vào default deny)."""
    assert action in app_config.policy.actions, (
        f"Action '{action}' chưa có trong policy.yaml — sẽ bị default_decision=deny chặn."
    )


@pytest.mark.parametrize("action", NEW_READONLY_ACTIONS)
def test_new_readonly_action_is_allowed_without_approval(app_config, action: str) -> None:
    """6 tool read-only mới phải allowed=True và requires_approval=False."""
    rule = app_config.policy.actions.get(action)
    assert rule is not None, f"Action '{action}' chưa có rule trong policy.yaml."
    assert rule.allowed is True, (
        f"Action '{action}' phải allowed=True (read-only, an toàn)."
    )
    assert rule.requires_approval is False, (
        f"Action '{action}' phải requires_approval=False (read-only, không cần approval)."
    )


def test_default_decision_still_denies_unknown_actions(app_config) -> None:
    """Default decision vẫn phải là deny (fail-closed) cho action không có rule."""
    assert app_config.policy.default_decision == "deny"
    assert "definitely_not_a_real_action" not in app_config.policy.actions


def test_policy_yaml_declares_resource_threshold_80() -> None:
    """Câu 1.1: policy.yaml phải khai báo ngưỡng 80% (đọc thô từ file, không qua AppConfig).

    Lý do không dùng app_config: PolicySettings hiện chưa có field
    resource_threshold_percent (trách nhiệm của diagnostics.py/agent.py — Phong).
    Test này chỉ xác nhận YAML có khai báo đúng, để Phong đọc sau.
    """
    from pathlib import Path

    import yaml

    policy_path = Path(__file__).resolve().parents[1] / "config" / "policy.yaml"
    assert policy_path.exists(), f"Không tìm thấy {policy_path}"

    with policy_path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    assert data["policy"]["resource_threshold_percent"] == 80, (
        "policy.yaml phải khai báo resource_threshold_percent: 80 (câu 1.1)."
    )
