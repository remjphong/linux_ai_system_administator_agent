"""Tests for evidence-gated human-approved remediation workflow."""
from __future__ import annotations

from dataclasses import replace

import pytest

from linux_admin.config import ActionPolicy
from linux_admin.contracts import IncidentContext, ToolResult, ToolSpec
from linux_admin.registry import ToolRegistry
from linux_admin.remediation_workflow import (
    build_remediation_proposal,
    no_proposal_result,
    run_remediation_workflow,
)


class FakeRestartTool:
    spec = ToolSpec(
        name="restart_service",
        description="Test-only fake restart",
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
        self.called = False
        self.call_count = 0

    def execute(self, service_name: str):
        from linux_admin.contracts import ToolResult
        self.called = True
        self.call_count += 1
        return ToolResult(
            tool_name="restart_service",
            status="success",
            data={"executed": True, "service_name": service_name},
        )


class FakeVerifyTool:
    spec = ToolSpec(
        name="verify_service_health",
        description="Test-only fake health verification",
        parameters={
            "type": "object",
            "properties": {"service_name": {"type": "string"}},
            "required": ["service_name"],
            "additionalProperties": False,
        },
    )

    def __init__(self, healthy: bool = True) -> None:
        self.healthy = healthy
        self.calls = 0

    def execute(self, service_name: str):
        self.calls += 1
        return ToolResult(
            tool_name=self.spec.name,
            status="success",
            data={
                "service_name": service_name,
                "healthy": self.healthy,
                "active_state": "active" if self.healthy else "failed",
            },
        )


class FakeVerifyEndpointTool:
    spec = ToolSpec(
        name="verify_endpoint",
        description="Test-only endpoint verification",
        parameters={
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
            "additionalProperties": False,
        },
    )

    def __init__(self, healthy: bool) -> None:
        self.healthy = healthy
        self.calls = 0

    def execute(self, url: str) -> ToolResult:
        self.calls += 1
        return ToolResult(
            tool_name=self.spec.name,
            status="success",
            data={
                "url": url,
                "healthy": self.healthy,
                "reachable": True,
                "status_code": 200 if self.healthy else 503,
            },
        )


def _failed_incident(service_name: str) -> IncidentContext:
    incident = IncidentContext(user_request=f"Investigate why {service_name} failed and fix it")
    incident.status = "completed"
    incident.evidence.append(
        ToolResult(
            tool_name="get_service_status",
            status="success",
            data={
                "service_name": service_name,
                "load_state": "loaded",
                "active_state": "failed",
                "sub_state": "failed",
                "result": "exit-code",
            },
        )
    )
    return incident


def _action_registry(verification_healthy: bool = True):
    registry = ToolRegistry()
    restart = FakeRestartTool()
    registry.register(restart)
    registry.register(FakeVerifyTool(healthy=verification_healthy))
    return registry, restart


def test_proposal_requires_explicit_failed_service(app_config):
    registry, _ = _action_registry()
    service = app_config.services.allowlist[0]
    proposal = build_remediation_proposal(_failed_incident(service), app_config, registry)
    assert proposal is not None
    assert proposal.request.action_name == "restart_service"
    assert proposal.request.arguments["service_name"] == service
    assert proposal.to_dict()["action_fingerprint"] == proposal.request.fingerprint


def test_generic_slow_machine_request_never_guesses_a_service(app_config):
    registry, _ = _action_registry()
    incident = _failed_incident(app_config.services.allowlist[0])
    incident.user_request = "Tại sao máy đang chạy chậm?"
    proposal = build_remediation_proposal(incident, app_config, registry)
    assert proposal is None
    no_op = no_proposal_result(incident.user_request)
    assert no_op["status"] == "not_proposed"
    assert no_op["changes_made"] is False
    assert "Không có hành động" in no_op["message"]
    assert no_op["problem_resolution"]["status"] == "diagnosis_only"
    assert no_op["problem_resolution"]["resolved"] is False
    assert no_op["follow_up_question"] is not None
    assert "ứng dụng" in no_op["follow_up_question"].casefold()


def test_missing_or_inactive_service_does_not_propose_restart(app_config):
    registry, _ = _action_registry()
    service = app_config.services.allowlist[0]
    incident = _failed_incident(service)
    incident.evidence[0].data["active_state"] = "inactive"
    assert build_remediation_proposal(incident, app_config, registry) is None
    incident.evidence[0].data.update(load_state="not-found", active_state="failed")
    assert build_remediation_proposal(incident, app_config, registry) is None


def test_policy_denial_never_prompts_or_executes(
    app_config, audit_logger
):
    registry, restart = _action_registry()
    service = app_config.services.allowlist[0]
    proposal = build_remediation_proposal(_failed_incident(service), app_config, registry)
    assert proposal is not None

    def unexpected_input(_prompt: str) -> str:
        raise AssertionError("must not prompt when policy denies the action")

    result = run_remediation_workflow(
        proposal,
        incident_id="test-policy-denial",
        config=app_config,
        registry=registry,
        audit=audit_logger,
        input_fn=unexpected_input,
        output_fn=lambda _line: None,
    )
    assert result["status"] == "blocked_by_policy"
    assert result["changes_made"] is False
    assert result["problem_resolution"]["status"] == "blocked_by_policy"
    assert restart.called is False

    events = audit_logger.list_events(
        incident_id="test-policy-denial"
    )
    event_types = [event["event_type"] for event in events]
    assert "action.denied" in event_types
    assert "action.execution_started" not in event_types


def test_dry_run_never_executes_and_reports_not_attempted(
    app_config, audit_logger
):
    registry, restart = _action_registry()
    service = app_config.services.allowlist[0]
    proposal = build_remediation_proposal(
        _failed_incident(service), app_config, registry
    )
    assert proposal is not None

    service_settings = replace(
        app_config.services,
        restart_enabled=True,
        allowlist=(service,),
    )
    agent_settings = replace(
        app_config.agent,
        mode="assisted",
        dry_run=True,
    )
    policy_settings = replace(
        app_config.policy,
        actions={
            **app_config.policy.actions,
            "restart_service": ActionPolicy(True, True),
        },
    )
    dry_run_config = replace(
        app_config,
        agent=agent_settings,
        services=service_settings,
        policy=policy_settings,
    )

    def unexpected_input(_prompt: str) -> str:
        raise AssertionError("dry-run must not request execution approval")

    result = run_remediation_workflow(
        proposal,
        incident_id="test-dry-run",
        config=dry_run_config,
        registry=registry,
        audit=audit_logger,
        input_fn=unexpected_input,
        output_fn=lambda _line: None,
    )

    assert result["status"] == "dry_run_no_change"
    assert result["changes_made"] is False
    assert restart.called is False
    assert result["problem_resolution"]["status"] == "not_attempted"
    assert result["problem_resolution"]["resolved"] is False

    events = audit_logger.list_events(
        incident_id="test-dry-run"
    )
    event_types = [event["event_type"] for event in events]
    assert "action.dry_run" in event_types
    assert "action.execution_started" not in event_types


def test_approved_action_is_executed_and_verified(app_config, audit_logger):
    registry, restart = _action_registry()
    service = app_config.services.allowlist[0]
    proposal = build_remediation_proposal(_failed_incident(service), app_config, registry)
    assert proposal is not None

    service_settings = replace(app_config.services, restart_enabled=True, allowlist=(service,))
    agent_settings = replace(app_config.agent, mode="assisted", dry_run=False)
    rule = ActionPolicy(allowed=True, requires_approval=True)
    rules = dict(app_config.policy.actions)
    rules["restart_service"] = rule
    policy_settings = replace(app_config.policy, actions=rules)
    enabled_config = replace(
        app_config, agent=agent_settings, services=service_settings, policy=policy_settings
    )

    result = run_remediation_workflow(
        proposal,
        incident_id="test-approved-action",
        config=enabled_config,
        registry=registry,
        audit=audit_logger,
        input_fn=lambda _prompt: "APPROVE",
        output_fn=lambda _line: None,
    )
    assert restart.called is True
    assert result["status"] == "verified_recovered"
    assert result["changes_made"] is True
    assert result["verification"]["data"]["healthy"] is True
    assert result["problem_resolution"]["status"] == "resolved"
    assert result["problem_resolution"]["resolved"] is True

    events = audit_logger.list_events(incident_id="test-approved-action")
    assert events
    assert all(
        event["action_id"] == proposal.request.action_id
        for event in events
    )
    event_types = [event["event_type"] for event in events]
    assert "action.execution_started" in event_types
    assert "action.execution_finished" in event_types
    assert "action.verification_finished" in event_types


def test_service_active_but_original_endpoint_unhealthy_is_not_resolved(
    app_config, audit_logger
):
    registry, restart = _action_registry()
    endpoint = FakeVerifyEndpointTool(healthy=False)
    registry.register(endpoint)

    service = app_config.services.allowlist[0]
    proposal = build_remediation_proposal(
        _failed_incident(service), app_config, registry
    )
    assert proposal is not None

    service_settings = replace(
        app_config.services, restart_enabled=True, allowlist=(service,)
    )
    agent_settings = replace(app_config.agent, mode="assisted", dry_run=False)
    policy_settings = replace(
        app_config.policy,
        actions={
            **app_config.policy.actions,
            "restart_service": ActionPolicy(True, True),
        },
    )
    enabled_config = replace(
        app_config,
        agent=agent_settings,
        services=service_settings,
        policy=policy_settings,
    )
    url = "http://127.0.0.1:18080/health"

    result = run_remediation_workflow(
        proposal,
        incident_id="test-endpoint-still-unhealthy",
        config=enabled_config,
        registry=registry,
        audit=audit_logger,
        verification_url=url,
        input_fn=lambda _prompt: "APPROVE",
        output_fn=lambda _line: None,
    )

    assert restart.called is True
    assert result["verification"]["data"]["healthy"] is True
    assert result["endpoint_verification"]["data"]["healthy"] is False
    assert result["endpoint_verification"]["data"]["status_code"] == 503
    assert result["status"] == "recovery_failed"
    assert result["problem_resolution"]["status"] == "partially_resolved"
    assert result["problem_resolution"]["resolved"] is False
    assert endpoint.calls == 2


def test_action_runs_but_failed_health_check_reports_unresolved(
    app_config, audit_logger
):
    registry, restart = _action_registry(verification_healthy=False)
    service = app_config.services.allowlist[0]
    proposal = build_remediation_proposal(
        _failed_incident(service), app_config, registry
    )
    assert proposal is not None

    service_settings = replace(
        app_config.services,
        restart_enabled=True,
        allowlist=(service,),
    )
    agent_settings = replace(
        app_config.agent,
        mode="assisted",
        dry_run=False,
    )
    policy_settings = replace(
        app_config.policy,
        actions={
            **app_config.policy.actions,
            "restart_service": ActionPolicy(True, True),
        },
    )
    enabled_config = replace(
        app_config,
        agent=agent_settings,
        services=service_settings,
        policy=policy_settings,
    )

    result = run_remediation_workflow(
        proposal,
        incident_id="test-action-verification-failed",
        config=enabled_config,
        registry=registry,
        audit=audit_logger,
        input_fn=lambda _prompt: "APPROVE",
        output_fn=lambda _line: None,
    )

    assert restart.called is True
    assert restart.call_count == 1
    assert result["changes_made"] is True
    assert result["status"] == "recovery_failed"
    assert result["verification"]["data"]["healthy"] is False
    assert result["problem_resolution"]["status"] == "unresolved"
    assert result["problem_resolution"]["resolved"] is False
    assert result["verification"]["data"]["recovery_action_retried"] is False


def test_verification_audit_failure_never_claims_problem_resolved(
    app_config,
):
    from linux_admin.audit import AuditError

    registry, restart = _action_registry()
    service = app_config.services.allowlist[0]
    proposal = build_remediation_proposal(
        _failed_incident(service), app_config, registry
    )
    assert proposal is not None

    service_settings = replace(
        app_config.services,
        restart_enabled=True,
        allowlist=(service,),
    )
    agent_settings = replace(
        app_config.agent,
        mode="assisted",
        dry_run=False,
    )
    policy_settings = replace(
        app_config.policy,
        actions={
            **app_config.policy.actions,
            "restart_service": ActionPolicy(True, True),
        },
    )
    enabled_config = replace(
        app_config,
        agent=agent_settings,
        services=service_settings,
        policy=policy_settings,
    )

    class FailVerificationAudit:
        def record_event(self, **kwargs):
            if kwargs.get("event_type") == "action.verification_finished":
                raise AuditError("simulated verification audit failure")
            return 1

    result = run_remediation_workflow(
        proposal,
        incident_id="test-verification-audit-failure",
        config=enabled_config,
        registry=registry,
        audit=FailVerificationAudit(),
        input_fn=lambda _prompt: "APPROVE",
        output_fn=lambda _line: None,
    )

    assert restart.call_count == 1
    assert result["changes_made"] is True
    assert result["verification"]["data"]["healthy"] is True
    assert result["verification_audit_error"] is True
    assert result["status"] == "audit_failure_after_execution"
    assert result["problem_resolution"]["status"] == "verification_failed"
    assert result["problem_resolution"]["resolved"] is False


def test_required_endpoint_without_unambiguous_url_is_not_claimed_resolved(
    app_config, audit_logger
):
    registry, restart = _action_registry()
    service = app_config.services.allowlist[0]
    proposal = build_remediation_proposal(
        _failed_incident(service), app_config, registry
    )
    assert proposal is not None

    service_settings = replace(
        app_config.services,
        restart_enabled=True,
        allowlist=(service,),
    )
    agent_settings = replace(
        app_config.agent,
        mode="assisted",
        dry_run=False,
    )
    policy_settings = replace(
        app_config.policy,
        actions={
            **app_config.policy.actions,
            "restart_service": ActionPolicy(True, True),
        },
    )
    enabled_config = replace(
        app_config,
        agent=agent_settings,
        services=service_settings,
        policy=policy_settings,
    )

    result = run_remediation_workflow(
        proposal,
        incident_id="test-required-endpoint-verification-missing",
        config=enabled_config,
        registry=registry,
        audit=audit_logger,
        verification_url=None,
        endpoint_verification_required=True,
        input_fn=lambda _prompt: "APPROVE",
        output_fn=lambda _line: None,
    )

    assert restart.call_count == 1
    assert result["verification"]["data"]["healthy"] is True
    assert result["endpoint_verification"] is None
    assert result["status"] == "recovery_failed"
    assert result["problem_resolution"]["status"] == "verification_failed"
    assert result["problem_resolution"]["resolved"] is False


def test_rejected_action_is_never_executed(app_config, audit_logger):
    registry, restart = _action_registry()
    service = app_config.services.allowlist[0]
    proposal = build_remediation_proposal(_failed_incident(service), app_config, registry)
    assert proposal is not None

    service_settings = replace(app_config.services, restart_enabled=True, allowlist=(service,))
    agent_settings = replace(app_config.agent, mode="assisted", dry_run=False)
    policy_settings = replace(
        app_config.policy,
        actions={**app_config.policy.actions, "restart_service": ActionPolicy(True, True)},
    )
    enabled_config = replace(
        app_config, agent=agent_settings, services=service_settings, policy=policy_settings
    )

    result = run_remediation_workflow(
        proposal,
        incident_id="test-rejected-action",
        config=enabled_config,
        registry=registry,
        audit=audit_logger,
        input_fn=lambda _prompt: "NO",
        output_fn=lambda _line: None,
    )
    assert result["status"] == "rejected"
    assert result["changes_made"] is False
    assert result["problem_resolution"]["status"] == "rejected"
    assert restart.called is False

    events = audit_logger.list_events(
        incident_id="test-rejected-action"
    )
    event_types = [event["event_type"] for event in events]
    assert "action.rejected" in event_types
    assert "action.execution_started" not in event_types


@pytest.mark.parametrize(
    ("scenario", "failed_event"),
    [
        ("policy_blocked", "action.denied"),
        ("dry_run", "action.dry_run"),
        ("rejected", "action.rejected"),
    ],
)
def test_pre_execution_audit_failure_is_not_hidden(
    app_config, audit_logger, scenario, failed_event
):
    from linux_admin.audit import AuditError

    registry, restart = _action_registry()
    service = app_config.services.allowlist[0]
    proposal = build_remediation_proposal(
        _failed_incident(service), app_config, registry
    )
    assert proposal is not None

    if scenario == "policy_blocked":
        config = app_config
    else:
        service_settings = replace(
            app_config.services,
            restart_enabled=True,
            allowlist=(service,),
        )
        agent_settings = replace(
            app_config.agent,
            mode="assisted",
            dry_run=(scenario == "dry_run"),
        )
        actions = dict(app_config.policy.actions)
        actions["restart_service"] = ActionPolicy(True, True)
        config = replace(
            app_config,
            agent=agent_settings,
            services=service_settings,
            policy=replace(app_config.policy, actions=actions),
        )

    incident_id = f"test-audit-failure-{scenario}"

    class FailingAudit:
        def record_event(self, **kwargs):
            if kwargs.get("event_type") == failed_event:
                raise AuditError("simulated audit failure")
            return audit_logger.record_event(**kwargs)

    def input_fn(_prompt):
        if scenario != "rejected":
            raise AssertionError(
                "Policy-blocked and dry-run paths must not request approval"
            )
        return "NO"

    result = run_remediation_workflow(
        proposal,
        incident_id=incident_id,
        config=config,
        registry=registry,
        audit=FailingAudit(),
        input_fn=input_fn,
        output_fn=lambda _line: None,
    )

    assert result["status"] == "audit_failure_before_execution"
    assert result["changes_made"] is False
    assert result["action"]["data"]["audit_failed_before_execution"] is True
    assert result["problem_resolution"]["status"] == "not_attempted"
    assert result["problem_resolution"]["resolved"] is False
    assert restart.called is False


def test_repair_request_for_unknown_endpoint_asks_for_service_context():
    result = no_proposal_result(
        "Khắc phục endpoint http://127.0.0.1:1/ không truy cập được",
        [
            (
                "Diagnosis: Endpoint unreachable "
                "(classification=endpoint_unreachable, confidence=high)."
            ),
            (
                "Confirmed fact: A connection to 127.0.0.1:1 was refused "
                "by the target endpoint."
            ),
            (
                "Confirmed fact: Local socket inspection reported zero "
                "listening sockets on 127.0.0.1:1 at inspection time."
            ),
        ],
    )

    question = result["follow_up_question"]
    assert question is not None
    assert "systemd unit" in question.casefold()
    assert result["changes_made"] is False
    assert result["problem_resolution"]["resolved"] is False


def test_incomplete_investigation_is_not_labeled_diagnosis_only() -> None:
    for status in ("failed", "inconclusive"):
        result = no_proposal_result(
            "Check service status",
            findings=(),
            investigation_status=status,
        )

        assert result["status"] == "not_proposed"
        assert result["changes_made"] is False
        assert result["problem_resolution"]["status"] == "not_attempted"
        assert result["problem_resolution"]["resolved"] is False
        assert "investigation" in result["message"].casefold()


def test_no_proposal_result_uses_connection_refusal_evidence():
    from linux_admin.remediation_workflow import no_proposal_result

    findings = [
        (
            "Diagnosis: Endpoint unreachable "
            "(classification=endpoint_unreachable, confidence=high)."
        ),
        "Confirmed fact: A connection to 127.0.0.1:1 was refused by the target endpoint.",
    ]

    result = no_proposal_result(
        "Kiểm tra endpoint http://127.0.0.1:1/ có truy cập được không",
        findings,
    )

    assert result["status"] == "not_proposed"
    assert result["changes_made"] is False
    assert "127.0.0.1:1" in result["recommended_next_step"]
    assert "dns" not in result["recommended_next_step"].casefold()
    assert "gateway" not in result["recommended_next_step"].casefold()
    assert "Không có hành động" in result["message"]
    assert "xácđịnh" not in result["message"]
    assert result["follow_up_question"] is None

def test_no_proposal_uses_empty_listener_evidence_for_refused_endpoint() -> None:
    from linux_admin.remediation_workflow import no_proposal_result

    result = no_proposal_result(
        "Kiểm tra endpoint",
        [
            (
                "Diagnosis: endpoint unreachable "
                "(classification=endpoint_unreachable, confidence=high)."
            ),
            (
                "Confirmed fact: A connection to 127.0.0.1:1 was refused "
                "by the target endpoint."
            ),
            (
                "Confirmed fact: Local socket inspection reported zero "
                "listening sockets on 127.0.0.1:1 at inspection time."
            ),
        ],
    )

    next_step = result["recommended_next_step"]
    assert "không tìm thấy listener" in next_step
    assert "dịch vụ dự kiến cung cấp endpoint" in next_step
    assert "status và log" not in next_step
    assert result["changes_made"] is False
    assert result["follow_up_question"] is None

def test_multi_endpoint_recommendation_uses_diagnostic_next_check():
    from linux_admin.remediation_workflow import no_proposal_result

    request = (
        "Compare the connection failure across "
        "http://127.0.0.1:1/ and http://127.0.0.1:2/"
    )
    recommendation = (
        "Inspect the listener on 127.0.0.1:2, then identify its expected "
        "owner from application or deployment configuration."
    )
    findings = [
        (
            "Diagnosis: Connection failure was observed on 2 of 2 endpoints "
            "(classification=endpoint_unreachable, confidence=high)."
        ),
        (
            "Confirmed fact: HTTP probe for http://127.0.0.1:1/ failed "
            "with ConnectionRefusedError."
        ),
        (
            "Confirmed fact: HTTP probe for http://127.0.0.1:2/ failed "
            "with ConnectionRefusedError."
        ),
        f"Recommended next check: {recommendation}",
    ]

    result = no_proposal_result(request, findings)

    assert result["status"] == "not_proposed"
    assert result["recommended_next_step"] == recommendation
    assert "dns" not in result["recommended_next_step"].casefold()
    assert "gateway" not in result["recommended_next_step"].casefold()
    assert result["changes_made"] is False
