"""Tests for the Agent's bounded read-only workflow."""

from __future__ import annotations

from linux_admin.agent import Agent
from linux_admin.contracts import ToolResult, ToolSpec
from linux_admin.llm_client import AgentPlan, FakeLLMClient, PlanStep
from linux_admin.registry import ToolRegistry


class StateChangingTestTool:
    """A trap tool used to prove the Agent refuses direct mutation calls."""

    spec = ToolSpec(
        name="restart_service",
        description="Test-only state-changing operation",
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

    def __init__(self) -> None:
        self.called = False

    def execute(self, **kwargs: object) -> ToolResult:
        self.called = True
        return ToolResult(tool_name=self.spec.name, status="success")


def test_agent_runs_rule_based_service_investigation(
    app_config, audit_logger, registry_factory
) -> None:
    registry = registry_factory()
    agent = Agent(registry=registry, config=app_config, audit=audit_logger)

    incident = agent.run("Investigate service failure for demo-web.service")

    assert incident.status == "completed"
    assert incident.steps == 3
    assert [item.tool_name for item in incident.evidence] == [
        "get_service_status",
        "get_failed_services",
        "get_service_logs",
    ]
    assert any(
        "active_state='inactive'" in finding for finding in incident.findings
    )
    assert any(
        "does not mean the incident is repaired" in finding
        for finding in incident.findings
    )

    events = audit_logger.list_events(incident_id=incident.incident_id)
    assert events[0]["event_type"] == "incident.started"
    assert events[-1]["event_type"] == "incident.finished"
    assert events[-1]["details"]["status"] == "completed"


def test_agent_returns_inconclusive_when_no_matching_tools_exist(
    app_config, audit_logger
) -> None:
    incident = Agent(
        registry=ToolRegistry(), config=app_config, audit=audit_logger
    ).run("Investigate disk pressure")

    assert incident.status == "inconclusive"
    assert incident.evidence == []
    assert any("No applicable read-only tools" in item for item in incident.findings)


def test_agent_enforces_max_steps(app_config, audit_logger, registry_factory) -> None:
    registry = registry_factory()
    plan = AgentPlan(
        steps=tuple(
            PlanStep("get_system_overview", {}, "Read system overview")
            for _ in range(app_config.agent.max_steps + 3)
        ),
        rationale="Deliberately oversized plan for a safety test.",
    )
    agent = Agent(
        registry=registry,
        config=app_config,
        audit=audit_logger,
        planner=FakeLLMClient(default_plan=plan),
    )

    incident = agent.run("Run the supplied test plan")

    assert incident.status == "completed"
    assert incident.steps == app_config.agent.max_steps
    assert len(incident.evidence) == app_config.agent.max_steps
    assert any("Plan limited to" in item for item in incident.findings)


def test_agent_never_executes_state_changing_tool_directly(
    app_config, audit_logger, registry_factory
) -> None:
    registry = registry_factory()
    trap_tool = StateChangingTestTool()
    registry.register(trap_tool)
    plan = AgentPlan(
        steps=(PlanStep("restart_service", {"service_name": "demo-web.service"}),),
        rationale="Adversarial plan proposes a restart.",
    )
    incident = Agent(
        registry=registry,
        config=app_config,
        audit=audit_logger,
        planner=FakeLLMClient(default_plan=plan),
    ).run("Investigate service failure")

    assert trap_tool.called is False
    assert incident.evidence[0].status == "denied"
    assert incident.status == "inconclusive"


def test_agent_records_failed_tool_and_continues_with_other_evidence(
    app_config, audit_logger, registry_factory
) -> None:
    registry = registry_factory(
        failures={"get_service_status": "simulated permission error"}
    )
    incident = Agent(
        registry=registry, config=app_config, audit=audit_logger
    ).run("Investigate service failure")

    assert incident.status == "completed"
    assert incident.evidence[0].status == "failed"
    assert len(incident.evidence) == 3
    assert any("Some tools failed" in item for item in incident.findings)


def test_agent_fails_closed_if_audit_write_fails(app_config, registry_factory) -> None:
    class BrokenAudit:
        def record_event(self, **kwargs: object) -> int:
            raise OSError("database unavailable")

    calls: list[tuple[str, dict]] = []
    registry = registry_factory(calls=calls)
    incident = Agent(registry=registry, config=app_config, audit=BrokenAudit()).run(
        "Investigate disk pressure"
    )

    assert incident.status == "failed"
    assert incident.evidence == []
    assert calls == []


def test_audit_logger_redacts_secret_like_fields(tmp_path) -> None:
    from linux_admin.audit import AuditLogger

    logger = AuditLogger(tmp_path / "redaction.db")
    try:
        logger.record_event(
            "test.secret_redaction",
            "incident-redaction",
            {
                "provider": "fake",
                "api_key": "should-not-be-stored",
                "nested": {"password": "another-secret", "result": "ok"},
            },
        )
        event = logger.list_events(incident_id="incident-redaction")[0]
    finally:
        logger.close()

    assert event["details"]["api_key"] == "[REDACTED]"
    assert event["details"]["nested"]["password"] == "[REDACTED]"
    assert event["details"]["nested"]["result"] == "ok"
