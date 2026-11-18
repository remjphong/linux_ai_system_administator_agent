"""Tests for the Agent's bounded read-only workflow."""

from __future__ import annotations

import pytest

from linux_admin.agent import Agent, RuleBasedPlanner
from linux_admin.contracts import ToolResult, ToolSpec
from linux_admin.llm_client import AgentPlan, FakeLLMClient, PlanStep
from linux_admin.registry import ToolRegistry
from linux_admin.tools.logs import AuthLogTool, KernelLogTool
from linux_admin.tools.network import (
    ListeningPortTool,
    ListListeningPortsTool,
)
from linux_admin.tools.system import (
    IoStatsTool,
    ListAllMountsTool,
    SystemOverviewTool,
    TopProcessesTool,
)


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
        "currently inactive" in finding for finding in incident.findings
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
        failures={"get_failed_services": "simulated permission error"}
    )
    incident = Agent(
        registry=registry, config=app_config, audit=audit_logger
    ).run("Investigate service failure")

    assert incident.status == "completed"
    assert incident.evidence[0].status == "failed"
    assert len(incident.evidence) == 2
    assert incident.evidence[1].tool_name == "get_recent_errors"
    assert incident.evidence[1].ok
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

def test_endpoint_plan_does_not_guess_backing_service(
    app_config, registry_factory
) -> None:
    registry = registry_factory()
    planner = RuleBasedPlanner(app_config)
    available = [spec for spec in registry.list_tools() if not spec.changes_system]

    plan = planner.create_plan(
        "Check endpoint http://127.0.0.1:11434/", available
    )

    tool_names = [step.tool_name for step in plan.steps]
    assert tool_names == ["check_tcp_connectivity", "check_http_endpoint"]
    assert all("demo-web.service" not in str(step.arguments) for step in plan.steps)


def test_endpoint_plan_checks_service_only_when_explicitly_named(
    app_config, registry_factory
) -> None:
    registry = registry_factory()
    planner = RuleBasedPlanner(app_config)
    available = [spec for spec in registry.list_tools() if not spec.changes_system]

    plan = planner.create_plan(
        "Check endpoint http://127.0.0.1:18080/health and demo-web.service",
        available,
    )

    tool_names = [step.tool_name for step in plan.steps]
    assert tool_names == [
        "check_tcp_connectivity",
        "check_http_endpoint",
        "get_service_status",
        "get_service_logs",
    ]
    assert plan.steps[2].arguments["service_name"] == "demo-web.service"
    assert plan.steps[3].arguments["service_name"] == "demo-web.service"


def test_service_status_summary_prioritizes_not_found_over_inactive() -> None:
    result = ToolResult(
        tool_name="get_service_status",
        status="success",
        data={
            "service_name": "demo-web.service",
            "load_state": "not-found",
            "active_state": "inactive",
            "sub_state": "dead",
            "is_active": False,
            "loaded": False,
        },
    )

    summary = Agent._summarize_result(result)

    assert "was not found by systemd" in summary
    assert "load_state=not-found" in summary
    assert "currently inactive" not in summary


def test_agent_skips_logs_for_systemd_unit_not_found(
    app_config, audit_logger, registry_factory
) -> None:
    unit = "linux-admin-nonexistent-test.service"
    calls: list[tuple[str, dict]] = []
    registry = registry_factory(
        outputs={
            "get_service_status": {
                "service_name": unit,
                "load_state": "not-found",
                "active_state": "inactive",
                "sub_state": "dead",
                "loaded": False,
                "is_active": False,
            },
            "get_service_logs": {
                "service_name": unit,
                "lines": [],
                "line_count": 0,
                "since_minutes": 60,
            },
        },
        calls=calls,
    )

    incident = Agent(
        registry=registry,
        config=app_config,
        audit=audit_logger,
    ).run(f"Check service status for {unit}")

    assert incident.status == "completed"
    assert [item.tool_name for item in incident.evidence] == [
        "get_service_status"
    ]
    assert calls == [("get_service_status", {"service_name": unit})]
    assert any(
        "Skipped 1 queued get_service_logs check(s)" in finding
        for finding in incident.findings
    )

    events = audit_logger.list_events(incident_id=incident.incident_id)
    assert any(
        event["event_type"] == "incident.plan_step_skipped"
        and event["details"].get("reason") == "systemd_unit_not_found"
        for event in events
    )


def test_agent_stops_before_tools_if_plan_audit_write_fails(
    app_config, audit_logger, registry_factory, monkeypatch
) -> None:
    calls: list[tuple[str, dict]] = []
    registry = registry_factory(
        outputs={
            "check_tcp_connectivity": {
                "host": "127.0.0.1",
                "port": 11434,
                "reachable": True,
            },
            "check_http_endpoint": {
                "url": "http://127.0.0.1:11434/",
                "host": "127.0.0.1",
                "port": 11434,
                "reachable": True,
                "healthy": True,
                "status_code": 200,
                "reason": "OK",
                "redirect_followed": False,
            },
        },
        calls=calls,
    )

    original_record_event = audit_logger.record_event

    def fail_plan_event(
        event_type, incident_id, details, action_id=None
    ):
        if event_type == "incident.plan_created":
            raise RuntimeError("simulated audit failure")
        return original_record_event(
            event_type=event_type,
            incident_id=incident_id,
            details=details,
            action_id=action_id,
        )

    monkeypatch.setattr(audit_logger, "record_event", fail_plan_event)

    incident = Agent(registry, app_config, audit_logger).run(
        "Check whether http://127.0.0.1:11434/ is reachable."
    )

    assert incident.status == "failed"
    assert incident.steps == 0
    assert incident.evidence == []
    assert calls == []
    assert any("no tools were invoked" in finding for finding in incident.findings)


def test_agent_stops_after_tool_audit_write_fails(
    app_config, audit_logger, registry_factory, monkeypatch
) -> None:
    calls: list[tuple[str, dict]] = []
    registry = registry_factory(
        outputs={
            "check_tcp_connectivity": {
                "host": "127.0.0.1",
                "port": 11434,
                "reachable": True,
            },
            "check_http_endpoint": {
                "url": "http://127.0.0.1:11434/",
                "host": "127.0.0.1",
                "port": 11434,
                "reachable": True,
                "healthy": True,
                "status_code": 200,
                "reason": "OK",
                "redirect_followed": False,
            },
        },
        calls=calls,
    )

    original_record_event = audit_logger.record_event

    def fail_tool_event(
        event_type, incident_id, details, action_id=None
    ):
        if event_type == "tool.completed":
            raise RuntimeError("simulated audit failure")
        return original_record_event(
            event_type=event_type,
            incident_id=incident_id,
            details=details,
            action_id=action_id,
        )

    monkeypatch.setattr(audit_logger, "record_event", fail_tool_event)

    incident = Agent(registry, app_config, audit_logger).run(
        "Check whether http://127.0.0.1:11434/ is reachable."
    )

    assert incident.status == "failed"
    assert incident.steps == 1
    assert len(incident.evidence) == 1
    assert len(calls) == 1
    assert any("Audit persistence failed" in finding for finding in incident.findings)


def test_service_status_summary_does_not_treat_inactive_as_failure() -> None:
    result = ToolResult(
        tool_name="get_service_status",
        status="success",
        data={
            "service_name": "anacron.service",
            "load_state": "loaded",
            "active_state": "inactive",
            "sub_state": "dead",
            "service_type": "simple",
            "result": "success",
            "exec_main_status": "0",
            "remain_after_exit": "no",
            "is_active": False,
            "loaded": True,
        },
    )

    summary = Agent._summarize_result(result)

    assert "currently inactive" in summary
    assert "last execution result as success" in summary
    assert "does not establish a failure" in summary




def test_agent_adaptively_inspects_refused_loopback_port(
    app_config, audit_logger, registry_factory
) -> None:
    url = "http://127.0.0.1:1/"
    calls: list[tuple[str, dict]] = []
    registry = registry_factory(
        outputs={
            "check_tcp_connectivity": {
                "host": "127.0.0.1",
                "port": 1,
                "reachable": False,
                "error_type": "ConnectionRefusedError",
            },
            "check_http_endpoint": {
                "url": url,
                "host": "127.0.0.1",
                "port": 1,
                "reachable": False,
                "healthy": False,
                "status_code": None,
                "error_type": "ConnectionRefusedError",
            },
            "inspect_listening_port": {
                "port": 1,
                "listeners": [],
                "count": 0,
                "supported": True,
            },
            "get_recent_errors": {"errors": []},
        },
        calls=calls,
    )

    incident = Agent(
        registry=registry, config=app_config, audit=audit_logger
    ).run(f"Check endpoint {url} for connectivity")

    names = [result.tool_name for result in incident.evidence]
    assert incident.status == "completed"
    assert names == [
        "check_tcp_connectivity",
        "inspect_listening_port",
        "check_http_endpoint",
        "get_recent_errors",
    ]
    assert calls[1] == ("inspect_listening_port", {"port": 1})
    assert any(
        "Adaptive follow-up selected: inspect_listening_port" in finding
        for finding in incident.findings
    )



def test_agent_adaptively_inspects_reported_failed_service(
    app_config, audit_logger, registry_factory
) -> None:
    unit = "demo-web.service"
    calls: list[tuple[str, dict]] = []
    registry = registry_factory(
        outputs={
            "get_failed_services": {"failed_services": [unit]},
            "get_service_status": {
                "service_name": unit,
                "load_state": "loaded",
                "active_state": "failed",
                "sub_state": "failed",
                "result": "exit-code",
            },
            "get_service_logs": {
                "service_name": unit,
                "lines": ["Main process exited with status 1"],
            },
            "get_recent_errors": {"errors": []},
        },
        calls=calls,
    )

    incident = Agent(
        registry=registry, config=app_config, audit=audit_logger
    ).run("Investigate service failure")

    names = [result.tool_name for result in incident.evidence]
    assert incident.status == "completed"
    assert names == [
        "get_failed_services",
        "get_service_status",
        "get_service_logs",
        "get_recent_errors",
    ]
    assert calls[1] == ("get_service_status", {"service_name": unit})
    assert calls[2] == ("get_service_logs", {"service_name": unit})
    assert any(
        "Adaptive follow-up selected: get_service_status" in finding
        for finding in incident.findings
    )

@pytest.mark.parametrize(
    ("user_text", "expected", "arguments"),
    [
        ("List all mounts", "list_all_mounts", {}),
        ("Inspect disk I/O and iowait", "get_io_stats", {"sample_seconds": 1.0}),
        ("List listening ports", "list_listening_ports", {}),
        ("Inspect kernel OOM errors", "get_kernel_log",
         {"lines": 50, "since_minutes": 60, "priority": "err"}),
        ("Investigate SSH failed login anomalies", "check_auth_log",
         {"lines": 100, "since_minutes": 60, "brute_force_threshold": 10}),
        ("Investigate port 5432", "inspect_listening_port", {"port": 5432}),
        ("Kiểm tra cổng 5432", "inspect_listening_port", {"port": 5432}),
        ("CPU usage high", "list_top_processes", {"limit": 10, "sort_by": "cpu"}),
        ("RAM usage high", "list_top_processes", {"limit": 10, "sort_by": "memory"}),
        ("CPU RAM bottleneck", "list_top_processes",
         {"limit": 10, "sort_by": "both"}),
    ],
)
def test_r02_routes_read_only_specializations(app_config, user_text, expected, arguments):
    specs = [
        tool.spec for tool in (
            ListAllMountsTool, IoStatsTool, ListListeningPortsTool,
            ListeningPortTool, KernelLogTool, AuthLogTool,
            TopProcessesTool, SystemOverviewTool,
        )
    ]
    specs.append(ToolSpec(
        name="restart_service", description="must not be selected",
        risk_level="high", changes_system=True, requires_approval=True,
    ))
    plan = RuleBasedPlanner(app_config).create_plan(user_text, specs)
    steps = [step for step in plan.steps if step.tool_name == expected]
    assert len(steps) == 1
    assert steps[0].arguments == arguments
    assert "restart_service" not in [step.tool_name for step in plan.steps]
    assert len(plan.steps) <= app_config.agent.max_steps


def test_r02_legacy_process_schema_never_receives_sort_by(app_config):
    legacy = ToolSpec(
        name="list_top_processes", description="legacy process list",
        parameters={"type": "object", "properties": {
            "limit": {"type": "integer", "minimum": 1, "maximum": 50},
        }, "required": ["limit"], "additionalProperties": False},
    )
    plan = RuleBasedPlanner(app_config).create_plan("CPU usage high", [legacy])
    assert plan.steps[0].arguments == {"limit": 10}


def test_r02_unregistered_specializations_are_not_invented(app_config):
    plan = RuleBasedPlanner(app_config).create_plan("Inspect kernel OOM", [])
    assert plan.steps == ()


def test_r02_port_5432_does_not_guess_postgresql_service(app_config):
    tools = [
        ListeningPortTool.spec, ListListeningPortsTool.spec,
        ToolSpec(name="get_service_status", description="status"),
        ToolSpec(name="get_service_logs", description="logs"),
        ToolSpec(name="check_tcp_connectivity", description="tcp"),
    ]
    plan = RuleBasedPlanner(app_config).create_plan(
        "Why is port 5432 not listening?", tools,
    )
    assert {step.tool_name for step in plan.steps} == {
        "inspect_listening_port", "list_listening_ports",
    }
    assert plan.steps[0].arguments == {"port": 5432}


def test_r02_port_out_of_range_never_probes_arbitrary_endpoint(app_config):
    plan = RuleBasedPlanner(app_config).create_plan(
        "Investigate port 99999", [ListeningPortTool.spec],
    )
    assert plan.steps == ()


def test_r02_agent_never_executes_mutating_tool_for_mount_investigation(
    app_config, audit_logger,
):
    class FakeMountTool:
        spec = ListAllMountsTool.spec

        def execute(self, **kwargs):
            assert kwargs == {}
            return ToolResult(
                tool_name="list_all_mounts", status="success",
                data={"mounts": [{"mount_point": "/data", "used_percent": 85.0}]},
            )

    mutator = StateChangingTestTool()
    registry = ToolRegistry()
    registry.register(FakeMountTool())
    registry.register(mutator)
    incident = Agent(registry, app_config, audit_logger).run("List all mounts")
    assert incident.status == "completed"
    assert not mutator.called
    assert any("Mount /data reported 85.0%" in line for line in incident.findings)


def test_r02_hybrid_complex_specialization_does_not_call_llm(app_config):
    from linux_admin.agent import HybridPlanner

    class UnexpectedLLM:
        def create_plan(self, user_request, available_tools):
            raise AssertionError("Specialized local investigation must be deterministic")

    planner = HybridPlanner(
        app_config, RuleBasedPlanner(app_config), UnexpectedLLM(),
    )
    plan = planner.create_plan(
        "Compare kernel OOM with disk I/O",
        [KernelLogTool.spec, IoStatsTool.spec],
    )
    assert {step.tool_name for step in plan.steps} == {
        "get_kernel_log", "get_io_stats",
    }
