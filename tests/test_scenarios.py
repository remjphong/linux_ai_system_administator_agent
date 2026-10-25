"""Deterministic acceptance-style tests for the three beta incidents.

These tests use fake tools and SQLite in a temporary directory. They are safe to
run on Windows 10/11 and Ubuntu; no real service, filesystem cleanup, network
request, LLM API, or system-changing command is executed.
"""

from __future__ import annotations

from linux_admin.agent import Agent


def _data_by_tool(incident):
    return {result.tool_name: result.data for result in incident.evidence if result.ok}


def test_scenario_service_failure_collects_status_and_logs(
    app_config, audit_logger, registry_factory
) -> None:
    calls: list[tuple[str, dict]] = []
    registry = registry_factory(
        outputs={
            "get_service_status": {
                "service_name": "demo-web.service",
                "active_state": "failed",
                "is_active": False,
            },
            "get_failed_services": {"failed_services": ["demo-web.service"]},
            "get_service_logs": {
                "service_name": "demo-web.service",
                "lines": ["Main process exited with status 1"],
            },
        },
        calls=calls,
    )

    incident = Agent(registry, app_config, audit_logger).run(
        "Investigate service failure for demo-web.service"
    )
    evidence = _data_by_tool(incident)

    assert incident.status == "completed"
    assert evidence["get_service_status"]["active_state"] == "failed"
    assert "demo-web.service" in evidence["get_failed_services"]["failed_services"]
    assert evidence["get_service_logs"]["lines"]
    assert [name for name, _ in calls] == [
        "get_service_status",
        "get_failed_services",
        "get_service_logs",
    ]
    assert not any(name == "restart_service" for name, _ in calls)


def test_scenario_unreachable_endpoint_checks_tcp_http_and_service(
    app_config, audit_logger, registry_factory
) -> None:
    calls: list[tuple[str, dict]] = []
    registry = registry_factory(
        outputs={
            "check_tcp_connectivity": {
                "host": "127.0.0.1",
                "port": 8080,
                "reachable": False,
            },
            "check_http_endpoint": {
                "url": "http://127.0.0.1:8080/health",
                "reachable": False,
                "status_code": 503,
            },
            "get_service_status": {
                "service_name": "demo-web.service",
                "active_state": "active",
                "is_active": True,
            },
            "get_service_logs": {
                "service_name": "demo-web.service",
                "lines": ["Application readiness check failed"],
            },
        },
        calls=calls,
    )

    incident = Agent(registry, app_config, audit_logger).run(
        "Investigate why http://127.0.0.1:8080/health is unreachable"
    )
    evidence = _data_by_tool(incident)

    assert incident.status == "completed"
    assert evidence["check_tcp_connectivity"]["reachable"] is False
    assert evidence["check_http_endpoint"]["status_code"] == 503
    assert evidence["get_service_status"]["active_state"] == "active"
    assert "get_service_logs" in evidence
    assert len(calls) == 4
    assert not any(name == "restart_service" for name, _ in calls)


def test_scenario_disk_pressure_diagnoses_without_deleting_data(
    app_config, audit_logger, registry_factory
) -> None:
    calls: list[tuple[str, dict]] = []
    registry = registry_factory(
        outputs={
            "get_disk_usage": {
                "path": "/",
                "total_bytes": 1000,
                "used_bytes": 970,
                "free_bytes": 30,
                "used_percent": 97.0,
            },
            "get_system_overview": {
                "platform": "Linux",
                "cpu_percent": 22.0,
                "memory_percent": 78.0,
            },
            "list_top_processes": {
                "processes": [{"pid": 123, "name": "demo-app"}],
                "limit": 5,
            },
        },
        calls=calls,
    )

    incident = Agent(registry, app_config, audit_logger).run(
        "Investigate disk pressure on filesystem /"
    )
    evidence = _data_by_tool(incident)

    assert incident.status == "completed"
    assert evidence["get_disk_usage"]["used_percent"] == 97.0
    assert "get_system_overview" in evidence
    assert "list_top_processes" in evidence
    assert [name for name, _ in calls] == [
        "get_disk_usage",
        "get_system_overview",
        "list_top_processes",
    ]
    assert not any(name in {"delete_files", "clean_package_cache"} for name, _ in calls)
    assert any(
        "does not mean the incident is repaired" in item
        for item in incident.findings
    )


def test_scenario_records_audit_for_each_incident(
    app_config, audit_logger, registry_factory
) -> None:
    incident = Agent(
        registry_factory(), app_config, audit_logger
    ).run("Investigate service failure")

    events = audit_logger.list_events(incident_id=incident.incident_id)
    event_types = [event["event_type"] for event in events]

    assert event_types[0] == "incident.started"
    assert "incident.plan_created" in event_types
    assert "tool.completed" in event_types
    assert event_types[-1] == "incident.finished"
