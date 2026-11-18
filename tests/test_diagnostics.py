"""Offline tests for deterministic evidence-to-diagnosis classification."""

from __future__ import annotations

from linux_admin.contracts import ToolResult
from linux_admin.diagnostics import (
    diagnose_incident,
    synthesize_specialized_evidence,
)


def result(name: str, data: dict, *, status: str = "success") -> ToolResult:
    return ToolResult(
        tool_name=name,
        status=status,  # type: ignore[arg-type]
        data=data,
        error=None if status == "success" else "synthetic test failure",
    )


def test_failed_service_does_not_invent_root_cause() -> None:
    report = diagnose_incident(
        "Investigate nginx.service",
        [
            result(
                "get_service_status",
                {
                    "service_name": "nginx.service",
                    "load_state": "loaded",
                    "active_state": "failed",
                    "sub_state": "failed",
                    "result": "exit-code",
                    "exec_main_status": "1",
                },
            )
        ],
    )

    assert report.classification == "service_failed"
    assert report.confidence == "high"
    assert any(
        "in failed state" in fact
        for fact in report.confirmed_facts
    )
    assert "root cause needs log evidence" in report.summary
    assert any(
        "Inspect recent logs" in check
        for check in report.next_checks
    )


def test_http_200_is_reachable_but_not_claimed_fully_healthy() -> None:
    report = diagnose_incident(
        "Check endpoint",
        [
            result(
                "check_tcp_connectivity",
                {"host": "127.0.0.1", "port": 11434, "reachable": True},
            ),
            result(
                "check_http_endpoint",
                {
                    "url": "http://127.0.0.1:11434/",
                    "host": "127.0.0.1",
                    "port": 11434,
                    "reachable": True,
                    "healthy": True,
                    "status_code": 200,
                },
            ),
        ],
    )

    assert report.classification == "endpoint_reachable"
    assert any("HTTP endpoint returned status 200" in item for item in report.confirmed_facts)
    assert any("not every application function" in item for item in report.confirmed_facts)
    assert not report.hypotheses


def test_connection_refused_does_not_invent_backing_service() -> None:
    report = diagnose_incident(
        "Investigate http://127.0.0.1:18080/health",
        [
            result(
                "check_tcp_connectivity",
                {
                    "host": "127.0.0.1",
                    "port": 18080,
                    "reachable": False,
                    "error_type": "ConnectionRefusedError",
                },
            ),
            result(
                "check_http_endpoint",
                {
                    "url": "http://127.0.0.1:18080/health",
                    "host": "127.0.0.1",
                    "port": 18080,
                    "reachable": False,
                    "status_code": None,
                    "error_type": "ConnectionRefusedError",
                },
            ),
        ],
    )

    assert report.classification == "endpoint_unreachable"
    assert any("connection to 127.0.0.1:18080 was refused" in item for item in report.confirmed_facts)
    assert any("does not distinguish these causes" in item for item in report.hypotheses)
    assert any("Identify the process/service intended" in item for item in report.next_checks)


def test_connection_refused_uses_empty_local_listener_evidence() -> None:
    report = diagnose_incident(
        "Investigate http://127.0.0.1:18080/health",
        [
            result(
                "check_tcp_connectivity",
                {
                    "host": "127.0.0.1",
                    "port": 18080,
                    "reachable": False,
                    "error_type": "ConnectionRefusedError",
                },
            ),
            result(
                "inspect_listening_port",
                {
                    "port": 18080,
                    "listeners": [],
                    "count": 0,
                    "supported": True,
                },
            ),
        ],
    )

    assert report.classification == "endpoint_unreachable"
    assert any(
        "zero listening sockets on 127.0.0.1:18080" in item
        for item in report.confirmed_facts
    )
    assert any(
        "does not identify which service" in item
        for item in report.hypotheses
    )
    assert any(
        "expected service" in item and "configuration" in item
        for item in report.next_checks
    )


def test_http_503_marks_server_error_not_connection_failure() -> None:
    report = diagnose_incident(
        "Check endpoint",
        [
            result(
                "check_tcp_connectivity",
                {"host": "127.0.0.1", "port": 8080, "reachable": True},
            ),
            result(
                "check_http_endpoint",
                {
                    "url": "http://127.0.0.1:8080/health",
                    "host": "127.0.0.1",
                    "port": 8080,
                    "reachable": True,
                    "status_code": 503,
                },
            ),
        ],
    )

    assert report.classification == "http_server_error"
    assert any("status 503" in item for item in report.confirmed_facts)
    assert any("does not establish which component" in item for item in report.hypotheses)


def test_systemd_not_found_takes_precedence_over_inactive() -> None:
    report = diagnose_incident(
        "Investigate demo-web.service",
        [
            result(
                "get_service_status",
                {
                    "service_name": "demo-web.service",
                    "load_state": "not-found",
                    "active_state": "inactive",
                    "sub_state": "dead",
                    "loaded": False,
                    "is_active": False,
                },
            )
        ],
    )

    assert report.classification == "service_missing"
    assert "not-found" in report.confirmed_facts[0]
    assert any("may be wrong or the service may not be installed" in item for item in report.hypotheses)


def test_active_service_with_no_recent_logs_is_not_called_failed() -> None:
    report = diagnose_incident(
        "Check accounts-daemon.service",
        [
            result(
                "get_service_status",
                {
                    "service_name": "accounts-daemon.service",
                    "load_state": "loaded",
                    "active_state": "active",
                    "sub_state": "running",
                    "is_active": True,
                },
            ),
            result("get_failed_services", {"failed_services": [], "count": 0}),
            result(
                "get_service_logs",
                {
                    "service_name": "accounts-daemon.service",
                    "lines": [],
                    "line_count": 0,
                    "since_minutes": 60,
                },
            ),
        ],
    )

    assert report.classification == "service_running"
    assert any("active (running)" in item for item in report.confirmed_facts)
    assert any("No journal entries" in item for item in report.confirmed_facts)
    assert "failed" not in report.summary.casefold()


def test_inactive_successful_oneshot_is_not_assumed_failed() -> None:
    report = diagnose_incident(
        "Check anacron.service",
        [
            result(
                "get_service_status",
                {
                    "service_name": "anacron.service",
                    "load_state": "loaded",
                    "active_state": "inactive",
                    "sub_state": "dead",
                    "result": "success",
                    "exec_main_status": "0",
                    "remain_after_exit": "no",
                },
            )
        ],
    )

    assert report.classification == "service_inactive"
    assert any("last recorded execution succeeded" in item for item in report.confirmed_facts)
    assert any("does not prove a service failure" in item for item in report.confirmed_facts)


def test_failed_tool_results_in_inconclusive_diagnosis() -> None:
    report = diagnose_incident(
        "Check system",
        [result("get_system_overview", {}, status="timeout")],
    )

    assert report.classification == "inconclusive"
    assert report.confidence == "low"
    assert any("status timeout" in item for item in report.confirmed_facts)


def test_report_renders_facts_hypotheses_and_next_checks_separately() -> None:
    report = diagnose_incident(
        "Check endpoint",
        [
            result(
                "check_tcp_connectivity",
                {"host": "127.0.0.1", "port": 8080, "reachable": False, "error_type": "ConnectionRefusedError"},
            )
        ],
    )

    rendered = report.to_findings()
    assert rendered[0].startswith("Diagnosis:")
    assert any(line.startswith("Confirmed fact:") for line in rendered)
    assert any(line.startswith("Unconfirmed hypothesis:") for line in rendered)
    assert any(line.startswith("Recommended next check:") for line in rendered)

def test_resource_pressure_snapshot_reports_indicators_without_inventing_cause():
    report = diagnose_incident(
        "Investigate system resource pressure",
        [
            result(
                "get_system_overview",
                {
                    "cpu_percent": 92.5,
                    "memory_percent": 93.2,
                    "swap_percent": 14.0,
                },
            ),
            result(
                "get_disk_usage",
                {
                    "path": "/",
                    "used_percent": 97.0,
                },
            ),
        ],
    )

    assert report.classification == "resource_pressure"
    assert report.confidence == "medium"
    assert any("92.5%" in fact for fact in report.confirmed_facts)
    assert any("93.2%" in fact for fact in report.confirmed_facts)
    assert any("97.0%" in fact for fact in report.confirmed_facts)
    assert any("root cause" in hypothesis for hypothesis in report.hypotheses)
    assert any("Repeat resource measurements" in check for check in report.next_checks)


def test_normal_resource_snapshot_does_not_claim_system_is_healthy():
    report = diagnose_incident(
        "Check CPU usage and system performance",
        [
            result(
                "get_system_overview",
                {
                    "cpu_percent": 0.0,
                    "memory_percent": 47.4,
                    "swap_percent": 14.5,
                },
            ),
        ],
    )

    assert report.classification == "resource_snapshot_no_pressure_signal"
    assert report.confidence == "medium"
    assert any("0.0%" in fact for fact in report.confirmed_facts)
    assert "does not establish overall system health" in report.summary
    assert any("single sample" in hypothesis for hypothesis in report.hypotheses)


def test_general_system_survey_aggregates_all_read_only_evidence() -> None:
    report = diagnose_incident(
        "Kiểm tra tình trạng hệ thống, có vấn đề nào bất thường không.",
        [
            result(
                "get_system_overview",
                {
                    "cpu_percent": 12.0,
                    "memory_percent": 28.2,
                    "swap_percent": 0.0,
                    "process_count": 218,
                },
            ),
            result(
                "get_disk_usage",
                {"path": "/", "used_percent": 59.1},
            ),
            result(
                "get_network_state",
                {
                    "count": 2,
                    "interfaces": [
                        {"name": "enp0s3", "is_up": True, "addresses": []},
                        {"name": "lo", "is_up": True, "addresses": []},
                    ],
                },
            ),
            result(
                "get_failed_services",
                {"failed_services": [], "count": 0},
            ),
            result(
                "get_recent_errors",
                {
                    "errors": [
                        "polkit-agent-helper: authentication conversation failed",
                        "pam_unix(polkit-1:auth): could not identify password",
                    ],
                    "count": 2,
                    "since_minutes": 60,
                },
            ),
        ],
    )

    assert report.classification == "system_survey"
    assert report.confidence == "medium"
    assert "2 recent error-priority journal message(s) were found" in report.summary
    assert any("CPU utilization was 12.0%" in fact for fact in report.confirmed_facts)
    assert any("RAM utilization was 28.2%" in fact for fact in report.confirmed_facts)
    assert any("Filesystem / was 59.1% used" in fact for fact in report.confirmed_facts)
    assert any("2 interface record(s): 2 up and 0 down" in fact for fact in report.confirmed_facts)
    assert any("returned no failed units" in fact for fact in report.confirmed_facts)
    assert any("2 non-empty message(s)" in fact for fact in report.confirmed_facts)
    assert any("polkit-agent-helper" in fact for fact in report.confirmed_facts)
    assert any("does not establish DNS resolution" in item for item in report.hypotheses)
    assert any("comprehensive security assessment" in item for item in report.hypotheses)


def test_system_survey_reports_pressure_without_claiming_a_root_cause() -> None:
    report = diagnose_incident(
        "Kiểm tra tình trạng hệ thống, có vấn đề nào bất thường không.",
        [
            result("get_system_overview", {
                "cpu_percent": 95.0,
                "memory_percent": 92.0,
                "swap_percent": 0.0,
            }),
            result("get_disk_usage", {"path": "/", "used_percent": 59.0}),
            result("get_network_state", {"interfaces": [], "count": 0}),
            result("get_failed_services", {"failed_services": [], "count": 0}),
            result("get_recent_errors", {"errors": [], "count": 0}),
        ],
    )

    assert report.classification == "system_survey"
    assert "resource threshold signal(s)" in report.summary
    assert any("root cause" in item for item in report.hypotheses)
    assert any("Repeat resource measurements" in item for item in report.next_checks)


def test_generic_vietnamese_system_status_uses_system_survey() -> None:
    report = diagnose_incident(
        "hệ thống đang trong tình trạng thế nào",
        [
            result("get_system_overview", {
                "cpu_percent": 10.0,
                "memory_percent": 30.0,
                "swap_percent": 0.0,
            }),
            result("get_disk_usage", {
                "path": "/", "used_percent": 50.0,
            }),
            result("get_network_state", {
                "interfaces": [{"name": "enp0s3", "is_up": True}],
                "count": 1,
            }),
            result("get_failed_services", {
                "failed_services": [], "count": 0,
            }),
            result("get_recent_errors", {
                "errors": [], "count": 0, "since_minutes": 60,
            }),
        ],
    )

    assert report.classification == "system_survey"
    assert any("CPU utilization was 10.0%" in fact for fact in report.confirmed_facts)
    assert any("Filesystem / was 50.0% used" in fact for fact in report.confirmed_facts)

def test_r02_config_threshold_is_read_at_runtime(app_config, tmp_path):
    from linux_admin.config import ConfigurationError, load_config

    assert app_config.policy.resource_threshold_percent == 80.0
    for filename in ("agent.yaml", "policy.yaml", "services.yaml"):
        (tmp_path / filename).write_text(
            (app_config.config_dir / filename).read_text(encoding="utf-8"),
            encoding="utf-8",
        )
    policy_file = tmp_path / "policy.yaml"
    original = policy_file.read_text(encoding="utf-8")
    import pytest

    for invalid in ("0", "101", "true", '"not-a-number"'):
        policy_file.write_text(
            original.replace("resource_threshold_percent: 80",
                             f"resource_threshold_percent: {invalid}"),
            encoding="utf-8",
        )
        with pytest.raises(ConfigurationError, match="resource_threshold_percent"):
            load_config(config_dir=tmp_path, project_root=app_config.project_root,
                        dotenv_path=tmp_path / "no.env")


def test_r02_threshold_is_effective_at_boundary() -> None:
    for percent, expected in ((79.9, False), (80.0, True), (80.1, True)):
        evidence = [result("get_system_overview", {
            "cpu_percent": percent, "memory_percent": 30.0,
            "swap_percent": 0.0,
        })]
        report = diagnose_incident(
            "Check CPU", evidence, resource_threshold_percent=80.0,
        )
        assert (report.classification == "resource_pressure") is expected
        assert not any("sustained" in fact for fact in report.confirmed_facts)
        assert (
            "snapshot" in report.summary.lower()
            or any("sample" in item for item in report.hypotheses)
        )


def test_r02_policy_threshold_changes_generic_and_survey_paths() -> None:
    evidence = [result("get_system_overview", {
        "cpu_percent": 85.0, "memory_percent": 85.0, "swap_percent": 0.0,
    })]
    generic = diagnose_incident(
        "Check CPU RAM", evidence, resource_threshold_percent=90.0,
    )
    survey = diagnose_incident(
        "Kiểm tra tình trạng hệ thống", evidence,
        resource_threshold_percent=80.0,
    )
    assert generic.classification == "resource_snapshot_no_pressure_signal"
    assert "resource threshold signal(s)" in survey.summary
    assert "80% investigation threshold" in " ".join(survey.confirmed_facts)


def test_r02_specialized_evidence_keeps_facts_and_hypotheses_distinct():
    evidence = [
        result("list_all_mounts", {"mounts": [
            {"mount_point": "/data", "used_percent": 80.0}]}),
        result("list_listening_ports", {"sockets": [
            {"local_port": 5432, "pid": 1234}]}),
        result("get_io_stats", {"sample_seconds": 1.0,
            "io_wait_percent": 20.0,
            "disk_stats": [{"device": "sda", "util_percent": 95.0}]}),
        result("get_kernel_log", {"messages": ["kernel: Out of memory: killed process"]}),
        result("check_auth_log", {"failed_login_count": 12,
            "successful_login_count": 1, "brute_force_suspected": True,
            "suspicious_ips": [{"ip": "192.0.2.4", "failure_count": 12}]}),
        result("list_top_processes", {"top_cpu": [{"pid": 10}],
            "top_memory": [{"pid": 11}]}),
    ]
    findings = synthesize_specialized_evidence(
        "Investigate port 5432 and CPU RAM bottleneck", evidence,
    )
    assert any("80.0% usage" in f for f in findings if f.startswith("Confirmed"))
    assert any("port 5432" in f for f in findings if f.startswith("Confirmed"))
    assert any("OOM-related text" in f for f in findings if f.startswith("Confirmed"))
    assert any("failed login" in f for f in findings if f.startswith("Confirmed"))
    assert any("short snapshots" in f for f in findings if f.startswith("Unconfirmed"))
    assert not any("compromised" in f or "sustained bottleneck confirmed" in f
                   for f in findings)


def test_r02_failed_tools_never_generate_synthetic_success_facts():
    findings = synthesize_specialized_evidence(
        "Inspect auth and kernel", [
            result("check_auth_log", {"failed_login_count": 100}, status="failed"),
            result("get_kernel_log", {"messages": ["OOM"]}, status="failed"),
        ],
    )
    assert any("returned status failed" in f for f in findings)
    assert not any("100 failed" in f or "OOM-related" in f for f in findings)
