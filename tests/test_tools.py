"""Tool and Registry tests that are safe on Windows and Ubuntu.

External system commands, network connections for diagnostic paths, and service
changes are mocked. Two psutil-backed tests read local metrics without changing state.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from linux_admin.config import load_config
from linux_admin.contracts import (
    ActionRequest,
    ApprovalRecord,
    PolicyDecision,
    ToolResult,
    ToolSpec,
)
from linux_admin.registry import ToolRegistry, ToolRegistryError
from linux_admin.tools import register_builtin_tools
from linux_admin.tools.logs import (
    AuthLogTool,
    FailedServicesTool,
    KernelLogTool,
    RecentErrorsTool,
    ServiceLogsTool,
)
from linux_admin.tools.network import (
    HttpEndpointTool,
    ListListeningPortsTool,
    NetworkStateTool,
    TcpConnectivityTool,
)
from linux_admin.tools.security import InspectSecurityPostureTool
from linux_admin.tools.services import RestartServiceTool, ServiceStatusTool
from linux_admin.tools.system import (
    DiskUsageTool,
    IoStatsTool,
    ListAllMountsTool,
    SystemOverviewTool,
    TopProcessesTool,
)
from linux_admin.verification import (
    RecoveryManager,
    VerifyEndpointTool,
    VerifyServiceHealthTool,
)


class EchoTool:
    spec = ToolSpec(
        name="echo_message",
        description="Return a message for registry tests",
        parameters={
            "type": "object",
            "properties": {"message": {"type": "string", "minLength": 1}},
            "required": ["message"],
            "additionalProperties": False,
        },
    )

    def execute(self, **kwargs: Any) -> ToolResult:
        return ToolResult(
            tool_name=self.spec.name,
            status="success",
            data={"message": kwargs["message"]},
        )


class RestartTool:
    spec = ToolSpec(
        name="restart_service",
        description="Restart one pre-approved service",
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

    def execute(self, **kwargs: Any) -> ToolResult:
        return ToolResult(
            tool_name=self.spec.name,
            status="success",
            data={"restarted": kwargs["service_name"]},
        )


class WrongResultTool:
    spec = ToolSpec(name="wrong_result", description="Return a mismatched result")

    def execute(self, **kwargs: Any) -> ToolResult:
        del kwargs
        return ToolResult(tool_name="another_tool", status="success")


def test_registry_invokes_explicitly_registered_tool() -> None:
    registry = ToolRegistry()
    registry.register(EchoTool())

    result = registry.invoke("echo_message", {"message": "hello"})

    assert result.ok is True
    assert result.data["message"] == "hello"


def test_registry_rejects_unknown_tool() -> None:
    result = ToolRegistry().invoke("not_registered")

    assert result.status == "failed"
    assert result.error == "Unknown tool: not_registered"


def test_registry_validates_required_and_unexpected_arguments() -> None:
    registry = ToolRegistry()
    registry.register(EchoTool())

    missing = registry.invoke("echo_message", {})
    unexpected = registry.invoke("echo_message", {"message": "hi", "shell": True})
    wrong_type = registry.invoke("echo_message", {"message": 123})

    assert missing.status == "invalid_input"
    assert unexpected.status == "invalid_input"
    assert wrong_type.status == "invalid_input"


def test_registry_rejects_duplicate_tool_names() -> None:
    registry = ToolRegistry()
    registry.register(EchoTool())

    try:
        registry.register(EchoTool())
    except ToolRegistryError:
        pass
    else:
        raise AssertionError("Duplicate tool registration should fail")


def test_registry_rejects_mismatched_result_name() -> None:
    registry = ToolRegistry()
    registry.register(WrongResultTool())

    result = registry.invoke("wrong_result")

    assert result.status == "failed"
    assert result.error == "Tool result name does not match registered tool name"


def test_shared_yaml_configuration_loads_and_defaults_fail_closed(monkeypatch) -> None:
    monkeypatch.setenv("LLM_ENABLED", "false")
    monkeypatch.setenv("TAVILY_ENABLED", "false")
    config = load_config()

    assert config.agent.mode == "observe"
    assert config.agent.dry_run is True
    assert config.policy.default_decision == "deny"
    assert config.policy.actions["restart_service"].allowed is False
    assert config.services.restart_enabled is False
    assert config.llm.enabled is False


def test_registry_blocks_state_changing_tool_through_normal_invoke() -> None:
    registry = ToolRegistry()
    registry.register(RestartTool())

    result = registry.invoke("restart_service", {"service_name": "demo-web.service"})

    assert result.status == "denied"
    assert "controlled action path" in (result.error or "")


def test_authorized_action_requires_matching_approval() -> None:
    registry = ToolRegistry()
    registry.register(RestartTool())
    request = ActionRequest(
        action_name="restart_service",
        arguments={"service_name": "demo-web.service"},
        reason="A test incident requires a restart",
    )
    decision = PolicyDecision(
        action_id=request.action_id,
        outcome="approval_required",
        reason="Policy requires approval",
        action_fingerprint=request.fingerprint,
    )

    denied = registry.invoke_authorized_action(request, decision)
    approved = ApprovalRecord(
        action_id=request.action_id,
        action_fingerprint=request.fingerprint,
        approved=True,
        approver="test-user",
        reason="Approved for unit test",
    )
    result = registry.invoke_authorized_action(request, decision, approved)

    assert denied.status == "denied"
    assert result.ok is True
    assert result.data["restarted"] == "demo-web.service"


def test_approval_for_different_arguments_is_rejected() -> None:
    registry = ToolRegistry()
    registry.register(RestartTool())
    request = ActionRequest(
        action_name="restart_service",
        arguments={"service_name": "demo-web.service"},
        reason="A test incident requires a restart",
    )
    decision = PolicyDecision(
        action_id=request.action_id,
        outcome="approval_required",
        reason="Policy requires approval",
        action_fingerprint=request.fingerprint,
    )
    unrelated_approval = ApprovalRecord(
        action_id=request.action_id,
        action_fingerprint="not-the-same-request",
        approved=True,
        approver="test-user",
        reason="Approval must not transfer to another action",
    )

    result = registry.invoke_authorized_action(request, decision, unrelated_approval)

    assert result.status == "denied"


def test_system_overview_reads_real_platform_metrics() -> None:
    result = SystemOverviewTool().execute()
    assert result.ok is True
    assert result.data["platform"]
    assert 0 <= result.data["memory_percent"] <= 100
    assert result.data["memory_total_bytes"] > 0


def test_disk_usage_reads_test_directory(tmp_path) -> None:
    (tmp_path / "sample.txt").write_text("hello", encoding="utf-8")
    result = DiskUsageTool().execute(path=str(tmp_path))
    assert result.ok is True
    assert result.data["total_bytes"] >= result.data["used_bytes"]
    assert result.data["free_bytes"] >= 0


def test_disk_usage_rejects_nonexistent_path(tmp_path) -> None:
    result = DiskUsageTool().execute(path=str(tmp_path / "missing"))
    assert result.status == "invalid_input"


def test_top_processes_enforces_bounds_and_returns_records() -> None:
    tool = TopProcessesTool()
    assert tool.execute(limit=0).status == "invalid_input"
    result = tool.execute(limit=3)
    assert result.ok is True
    assert len(result.data["processes"]) <= 3


def test_failed_services_parses_systemctl_output(monkeypatch) -> None:
    import linux_admin.tools.logs as logs_module

    monkeypatch.setattr(logs_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(logs_module.shutil, "which", lambda _name: "/usr/bin/systemctl")
    calls: list[tuple[list[str], dict[str, Any]]] = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(
            returncode=0,
            stdout="demo-web.service loaded failed failed Demo web\n",
            stderr="",
        )

    monkeypatch.setattr(logs_module.subprocess, "run", fake_run)
    result = FailedServicesTool().execute()

    assert result.ok is True
    assert result.data["failed_services"] == ["demo-web.service"]
    assert calls[0][1]["shell"] is False
    assert "--no-pager" in calls[0][0]


def test_service_logs_uses_bounded_fixed_argument_list(monkeypatch) -> None:
    import linux_admin.tools.logs as logs_module

    monkeypatch.setattr(logs_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(logs_module.shutil, "which", lambda _name: "/usr/bin/journalctl")
    captured: dict[str, Any] = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout="line one\nline two\n", stderr="")

    monkeypatch.setattr(logs_module.subprocess, "run", fake_run)
    result = ServiceLogsTool().execute(service_name="demo-web.service", lines=2, since_minutes=30)

    assert result.ok is True
    assert result.data["line_count"] == 2
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["timeout"] > 0
    assert "--unit" in captured["command"]
    assert "demo-web.service" in captured["command"]


def test_service_logs_normalizes_no_entries(monkeypatch) -> None:
    import linux_admin.tools.logs as logs_module

    monkeypatch.setattr(logs_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        logs_module.shutil,
        "which",
        lambda _name: "/usr/bin/journalctl",
    )
    monkeypatch.setattr(
        logs_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="-- No entries --\n",
            stderr="",
        ),
    )

    result = ServiceLogsTool().execute(service_name="demo-web.service")

    assert result.ok is True
    assert result.data["lines"] == []
    assert result.data["line_count"] == 0
    assert "Read 0 journal entries" in result.evidence[0]


def test_service_logs_rejects_invalid_unit_name_before_command(monkeypatch) -> None:
    import linux_admin.tools.logs as logs_module

    called = False

    def fake_run(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("command must not run for invalid service names")

    monkeypatch.setattr(logs_module.subprocess, "run", fake_run)
    result = ServiceLogsTool().execute(service_name="; rm -rf /")
    assert result.status == "invalid_input"
    assert called is False


def test_recent_errors_caps_line_limit() -> None:
    result = RecentErrorsTool().execute(lines=1000)
    assert result.status == "invalid_input"



def test_recent_errors_normalizes_no_entries_sentinel(monkeypatch) -> None:
    import linux_admin.tools.logs as logs_module

    monkeypatch.setattr(logs_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        logs_module.shutil,
        "which",
        lambda _name: "/usr/bin/journalctl",
    )
    monkeypatch.setattr(
        logs_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="-- No entries --\n",
            stderr="",
        ),
    )

    result = RecentErrorsTool().execute()

    assert result.ok is True
    assert result.data["errors"] == []
    assert result.data["count"] == 0
    assert result.evidence == ["Read 0 recent error-priority journal entries."]


def test_network_state_reads_interfaces() -> None:
    result = NetworkStateTool().execute()
    assert result.ok is True
    assert isinstance(result.data["interfaces"], list)


def test_tcp_connectivity_reports_success_with_mocked_socket(monkeypatch) -> None:
    import linux_admin.tools.network as network_module

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(network_module.socket, "create_connection", lambda *args, **kwargs: FakeConnection())
    result = TcpConnectivityTool().execute(host="127.0.0.1", port=443, timeout_seconds=1)
    assert result.ok is True
    assert result.data["reachable"] is True


def test_tcp_connectivity_rejects_cloud_metadata_target() -> None:
    result = TcpConnectivityTool().execute(host="169.254.169.254", port=80)
    assert result.status == "invalid_input"


def test_http_endpoint_rejects_unsafe_url_without_network() -> None:
    tool = HttpEndpointTool()
    assert tool.execute(url="file:///etc/passwd").status == "invalid_input"
    assert tool.execute(url="http://user:password@example.com/").status == "invalid_input"


def test_http_endpoint_reports_http_5xx_as_reachable_but_unhealthy(monkeypatch) -> None:
    import linux_admin.tools.network as network_module

    class FakeResponse:
        status = 503
        reason = "Service Unavailable"

        def read(self, _limit: int) -> bytes:
            return b"service unavailable"

    class FakeConnection:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, *args, **kwargs):
            return None

        def getresponse(self):
            return FakeResponse()

        def close(self):
            return None

    monkeypatch.setattr(network_module.http.client, "HTTPConnection", FakeConnection)
    result = HttpEndpointTool().execute(url="http://127.0.0.1:8080/health")
    assert result.ok is True
    assert result.data["reachable"] is True
    assert result.data["healthy"] is False
    assert result.data["status_code"] == 503


def test_service_status_parses_systemctl_show(monkeypatch, app_config) -> None:
    import linux_admin.tools.services as services_module

    monkeypatch.setattr(services_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(services_module.shutil, "which", lambda _name: "/usr/bin/systemctl")
    captured: dict[str, Any] = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return SimpleNamespace(
            returncode=0,
            stdout=(
                "LoadState=loaded\n"
                "ActiveState=active\n"
                "SubState=running\n"
                "UnitFileState=enabled\n"
                "Type=simple\n"
                "Result=success\n"
                "ExecMainCode=1\n"
                "ExecMainStatus=0\n"
                "RemainAfterExit=no\n"
            ),
            stderr="",
        )

    monkeypatch.setattr(services_module.subprocess, "run", fake_run)
    result = ServiceStatusTool(app_config).execute(service_name="demo-web.service")
    assert result.ok is True
    assert result.data["is_active"] is True
    assert result.data["sub_state"] == "running"
    assert result.data["service_type"] == "simple"
    assert result.data["result"] == "success"
    assert result.data["exec_main_code"] == "1"
    assert result.data["exec_main_status"] == "0"
    assert result.data["remain_after_exit"] == "no"
    assert "--property=Type" in captured["command"]
    assert "--property=Result" in captured["command"]
    assert "--property=ExecMainCode" in captured["command"]
    assert "--property=ExecMainStatus" in captured["command"]
    assert "--property=RemainAfterExit" in captured["command"]
    assert captured["kwargs"]["shell"] is False


def test_restart_tool_stays_disabled_by_default(app_config, monkeypatch) -> None:
    import linux_admin.tools.services as services_module

    monkeypatch.setattr(services_module.subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("must not restart service")))
    result = RestartServiceTool(app_config).execute(service_name="demo-web.service")
    assert result.status == "denied"


def test_security_posture_does_not_disclose_api_key(app_config) -> None:
    result = InspectSecurityPostureTool(app_config).execute()
    assert result.ok is True
    assert result.data["overall"] in {"pass", "warning", "fail"}
    rendered = repr(result.data)
    assert app_config.llm.api_key not in rendered if app_config.llm.api_key else True


def test_verify_service_health_uses_real_status_adapter(monkeypatch, app_config) -> None:
    import linux_admin.verification as verification_module

    monkeypatch.setattr(
        verification_module,
        "query_service_status",
        lambda service_name, timeout_seconds: ToolResult(
            tool_name="get_service_status",
            status="success",
            data={"service_name": service_name, "active_state": "active", "is_active": True},
        ),
    )
    result = VerifyServiceHealthTool(app_config).execute(service_name="demo-web.service")
    assert result.ok is True
    assert result.data["healthy"] is True
    assert result.data["verification"] == "service_active_state"


def test_verify_endpoint_maps_http_result(monkeypatch) -> None:
    import linux_admin.verification as verification_module

    monkeypatch.setattr(
        verification_module,
        "perform_http_check",
        lambda url, timeout_seconds: ToolResult(
            tool_name="check_http_endpoint",
            status="success",
            data={"url": url, "reachable": True, "healthy": True, "status_code": 200},
        ),
    )
    result = VerifyEndpointTool().execute(url="http://127.0.0.1/health")
    assert result.ok is True
    assert result.data["verification"] == "http_endpoint"
    assert result.data["healthy"] is True


def test_recovery_manager_retries_only_health_check_and_is_bounded() -> None:
    responses = iter(
        [
            ToolResult(tool_name="verify_service_health", status="success", data={"healthy": False}),
            ToolResult(tool_name="verify_service_health", status="success", data={"healthy": True}),
        ]
    )
    calls = 0

    def check() -> ToolResult:
        nonlocal calls
        calls += 1
        return next(responses)

    manager = RecoveryManager(max_attempts=2, interval_seconds=0, sleeper=lambda _seconds: None)
    result = manager.verify_until_healthy(check)

    assert result.ok is True
    assert result.data["verification_attempts"][-1]["healthy"] is True
    assert calls == 2


def test_recovery_manager_stops_without_repeating_action() -> None:
    result = ToolResult(
        tool_name="verify_service_health",
        status="failed",
        error="service still down",
        data={"healthy": False},
    )
    disposition = RecoveryManager.handle_recovery_failure(
        incident_id="incident-1", action_name="restart_service", last_result=result
    )
    assert disposition["status"] == "recovery_failed"
    assert disposition["automatic_follow_up_action"] is False


def test_builtin_registration_contains_all_expected_real_tools(app_config) -> None:
    registry = register_builtin_tools(ToolRegistry(), app_config)
    names = {spec.name for spec in registry.list_tools()}
    assert {
        "get_system_overview",
        "get_disk_usage",
        "list_top_processes",
        "get_failed_services",
        "get_service_logs",
        "get_recent_errors",
        "get_service_status",
        "restart_service",
        "get_network_state",
        "check_tcp_connectivity",
        "check_http_endpoint",
        "inspect_listening_port",
        "inspect_security_posture",
        "verify_service_health",
        "verify_endpoint",
    } <= names
    assert registry.get_spec("restart_service").changes_system is True


def test_listening_port_tool_only_reports_matching_listening_sockets(monkeypatch):
    from types import SimpleNamespace

    import psutil

    import linux_admin.tools.network as network_module
    from linux_admin.tools.network import ListeningPortTool

    sockets = [
        SimpleNamespace(
            status=psutil.CONN_LISTEN,
            laddr=SimpleNamespace(ip="127.0.0.1", port=8080),
            pid=None,
        ),
        SimpleNamespace(
            status=psutil.CONN_LISTEN,
            laddr=SimpleNamespace(ip="0.0.0.0", port=9090),
            pid=None,
        ),
        SimpleNamespace(
            status=psutil.CONN_ESTABLISHED,
            laddr=SimpleNamespace(ip="127.0.0.1", port=8080),
            pid=None,
        ),
    ]
    monkeypatch.setattr(
        network_module.psutil,
        "net_connections",
        lambda kind: sockets,
    )

    result = ListeningPortTool().execute(port=8080)

    assert result.ok
    assert result.data["count"] == 1
    assert result.data["listeners"][0]["local_address"] == "127.0.0.1"
    assert result.data["listeners"][0]["port"] == 8080
# ============================================================
# New system-intelligence tools (Quỳnh — feature/system-intelligence)
# ============================================================


def test_top_processes_sort_by_cpu() -> None:
    result = TopProcessesTool().execute(limit=3, sort_by="cpu")
    assert result.ok is True
    assert "processes" in result.data
    assert result.data["sort_by"] == "cpu_percent"
    assert len(result.data["processes"]) <= 3
    for proc in result.data["processes"]:
        assert "cpu_percent" in proc


def test_top_processes_sort_by_both_returns_two_lists() -> None:
    result = TopProcessesTool().execute(limit=3, sort_by="both")
    assert result.ok is True
    assert "top_cpu" in result.data
    assert "top_memory" in result.data
    assert len(result.data["top_cpu"]) <= 3
    assert len(result.data["top_memory"]) <= 3


def test_top_processes_rejects_invalid_sort_by() -> None:
    result = TopProcessesTool().execute(sort_by="threads")
    assert result.status == "invalid_input"


def test_list_all_mounts_returns_mounts() -> None:
    result = ListAllMountsTool().execute()
    assert result.ok is True
    assert isinstance(result.data["mounts"], list)
    assert result.data["mount_count"] == len(result.data["mounts"])
    for mount in result.data["mounts"]:
        assert "device" in mount
        assert "mount_point" in mount
        assert "fstype" in mount


def test_io_stats_rejects_invalid_sample_seconds() -> None:
    tool = IoStatsTool()
    assert tool.execute(sample_seconds=0).status == "invalid_input"
    assert tool.execute(sample_seconds=10).status == "invalid_input"
    assert tool.execute(sample_seconds="1").status == "invalid_input"


def test_io_stats_returns_disk_and_iowait_or_reports_unsupported() -> None:
    result = IoStatsTool().execute(sample_seconds=0.1)
    if result.ok:
        assert "disk_stats" in result.data
        assert "io_wait_percent" in result.data
        assert isinstance(result.data["disk_stats"], list)
    else:
        # Some container/CI environments lack disk counters.
        assert result.data.get("supported") is False


def test_list_listening_ports_filters_to_listen_only(monkeypatch) -> None:
    import psutil

    import linux_admin.tools.network as network_module

    sockets = [
        SimpleNamespace(
            status=psutil.CONN_LISTEN,
            laddr=SimpleNamespace(ip="127.0.0.1", port=22),
            pid=1,
        ),
        SimpleNamespace(
            status=psutil.CONN_LISTEN,
            laddr=SimpleNamespace(ip="0.0.0.0", port=80),
            pid=2,
        ),
        SimpleNamespace(
            status=psutil.CONN_ESTABLISHED,
            laddr=SimpleNamespace(ip="127.0.0.1", port=22),
            pid=3,
        ),
    ]
    monkeypatch.setattr(
        network_module.psutil,
        "net_connections",
        lambda kind: sockets,
    )

    result = ListListeningPortsTool().execute()
    assert result.ok is True
    assert result.data["count"] == 2
    ports = {item["local_port"] for item in result.data["sockets"]}
    assert ports == {22, 80}


def test_kernel_log_parses_messages(monkeypatch) -> None:
    import linux_admin.tools.logs as logs_module

    monkeypatch.setattr(logs_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(logs_module.shutil, "which", lambda _name: "/usr/bin/journalctl")
    monkeypatch.setattr(
        logs_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=(
                "2026-11-18T09:00:00 host kernel: Out of memory: Killed process 1234 (python3)\n"
                "2026-11-18T09:01:00 host kernel: EXT4-fs error (device sda1)\n"
            ),
            stderr="",
        ),
    )
    result = KernelLogTool().execute(lines=50)
    assert result.ok is True
    assert result.data["line_count"] == 2
    assert result.data["priority"] == "err"
    assert any("Out of memory" in msg for msg in result.data["messages"])


def test_kernel_log_handles_no_entries(monkeypatch) -> None:
    import linux_admin.tools.logs as logs_module

    monkeypatch.setattr(logs_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(logs_module.shutil, "which", lambda _name: "/usr/bin/journalctl")
    monkeypatch.setattr(
        logs_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout="-- No entries --\n", stderr=""
        ),
    )
    result = KernelLogTool().execute()
    assert result.ok is True
    assert result.data["messages"] == []
    assert result.data["line_count"] == 0


def test_kernel_log_rejects_invalid_priority() -> None:
    assert KernelLogTool().execute(priority="fatal").status == "invalid_input"
    assert KernelLogTool().execute(lines=0).status == "invalid_input"


def test_auth_log_detects_brute_force(monkeypatch) -> None:
    import linux_admin.tools.logs as logs_module

    monkeypatch.setattr(logs_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(logs_module.shutil, "which", lambda _name: "/usr/bin/journalctl")
    lines = "\n".join(
        f"2026-11-18T09:00:{i:02d} host sshd[1]: Failed password for root "
        f"from 1.2.3.4 port {10000 + i} ssh2"
        for i in range(15)
    )
    monkeypatch.setattr(
        logs_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=lines, stderr=""),
    )
    result = AuthLogTool().execute(lines=100, since_minutes=60)
    assert result.ok is True
    assert result.data["failed_login_count"] == 15
    assert result.data["brute_force_suspected"] is True
    assert result.data["top_source_ips"][0]["ip"] == "1.2.3.4"
    assert result.data["top_source_ips"][0]["failure_count"] == 15


def test_auth_log_no_brute_force_below_threshold(monkeypatch) -> None:
    import linux_admin.tools.logs as logs_module

    monkeypatch.setattr(logs_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(logs_module.shutil, "which", lambda _name: "/usr/bin/journalctl")
    lines = "\n".join(
        f"2026-11-18T09:00:{i:02d} host sshd[1]: Failed password for bob "
        f"from 5.6.7.8 port {10000 + i} ssh2"
        for i in range(5)
    )
    monkeypatch.setattr(
        logs_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=lines, stderr=""),
    )
    result = AuthLogTool().execute()
    assert result.ok is True
    assert result.data["failed_login_count"] == 5
    assert result.data["brute_force_suspected"] is False


def test_auth_log_counts_successful_logins(monkeypatch) -> None:
    import linux_admin.tools.logs as logs_module

    monkeypatch.setattr(logs_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(logs_module.shutil, "which", lambda _name: "/usr/bin/journalctl")
    monkeypatch.setattr(
        logs_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=(
                "2026-11-18T09:00:00 host sshd[1]: Accepted publickey for alice "
                "from 1.2.3.4 port 22 ssh2\n"
            ),
            stderr="",
        ),
    )
    result = AuthLogTool().execute()
    assert result.ok is True
    assert result.data["successful_login_count"] == 1
    assert result.data["failed_login_count"] == 0


def test_auth_log_rejects_invalid_inputs() -> None:
    assert AuthLogTool().execute(lines=0).status == "invalid_input"
    assert AuthLogTool().execute(since_minutes=0).status == "invalid_input"
    assert AuthLogTool().execute(brute_force_threshold=0).status == "invalid_input"


def test_new_read_only_tools_are_registered(app_config) -> None:
    registry = register_builtin_tools(ToolRegistry(), app_config)
    names = {spec.name for spec in registry.list_tools()}
    expected_new = {
        "list_all_mounts",
        "get_io_stats",
        "list_listening_ports",
        "get_kernel_log",
        "check_auth_log",
    }
    assert expected_new <= names
    for tool_name in expected_new:
        spec = registry.get_spec(tool_name)
        assert spec is not None
        assert spec.changes_system is False
        assert spec.risk_level == "read_only"


# COMPLETION-FIX-01 U-01 — bounded per-process I/O observations (offline).
def _u01_fake_io(monkeypatch, snapshots, *, device_reset=False):
    from collections import namedtuple

    import psutil

    import linux_admin.tools.system as system_module

    Disk = namedtuple("Disk", "read_count write_count read_bytes write_bytes busy_time")
    Cpu = namedtuple("Cpu", "user system iowait")
    disk_calls = iter([
        {"sda": Disk(10, 10, 100, 200, 100)},
        {"sda": Disk(9 if device_reset else 20, 20, 300, 600, 150)},
    ])
    cpu_calls = iter([Cpu(100, 100, 5), Cpu(110, 115, 6)])
    process_calls = iter(snapshots)

    class FakeProcess:
        def __init__(self, item):
            self.info = {key: item.get(key) for key in ("pid", "name", "username", "create_time")}
            self._item = item

        def io_counters(self):
            if self._item.get("denied"):
                raise psutil.AccessDenied(pid=self.info["pid"])
            if self._item.get("unsupported"):
                raise NotImplementedError("process IO unsupported")
            if self._item.get("missing"):
                return SimpleNamespace(read_bytes=None, write_bytes=None)
            return SimpleNamespace(
                read_bytes=self._item["read_bytes"],
                write_bytes=self._item["write_bytes"],
            )

    monkeypatch.setattr(system_module.psutil, "disk_io_counters", lambda perdisk: next(disk_calls))
    monkeypatch.setattr(system_module.psutil, "cpu_times", lambda: next(cpu_calls))
    monkeypatch.setattr(system_module.psutil, "process_iter", lambda attrs: [FakeProcess(p) for p in next(process_calls)])
    monkeypatch.setattr(system_module.time, "sleep", lambda seconds: None)


def test_u01_process_io_normal_bounded_and_device_preserved(monkeypatch):
    before = [
        {"pid": 101, "name": "reader", "username": "dev", "create_time": 50.0,
         "read_bytes": 100, "write_bytes": 20},
        {"pid": 202, "name": "writer", "username": "dev", "create_time": 51.0,
         "read_bytes": 10, "write_bytes": 100},
    ]
    after = [
        dict(before[0], read_bytes=300, write_bytes=40),
        dict(before[1], read_bytes=30, write_bytes=500),
    ]
    _u01_fake_io(monkeypatch, [before, after])
    result = IoStatsTool().execute(sample_seconds=1.0)
    assert result.ok
    assert result.data["device_count"] == 1
    assert result.data["disk_stats"][0]["read_iops"] == 10.0
    assert result.data["io_wait_percent"] == 3.85
    assert result.data["process_io_supported"] is True
    assert result.data["process_io_sampled_count"] == 2
    assert [p["pid"] for p in result.data["process_io_stats"]] == [202, 101]
    assert result.data["process_io_stats"][0]["write_bytes_delta"] == 400
    assert result.data["process_io_stats"][1]["read_bytes_per_sec"] == 200.0


def test_u01_missing_or_permission_limited_is_not_fabricated(monkeypatch):
    before = [
        {"pid": 101, "create_time": 50.0, "name": "private", "denied": True},
        {"pid": 202, "create_time": 50.0, "name": "unknown", "missing": True},
        {"pid": 303, "create_time": 50.0, "name": "unsupported", "unsupported": True},
    ]
    _u01_fake_io(monkeypatch, [before, before])
    result = IoStatsTool().execute(sample_seconds=0.1)
    assert result.ok
    assert result.data["process_io_stats"] == []
    assert result.data["process_io_supported"] is False
    assert result.data["process_io_inaccessible_count"] >= 6
    assert result.data["device_count"] == 1


def test_u01_terminated_and_reused_pids_are_excluded(monkeypatch):
    before = [
        {"pid": 101, "name": "old", "create_time": 50.0,
         "read_bytes": 100, "write_bytes": 200},
        {"pid": 102, "name": "gone", "create_time": 40.0,
         "read_bytes": 100, "write_bytes": 200},
    ]
    after = [{"pid": 101, "name": "new", "create_time": 51.0,
              "read_bytes": 900, "write_bytes": 900}]
    _u01_fake_io(monkeypatch, [before, after])
    result = IoStatsTool().execute(sample_seconds=0.1)
    assert result.ok
    assert result.data["process_io_sampled_count"] == 0
    assert result.data["process_io_stats"] == []


def test_u01_process_io_scan_and_report_are_bounded(monkeypatch):
    before = [
        {"pid": pid, "name": f"process-{pid}", "create_time": float(pid),
         "read_bytes": 0, "write_bytes": 0}
        for pid in range(1, 301)
    ]
    after = [dict(item, read_bytes=item["pid"] * 100) for item in before]
    _u01_fake_io(monkeypatch, [before, after])
    result = IoStatsTool().execute(sample_seconds=0.1)
    assert result.ok
    assert result.data["process_io_scan_limit"] == 256
    assert result.data["process_io_sampled_count"] == 256
    assert len(result.data["process_io_stats"]) == 10
    assert result.data["process_io_stats"][0]["pid"] == 256


def test_u01_process_enumeration_unsupported_keeps_device_observations(monkeypatch):
    import linux_admin.tools.system as system_module

    _u01_fake_io(monkeypatch, [[], []])
    def unsupported_process_iter(attrs):
        raise NotImplementedError("unsupported")
    monkeypatch.setattr(system_module.psutil, "process_iter", unsupported_process_iter)
    result = IoStatsTool().execute(sample_seconds=0.1)
    assert result.ok
    assert result.data["device_count"] == 1
    assert result.data["process_io_supported"] is False
    assert result.data["process_io_stats"] == []


def test_u01_negative_counter_delta_is_not_reported(monkeypatch):
    before = [{"pid": 101, "name": "reset", "create_time": 50.0,
               "read_bytes": 500, "write_bytes": 200}]
    after = [dict(before[0], read_bytes=100, write_bytes=300)]
    _u01_fake_io(monkeypatch, [before, after], device_reset=True)
    result = IoStatsTool().execute(sample_seconds=0.1)
    assert result.ok
    assert result.data["process_io_counter_reset_count"] == 1
    assert result.data["process_io_stats"] == []
    assert result.data["device_count"] == 0
    assert result.data["io_wait_percent"] is not None
