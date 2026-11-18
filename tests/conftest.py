"""Reusable fixtures for cross-platform unit and integration-style tests.

These fixtures use deterministic fake tools. They do not invoke systemctl,
journalctl, the network, an LLM API, or any state-changing system action.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

import pytest

from linux_admin.audit import AuditLogger
from linux_admin.config import AppConfig, load_config
from linux_admin.contracts import ToolResult, ToolSpec
from linux_admin.registry import ToolRegistry


class ConfiguredFakeTool:
    """Test-only tool whose result is controlled by fixture data."""

    def __init__(
        self,
        spec: ToolSpec,
        outputs: Mapping[str, Any],
        failures: Mapping[str, str],
        calls: list[tuple[str, dict[str, Any]]],
    ) -> None:
        self.spec = spec
        self._outputs = outputs
        self._failures = failures
        self._calls = calls

    def execute(self, **kwargs: Any) -> ToolResult:
        args = dict(kwargs)
        self._calls.append((self.spec.name, args))
        if self.spec.name in self._failures:
            return ToolResult(
                tool_name=self.spec.name,
                status="failed",
                error=self._failures[self.spec.name],
                evidence=[f"Fake failure injected for {self.spec.name}"],
            )

        output = self._outputs.get(self.spec.name)
        if callable(output):
            output = output(args)
        if isinstance(output, ToolResult):
            return output
        if output is None:
            output = self._default_output(self.spec.name, args)
        return ToolResult(
            tool_name=self.spec.name,
            status="success",
            data=dict(output),
            evidence=[f"Deterministic test fixture for {self.spec.name}"],
            duration_ms=1,
        )

    @staticmethod
    def _default_output(name: str, args: dict[str, Any]) -> dict[str, Any]:
        if name == "get_system_overview":
            return {
                "platform": "Linux",
                "cpu_percent": 12.5,
                "memory_percent": 48.0,
            }
        if name == "get_disk_usage":
            return {
                "path": args.get("path", "/"),
                "total_bytes": 1000,
                "used_bytes": 910,
                "free_bytes": 90,
                "used_percent": 91.0,
            }
        if name == "list_top_processes":
            return {"processes": [], "limit": args.get("limit", 5)}
        if name == "get_service_status":
            return {
                "service_name": args.get("service_name", "demo-web.service"),
                "active_state": "inactive",
                "is_active": False,
            }
        if name == "get_failed_services":
            return {"failed_services": ["demo-web.service"]}
        if name == "get_service_logs":
            return {
                "service_name": args.get("service_name", "demo-web.service"),
                "lines": ["Example service failed to start"],
            }
        if name == "check_tcp_connectivity":
            return {
                "host": args.get("host", "127.0.0.1"),
                "port": args.get("port", 8080),
                "reachable": False,
            }
        if name == "check_http_endpoint":
            return {
                "url": args.get("url", "http://127.0.0.1:8080/health"),
                "reachable": False,
                "status_code": 503,
            }
        if name == "inspect_listening_port":
            return {
                "port": args["port"],
                "listeners": [],
                "count": 0,
                "supported": True,
            }
        if name == "get_recent_errors":
            return {"errors": []}
        if name == "inspect_security_posture":
            return {"checks": [], "supported_checks": 0}
        return {}


@pytest.fixture

def app_config() -> AppConfig:
    """Return validated configuration from the project config directory."""
    return load_config()


@pytest.fixture

def audit_logger(tmp_path: Any) -> AuditLogger:
    """Use a fresh SQLite database for each test."""
    logger = AuditLogger(tmp_path / "audit.db")
    yield logger
    logger.close()


@pytest.fixture

def registry_factory() -> Callable[..., ToolRegistry]:
    """Build a registry of deterministic fake read-only tools.

    Args accepted by the returned factory:
        outputs: map tool name -> output dict, ToolResult, or callable(args)->dict.
        failures: map tool name -> error string for a simulated failed call.
        calls: optional list populated with (tool_name, arguments) tuples.
    """

    schemas: Sequence[ToolSpec] = (
        ToolSpec(name="get_system_overview", description="Fake system overview"),
        ToolSpec(
            name="get_disk_usage",
            description="Fake filesystem usage",
            parameters={
                "type": "object",
                "properties": {"path": {"type": "string", "minLength": 1}},
                "required": ["path"],
                "additionalProperties": False,
            },
        ),
        ToolSpec(
            name="list_top_processes",
            description="Fake top-process listing",
            parameters={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 50,
                    }
                },
                "required": ["limit"],
                "additionalProperties": False,
            },
        ),
        ToolSpec(
            name="get_service_status",
            description="Fake service status",
            parameters={
                "type": "object",
                "properties": {"service_name": {"type": "string", "minLength": 1}},
                "required": ["service_name"],
                "additionalProperties": False,
            },
        ),
        ToolSpec(name="get_failed_services", description="Fake failed-service list"),
        ToolSpec(
            name="get_service_logs",
            description="Fake service logs",
            parameters={
                "type": "object",
                "properties": {"service_name": {"type": "string", "minLength": 1}},
                "required": ["service_name"],
                "additionalProperties": False,
            },
        ),
        ToolSpec(
            name="check_tcp_connectivity",
            description="Fake TCP connectivity check",
            parameters={
                "type": "object",
                "properties": {
                    "host": {"type": "string", "minLength": 1},
                    "port": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 65535,
                    },
                },
                "required": ["host", "port"],
                "additionalProperties": False,
            },
        ),
        ToolSpec(
            name="check_http_endpoint",
            description="Fake HTTP endpoint check",
            parameters={
                "type": "object",
                "properties": {"url": {"type": "string", "minLength": 8}},
                "required": ["url"],
                "additionalProperties": False,
            },
        ),
        ToolSpec(
            name="inspect_listening_port",
            description="Fake local listening-port inspection",
            parameters={
                "type": "object",
                "properties": {
                    "port": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 65535,
                    },
                },
                "required": ["port"],
                "additionalProperties": False,
            },
        ),
        ToolSpec(
            name="get_recent_errors",
            description="Fake recent errors",
            parameters={
                "type": "object",
                "properties": {
                    "lines": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 200,
                    },
                    "since_minutes": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 1440,
                    },
                },
                "required": [],
                "additionalProperties": False,
            },
        ),
        ToolSpec(name="inspect_security_posture", description="Fake security checks"),
    )

    def build_registry(
        *,
        outputs: Mapping[str, Any] | None = None,
        failures: Mapping[str, str] | None = None,
        calls: list[tuple[str, dict[str, Any]]] | None = None,
    ) -> ToolRegistry:
        output_map = outputs or {}
        failure_map = failures or {}
        call_list = calls if calls is not None else []
        registry = ToolRegistry()
        for spec in schemas:
            registry.register(
                ConfiguredFakeTool(spec, output_map, failure_map, call_list)
            )
        return registry

    return build_registry
