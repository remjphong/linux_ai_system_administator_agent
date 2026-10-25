"""Controlled systemd service inspection and restart adapter.

Service restart is disabled by default in config/services.yaml. Even when enabled,
the tool is marked state-changing, the Registry blocks normal invocation, and the
Control layer must verify policy and a matching approval before the authorized path
can reach this adapter. This module never invokes sudo or a shell.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
from typing import Any

from linux_admin.config import AppConfig
from linux_admin.contracts import ToolResult, ToolSpec
from linux_admin.tools.logs import validate_service_name


def query_service_status(service_name: str, timeout_seconds: float = 8.0) -> ToolResult:
    tool_name = "get_service_status"
    invalid = validate_service_name(service_name)
    if invalid:
        return ToolResult(tool_name=tool_name, status="invalid_input", error=invalid)
    if platform.system() != "Linux":
        return ToolResult(tool_name=tool_name, status="failed", error="Service inspection requires Linux with systemd.", data={"supported": False, "platform": platform.system()})
    executable = shutil.which("systemctl")
    if executable is None:
        return ToolResult(tool_name=tool_name, status="failed", error="systemctl is not installed or not on PATH.")
    try:
        completed = subprocess.run(
            [
                executable,
                "show",
                "--no-pager",
                "--property=LoadState",
                "--property=ActiveState",
                "--property=SubState",
                "--property=UnitFileState",
                "--property=Type",
                "--property=Result",
                "--property=ExecMainCode",
                "--property=ExecMainStatus",
                "--property=RemainAfterExit",
                service_name,
            ],
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(0.1, min(float(timeout_seconds), 15.0)),
        )
    except subprocess.TimeoutExpired:
        return ToolResult(tool_name=tool_name, status="timeout", error="systemctl status query timed out.")
    except OSError as exc:
        return ToolResult(tool_name=tool_name, status="failed", error=f"Could not execute systemctl ({type(exc).__name__}).")
    if completed.returncode != 0:
        return ToolResult(tool_name=tool_name, status="failed", error=f"systemctl exited with code {completed.returncode}.")
    values: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip()] = value.strip()
    active_state = values.get("ActiveState", "unknown")
    load_state = values.get("LoadState", "unknown")
    return ToolResult(
        tool_name=tool_name,
        status="success",
        data={
            "service_name": service_name,
            "load_state": load_state,
            "active_state": active_state,
            "sub_state": values.get("SubState", "unknown"),
            "unit_file_state": values.get("UnitFileState", "unknown"),
            "service_type": values.get("Type", "unknown"),
            "result": values.get("Result", "unknown"),
            "exec_main_code": values.get("ExecMainCode", "unknown"),
            "exec_main_status": values.get("ExecMainStatus", "unknown"),
            "remain_after_exit": values.get("RemainAfterExit", "unknown"),
            "is_active": active_state == "active",
            "loaded": load_state == "loaded",
        },
        evidence=[f"Read systemd state for {service_name}; no service state was changed."],
    )


class ServiceStatusTool:
    spec = ToolSpec(
        name="get_service_status",
        description="Read the state of one systemd service unit.",
        parameters={
            "type": "object",
            "properties": {"service_name": {"type": "string", "minLength": 1, "maxLength": 255}},
            "required": ["service_name"],
            "additionalProperties": False,
        },
    )

    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def execute(self, service_name: str, **kwargs: Any) -> ToolResult:
        del kwargs
        return query_service_status(service_name, self.config.agent.tool_timeout_seconds)


class RestartServiceTool:
    spec = ToolSpec(
        name="restart_service",
        description="Restart one configured service after policy and explicit approval.",
        parameters={
            "type": "object",
            "properties": {"service_name": {"type": "string", "minLength": 1, "maxLength": 255}},
            "required": ["service_name"],
            "additionalProperties": False,
        },
        risk_level="high",
        changes_system=True,
        requires_approval=True,
    )

    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def execute(self, service_name: str, **kwargs: Any) -> ToolResult:
        del kwargs
        invalid = validate_service_name(service_name)
        if invalid:
            return ToolResult(tool_name=self.spec.name, status="invalid_input", error=invalid)
        if not self.config.services.restart_enabled:
            return ToolResult(tool_name=self.spec.name, status="denied", error="Service restart is disabled by configuration.")
        if self.config.agent.mode != "assisted":
            return ToolResult(tool_name=self.spec.name, status="denied", error="Service restart requires agent.mode=assisted.", data={"executed": False})
        if self.config.agent.dry_run:
            return ToolResult(tool_name=self.spec.name, status="denied", error="Service restart is blocked while dry_run is enabled.", data={"executed": False, "dry_run": True})
        policy = self.config.policy.actions.get("restart_service")
        if policy is None or not policy.allowed:
            return ToolResult(tool_name=self.spec.name, status="denied", error="Policy does not permit restart_service.")
        if service_name not in self.config.services.allowlist:
            return ToolResult(tool_name=self.spec.name, status="denied", error="Service is not in the configured allowlist.")
        if platform.system() != "Linux":
            return ToolResult(tool_name=self.spec.name, status="failed", error="Service restart requires Linux with systemd.")
        executable = shutil.which("systemctl")
        if executable is None:
            return ToolResult(tool_name=self.spec.name, status="failed", error="systemctl is not installed or not on PATH.")
        try:
            completed = subprocess.run(
                [executable, "restart", service_name],
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=max(0.1, min(float(self.config.agent.tool_timeout_seconds), 30.0)),
            )
        except subprocess.TimeoutExpired:
            return ToolResult(tool_name=self.spec.name, status="timeout", error="systemctl restart timed out; service state must be checked before retrying.", data={"service_name": service_name, "executed": True})
        except OSError as exc:
            return ToolResult(tool_name=self.spec.name, status="failed", error=f"Could not execute systemctl ({type(exc).__name__}).")
        if completed.returncode != 0:
            return ToolResult(tool_name=self.spec.name, status="failed", error=f"systemctl restart exited with code {completed.returncode}; verify service state before retrying.", data={"service_name": service_name, "executed": True})
        return ToolResult(
            tool_name=self.spec.name,
            status="success",
            data={"service_name": service_name, "command_accepted": True, "executed": True, "verified": False},
            evidence=["systemctl accepted the restart request; health verification is still required."],
        )


def build_tools(config: AppConfig) -> list[object]:
    return [ServiceStatusTool(config), RestartServiceTool(config)]
