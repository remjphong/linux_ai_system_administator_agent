"""Read-only posture checks over runtime privileges and loaded policy."""

from __future__ import annotations

import ctypes
import os
from typing import Any

from linux_admin.config import AppConfig
from linux_admin.contracts import ToolResult, ToolSpec
from linux_admin.tools.logs import AuthLogTool
from linux_admin.tools.security_updates import SecurityUpdatesTool


def _is_elevated() -> bool | None:
    if os.name == "posix" and hasattr(os, "geteuid"):
        return os.geteuid() == 0
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            return None
    return None


class InspectSecurityPostureTool:
    spec = ToolSpec(
        name="inspect_security_posture",
        description="Review high-level runtime privilege and safety configuration without changing the system.",
    )

    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def execute(self, **kwargs: Any) -> ToolResult:
        del kwargs
        checks: list[dict[str, str]] = []

        def add(name: str, status: str, detail: str) -> None:
            checks.append({"name": name, "status": status, "detail": detail})

        if self.config.policy.default_decision == "deny":
            add("policy_default", "pass", "Unconfigured actions are denied by default.")
        else:
            add("policy_default", "fail", "Policy is not configured to deny by default.")

        if not self.config.policy.allow_privilege_escalation:
            add("privilege_escalation", "pass", "Application-level privilege escalation is disabled.")
        else:
            add("privilege_escalation", "warning", "Configuration permits privilege escalation; no automatic elevation is implemented by this tool.")

        elevated = _is_elevated()
        if elevated is False:
            add("runtime_privilege", "pass", "Process does not appear to be running with elevated/root privileges.")
        elif elevated is True:
            add("runtime_privilege", "warning", "Process is running elevated/root; least-privilege operation is recommended.")
        else:
            add("runtime_privilege", "unknown", "Could not determine whether the process is elevated.")

        restart_rule = self.config.policy.actions.get("restart_service")
        if not self.config.services.restart_enabled:
            add("service_restart", "pass", "Service restart is disabled by configuration.")
        elif (
            restart_rule is not None
            and restart_rule.allowed
            and restart_rule.requires_approval
            and self.config.services.allowlist
        ):
            add("service_restart", "warning", "Restart is enabled for an allowlisted service and must remain approval-gated.")
        else:
            add("service_restart", "fail", "Restart enablement is inconsistent with policy/allowlist expectations.")

        if self.config.agent.dry_run:
            add("dry_run", "pass", "Dry-run is enabled; state-changing execution must not occur.")
        else:
            add("dry_run", "warning", "Dry-run is disabled; verify policy, approval, and executor boundaries before enabling actions.")

        if self.config.llm.enabled:
            add("llm_boundary", "warning", "LLM is enabled; model output must remain untrusted and tool access constrained.")
        else:
            add("llm_boundary", "pass", "LLM integration is disabled; rule-based operation remains available.")

        auth = AuthLogTool().execute(lines=1, since_minutes=1)
        if auth.ok:
            add("ssh_journal", "pass", "Journal đọc được trong tiến trình hiện tại.")
        else:
            add("ssh_journal", "unknown", auth.error or "Không đọc được log SSH.")

        statuses = [item["status"] for item in checks]
        overall = "fail" if "fail" in statuses else "warning" if "warning" in statuses or "unknown" in statuses else "pass"
        return ToolResult(
            tool_name=self.spec.name,
            status="success",
            data={"overall": overall, "checks": checks, "check_count": len(checks)},
            evidence=[f"Completed {len(checks)} read-only posture checks; no configuration was changed."],
        )


def build_tools(config: AppConfig) -> list[object]:
    return [InspectSecurityPostureTool(config), SecurityUpdatesTool(config.project_root)]
