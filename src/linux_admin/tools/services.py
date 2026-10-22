"""Service tool — status + restart an toàn (KHÔNG shell=True).

BETA:
- get_service_status: chỉ đọc, luôn cho phép.
- restart_service: gọi systemctl với list tham số cố định,
  timeout rõ ràng, không ghép chuỗi shell.
  Việc cho phép hay không do PolicyEngine + Executor quyết định.
"""
from __future__ import annotations

import logging
import subprocess

from linux_admin.core.contracts import ToolResult

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30


class GetServiceStatusTool:
    """Đọc trạng thái service bằng systemctl is-active (read-only)."""

    name = "get_service_status"

    def execute(
        self,
        service_name: str,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> ToolResult:
        if not service_name:
            return ToolResult(
                success=False,
                tool_name=self.name,
                error="service_name rỗng",
            )

        try:
            proc = subprocess.run(
                ["systemctl", "is-active", service_name],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return ToolResult(
                success=True,
                tool_name=self.name,
                data={
                    "service": service_name,
                    "state": proc.stdout.strip(),
                    "returncode": proc.returncode,
                },
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                success=False,
                tool_name=self.name,
                error="systemctl is-active timeout",
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return ToolResult(
                success=False,
                tool_name=self.name,
                error=str(exc),
            )


class RestartServiceTool:
    """Restart service trong allowlist. Policy + approval quyết định có gọi hay không."""

    name = "restart_service"

    def execute(
        self,
        service_name: str,
        is_dry_run: bool = True,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> ToolResult:
        if not service_name:
            return ToolResult(
                success=False,
                tool_name=self.name,
                error="service_name rỗng",
            )

        if is_dry_run:
            return ToolResult(
                success=True,
                tool_name=self.name,
                data={
                    "service": service_name,
                    "dry_run": True,
                    "message": "Dry-run: không thực thi",
                },
            )

        try:
            proc = subprocess.run(
                ["systemctl", "restart", service_name],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            if proc.returncode == 0:
                return ToolResult(
                    success=True,
                    tool_name=self.name,
                    data={"service": service_name, "returncode": 0},
                )
            return ToolResult(
                success=False,
                tool_name=self.name,
                error=proc.stderr.strip() or f"systemctl restart failed (rc={proc.returncode})",
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                success=False,
                tool_name=self.name,
                error="systemctl restart timeout",
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return ToolResult(
                success=False,
                tool_name=self.name,
                error=str(exc),
            )
