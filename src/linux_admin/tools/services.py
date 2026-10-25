"""Service tools: Trạng thái và restart service có kiểm soát."""
from __future__ import annotations

import logging
import subprocess

from linux_admin.contracts import ToolResult

logger = logging.getLogger(__name__)

def get_service_status(service_name: str, timeout: int = 10) -> ToolResult:
    """Đọc trạng thái service (Read-only)."""
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", service_name],
            capture_output=True, text=True, timeout=timeout, check=False
        )
        return ToolResult(
            tool_name="get_service_status",
            status="success",
            data={"service": service_name, "state": proc.stdout.strip()}
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return ToolResult(
            tool_name="get_service_status",
            status="failed",
            error=str(exc)
        )

def restart_service(service_name: str, is_dry_run: bool = True, timeout: int = 30) -> ToolResult:
    """Restart service (Changes system)."""
    if not service_name:
        return ToolResult(tool_name="restart_service", status="invalid_input", error="service_name rỗng")
        
    if is_dry_run:
        return ToolResult(
            tool_name="restart_service",
            status="success",
            data={"message": f"Dry-run: Sẽ restart {service_name}"}
        )
    
    try:
        proc = subprocess.run(
            ["systemctl", "restart", service_name],
            capture_output=True, text=True, timeout=timeout, check=False
        )
        if proc.returncode == 0:
            return ToolResult(
                tool_name="restart_service",
                status="success",
                data={"service": service_name}
            )
        return ToolResult(
            tool_name="restart_service",
            status="failed",
            error=proc.stderr.strip() or "systemctl restart failed"
        )
    except subprocess.TimeoutExpired:
        return ToolResult(tool_name="restart_service", status="timeout", error="systemctl restart timeout")
    except (OSError, subprocess.SubprocessError) as exc:
        return ToolResult(tool_name="restart_service", status="failed", error=str(exc))
