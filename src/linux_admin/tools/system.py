"""Read-only system observation tools implemented with psutil.

These tools run on Windows and Linux. They only read operating-system metrics;
they do not modify services, files, permissions, or network configuration.
"""

from __future__ import annotations

import os
import platform
import time
from pathlib import Path
from typing import Any

import psutil

from linux_admin.contracts import ToolResult, ToolSpec


class SystemOverviewTool:
    spec = ToolSpec(
        name="get_system_overview",
        description="Collect CPU, memory, platform, uptime, and process-count metrics.",
    )

    def execute(self, **kwargs: Any) -> ToolResult:
        del kwargs
        try:
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            boot_time = psutil.boot_time()
            data = {
                "platform": platform.system(),
                "platform_release": platform.release(),
                "machine": platform.machine(),
                "cpu_count_logical": psutil.cpu_count(logical=True),
                "cpu_count_physical": psutil.cpu_count(logical=False),
                "cpu_percent": float(psutil.cpu_percent(interval=0.15)),
                "memory_total_bytes": int(memory.total),
                "memory_available_bytes": int(memory.available),
                "memory_used_bytes": int(memory.used),
                "memory_percent": float(memory.percent),
                "swap_total_bytes": int(swap.total),
                "swap_used_bytes": int(swap.used),
                "swap_percent": float(swap.percent),
                "uptime_seconds": max(0, int(time.time() - boot_time)),
                "process_count": len(psutil.pids()),
            }
        except (OSError, psutil.Error) as exc:
            return ToolResult(
                tool_name=self.spec.name,
                status="failed",
                error=f"Could not collect system metrics ({type(exc).__name__}).",
            )

        return ToolResult(
            tool_name=self.spec.name,
            status="success",
            data=data,
            evidence=[
                "Metrics were read from psutil and the operating-system APIs."
            ],
        )


class DiskUsageTool:
    spec = ToolSpec(
        name="get_disk_usage",
        description="Read capacity and usage for an existing filesystem path.",
        parameters={
            "type": "object",
            "properties": {"path": {"type": "string", "minLength": 1, "maxLength": 4096}},
            "required": ["path"],
            "additionalProperties": False,
        },
    )

    def execute(self, path: str = "/", **kwargs: Any) -> ToolResult:
        del kwargs
        if not isinstance(path, str) or not path.strip() or "\x00" in path:
            return ToolResult(
                tool_name=self.spec.name,
                status="invalid_input",
                error="path must be a non-empty filesystem path.",
            )
        if len(path) > 4096:
            return ToolResult(
                tool_name=self.spec.name,
                status="invalid_input",
                error="path exceeds the maximum supported length.",
            )

        # On Windows, '/' is not a meaningful POSIX mountpoint; use the current
        # drive root while keeping the same default argument across platforms.
        effective_path = path
        if os.name == "nt" and path in {"/", "\\"}:
            effective_path = Path.cwd().anchor or str(Path.home())

        try:
            if not os.path.exists(effective_path):
                return ToolResult(
                    tool_name=self.spec.name,
                    status="invalid_input",
                    error="The requested path does not exist.",
                )
            usage = psutil.disk_usage(effective_path)
        except (OSError, ValueError, psutil.Error) as exc:
            return ToolResult(
                tool_name=self.spec.name,
                status="failed",
                error=f"Could not read disk usage ({type(exc).__name__}).",
            )

        data = {
            "path": os.path.abspath(effective_path),
            "total_bytes": int(usage.total),
            "used_bytes": int(usage.used),
            "free_bytes": int(usage.free),
            "used_percent": float(usage.percent),
        }
        return ToolResult(
            tool_name=self.spec.name,
            status="success",
            data=data,
            evidence=[
                f"Filesystem usage read for {data['path']}; no files were modified."
            ],
        )


class TopProcessesTool:
    spec = ToolSpec(
        name="list_top_processes",
        description="List processes sorted by resident-memory use.",
        parameters={
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 50}
            },
            "required": [],
            "additionalProperties": False,
        },
    )

    def execute(self, limit: int = 5, **kwargs: Any) -> ToolResult:
        del kwargs
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 50:
            return ToolResult(
                tool_name=self.spec.name,
                status="invalid_input",
                error="limit must be an integer between 1 and 50.",
            )

        processes: list[dict[str, Any]] = []
        try:
            for process in psutil.process_iter(
                attrs=["pid", "name", "username", "status", "memory_info"]
            ):
                try:
                    info = process.info
                    memory_info = info.get("memory_info")
                    rss = int(memory_info.rss) if memory_info is not None else 0
                    memory_percent = float(process.memory_percent())
                    processes.append(
                        {
                            "pid": int(info.get("pid") or 0),
                            "name": str(info.get("name") or "unknown")[:256],
                            "username": str(info.get("username") or "unknown")[:128],
                            "status": str(info.get("status") or "unknown"),
                            "rss_bytes": rss,
                            "memory_percent": memory_percent,
                        }
                    )
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    # Processes can exit or become inaccessible while being sampled.
                    continue
        except (OSError, psutil.Error) as exc:
            return ToolResult(
                tool_name=self.spec.name,
                status="failed",
                error=f"Could not enumerate processes ({type(exc).__name__}).",
            )

        processes.sort(key=lambda item: item["rss_bytes"], reverse=True)
        selected = processes[:limit]
        return ToolResult(
            tool_name=self.spec.name,
            status="success",
            data={"processes": selected, "limit": limit, "sort_by": "rss_bytes"},
            evidence=[f"Read {len(selected)} process record(s), sorted by resident memory."],
        )


def build_tools() -> list[object]:
    """Return the real, read-only system tools for Registry registration."""
    return [SystemOverviewTool(), DiskUsageTool(), TopProcessesTool()]
