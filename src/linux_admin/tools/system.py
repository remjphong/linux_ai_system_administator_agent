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
        description=(
            "List processes sorted by CPU and/or resident memory usage. "
            "Use sort_by='both' to get top-N by CPU and top-N by RAM in one call."
        ),
        parameters={
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 50},
                "sort_by": {
                    "type": "string",
                    "enum": ["cpu", "memory", "both"],
                },
            },
            "required": [],
            "additionalProperties": False,
        },
    )

    _CPU_SAMPLE_SECONDS = 0.1

    def execute(
        self, limit: int = 5, sort_by: str = "memory", **kwargs: Any
    ) -> ToolResult:
        del kwargs
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 50:
            return ToolResult(
                tool_name=self.spec.name,
                status="invalid_input",
                error="limit must be an integer between 1 and 50.",
            )
        if sort_by not in {"cpu", "memory", "both"}:
            return ToolResult(
                tool_name=self.spec.name,
                status="invalid_input",
                error="sort_by must be 'cpu', 'memory', or 'both'.",
            )

        needs_cpu = sort_by in {"cpu", "both"}
        if needs_cpu:
            # psutil.cpu_percent() returns 0.0 on first call. Prime all
            # processes once, wait a short window, then read real values.
            try:
                for process in psutil.process_iter():
                    try:
                        process.cpu_percent(None)
                    except (
                        psutil.NoSuchProcess,
                        psutil.AccessDenied,
                        psutil.ZombieProcess,
                    ):
                        continue
                time.sleep(self._CPU_SAMPLE_SECONDS)
            except (OSError, psutil.Error):
                # If priming fails we still collect memory data.
                pass

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
                    cpu_percent = 0.0
                    if needs_cpu:
                        try:
                            cpu_percent = float(process.cpu_percent(None))
                        except (
                            psutil.NoSuchProcess,
                            psutil.AccessDenied,
                            psutil.ZombieProcess,
                        ):
                            cpu_percent = 0.0
                    processes.append(
                        {
                            "pid": int(info.get("pid") or 0),
                            "name": str(info.get("name") or "unknown")[:256],
                            "username": str(info.get("username") or "unknown")[:128],
                            "status": str(info.get("status") or "unknown"),
                            "rss_bytes": rss,
                            "memory_percent": memory_percent,
                            "cpu_percent": cpu_percent,
                        }
                    )
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except (OSError, psutil.Error) as exc:
            return ToolResult(
                tool_name=self.spec.name,
                status="failed",
                error=f"Could not enumerate processes ({type(exc).__name__}).",
            )

        by_memory = sorted(processes, key=lambda item: item["rss_bytes"], reverse=True)
        if sort_by == "memory":
            selected = by_memory[:limit]
            return ToolResult(
                tool_name=self.spec.name,
                status="success",
                data={"processes": selected, "limit": limit, "sort_by": "rss_bytes"},
                evidence=[
                    f"Read {len(selected)} process record(s), sorted by resident memory."
                ],
            )

        by_cpu = sorted(
            processes, key=lambda item: item["cpu_percent"], reverse=True
        )
        if sort_by == "cpu":
            selected = by_cpu[:limit]
            return ToolResult(
                tool_name=self.spec.name,
                status="success",
                data={"processes": selected, "limit": limit, "sort_by": "cpu_percent"},
                evidence=[
                    f"Read {len(selected)} process record(s), sorted by CPU percent."
                ],
            )

        top_cpu = by_cpu[:limit]
        top_memory = by_memory[:limit]
        return ToolResult(
            tool_name=self.spec.name,
            status="success",
            data={
                "top_cpu": top_cpu,
                "top_memory": top_memory,
                "limit": limit,
                "sort_by": "both",
            },
            evidence=[
                (f"Read {len(top_cpu)} process(es) by CPU and "
                 f"{len(top_memory)} by resident memory.")
            ],
        )
class ListAllMountsTool:
    """List every mount point (including pseudo filesystems) with usage."""

    spec = ToolSpec(
        name="list_all_mounts",
        description=(
            "List all filesystem mount points with device, type, and capacity/usage. "
            "Uses psutil.disk_partitions(all=True) so pseudo filesystems on Linux "
            "are included; usage is None for filesystems that do not report it."
        ),
    )

    def execute(self, **kwargs: Any) -> ToolResult:
        del kwargs
        try:
            partitions = psutil.disk_partitions(all=True)
        except (OSError, psutil.Error) as exc:
            return ToolResult(
                tool_name=self.spec.name,
                status="failed",
                error=f"Could not enumerate mount points ({type(exc).__name__}).",
            )

        mounts: list[dict[str, Any]] = []
        for partition in partitions:
            entry: dict[str, Any] = {
                "device": partition.device,
                "mount_point": partition.mountpoint,
                "fstype": partition.fstype or "",
            }
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                entry.update(
                    total_bytes=int(usage.total),
                    used_bytes=int(usage.used),
                    free_bytes=int(usage.free),
                    used_percent=float(usage.percent),
                )
            except (OSError, PermissionError, psutil.Error):
                # Pseudo filesystems (proc, sysfs, cgroup) do not report statvfs.
                entry.update(
                    total_bytes=None,
                    used_bytes=None,
                    free_bytes=None,
                    used_percent=None,
                )
            mounts.append(entry)

        return ToolResult(
            tool_name=self.spec.name,
            status="success",
            data={"mount_count": len(mounts), "mounts": mounts},
            evidence=[
                f"Read {len(mounts)} mount point(s); no filesystem was modified."
            ],
        )


class IoStatsTool:
    """Sample disk I/O rates and CPU iowait over a short window."""

    spec = ToolSpec(
        name="get_io_stats",
        description=(
            "Sample disk I/O counters and CPU time over a short window to report "
            "per-device IOPS, throughput, busy/utilization, and overall CPU iowait%."
        ),
        parameters={
            "type": "object",
            "properties": {
                "sample_seconds": {"type": "number", "minimum": 0.1, "maximum": 5.0},
            },
            "required": [],
            "additionalProperties": False,
        },
    )

    def execute(
        self, sample_seconds: float = 1.0, **kwargs: Any
    ) -> ToolResult:
        del kwargs
        if isinstance(sample_seconds, bool) or not isinstance(
            sample_seconds, (int, float)
        ):
            return ToolResult(
                tool_name=self.spec.name,
                status="invalid_input",
                error="sample_seconds must be a number.",
            )
        if not 0.1 <= float(sample_seconds) <= 5.0:
            return ToolResult(
                tool_name=self.spec.name,
                status="invalid_input",
                error="sample_seconds must be between 0.1 and 5.0.",
            )
        window = float(sample_seconds)

        try:
            before_io = psutil.disk_io_counters(perdisk=True)
            before_cpu = psutil.cpu_times()
        except (OSError, psutil.Error) as exc:
            return ToolResult(
                tool_name=self.spec.name,
                status="failed",
                error=f"Could not read I/O/CPU counters ({type(exc).__name__}).",
            )
        if not before_io:
            return ToolResult(
                tool_name=self.spec.name,
                status="failed",
                error="Disk I/O counters are not available on this system.",
                data={"supported": False},
            )

        time.sleep(window)

        try:
            after_io = psutil.disk_io_counters(perdisk=True)
            after_cpu = psutil.cpu_times()
        except (OSError, psutil.Error) as exc:
            return ToolResult(
                tool_name=self.spec.name,
                status="failed",
                error=f"Could not read I/O/CPU counters after sampling ({type(exc).__name__}).",
            )
        if not after_io:
            return ToolResult(
                tool_name=self.spec.name,
                status="failed",
                error="Disk I/O counters disappeared between samples.",
            )

        devices: list[dict[str, Any]] = []
        for name in sorted(set(before_io) & set(after_io)):
            before = before_io[name]
            after = after_io[name]
            d_read = after.read_count - before.read_count
            d_write = after.write_count - before.write_count
            d_read_bytes = after.read_bytes - before.read_bytes
            d_write_bytes = after.write_bytes - before.write_bytes

            util_percent: float | None = None
            if hasattr(before, "busy_time") and hasattr(after, "busy_time"):
                d_busy_ms = after.busy_time - before.busy_time
                util_percent = round(
                    min(100.0, d_busy_ms / (window * 1000.0) * 100.0), 2
                )

            devices.append(
                {
                    "device": name,
                    "read_iops": round(d_read / window, 2),
                    "write_iops": round(d_write / window, 2),
                    "read_bytes_per_sec": int(d_read_bytes / window),
                    "write_bytes_per_sec": int(d_write_bytes / window),
                    "util_percent": util_percent,
                }
            )

        devices.sort(key=lambda item: item["util_percent"] or 0.0, reverse=True)

        iowait_percent: float | None = None
        if hasattr(before_cpu, "iowait") and hasattr(after_cpu, "iowait"):
            total_before = float(sum(before_cpu))
            total_after = float(sum(after_cpu))
            delta_total = total_after - total_before
            delta_iowait = float(after_cpu.iowait) - float(before_cpu.iowait)
            if delta_total > 0:
                iowait_percent = round(delta_iowait / delta_total * 100.0, 2)

        return ToolResult(
            tool_name=self.spec.name,
            status="success",
            data={
                "sample_seconds": window,
                "io_wait_percent": iowait_percent,
                "disk_stats": devices,
                "device_count": len(devices),
            },
            evidence=[
                (f"Sampled disk I/O and CPU iowait over {window:g} second(s); "
                 "no device was modified.")
            ],
        )
def build_tools() -> list[object]:
    """Return the real, read-only system tools for Registry registration."""
    return [
        SystemOverviewTool(),
        DiskUsageTool(),
        TopProcessesTool(),
        ListAllMountsTool(),
        IoStatsTool(),
    ]
