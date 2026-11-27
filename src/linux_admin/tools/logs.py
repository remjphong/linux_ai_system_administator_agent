"""Bounded Linux service and journal diagnostics.

The tools use fixed executable names and argument arrays with ``shell=False``.
They return a clear unsupported/failure result when systemd utilities are not
available (for example, on Windows or a Linux container without systemd).
"""

from __future__ import annotations

import ipaddress
import platform
import re
import shutil
import subprocess
from collections.abc import Sequence
from typing import Any, ClassVar

from linux_admin.contracts import ToolResult, ToolSpec

_SERVICE_NAME = re.compile(r"^[A-Za-z0-9_@.:-]+\.service$")
_MAX_LINES = 200
_MAX_SINCE_MINUTES = 24 * 60
_DEFAULT_TIMEOUT_SECONDS = 8.0


def validate_service_name(service_name: Any) -> str | None:
    if not isinstance(service_name, str) or len(service_name) > 255:
        return "service_name must be a string of at most 255 characters."
    if not _SERVICE_NAME.fullmatch(service_name) or service_name.startswith("-") or ".." in service_name:
        return "service_name must be a valid .service unit name."
    return None


def _linux_tool_error(tool_name: str) -> ToolResult | None:
    if platform.system() != "Linux":
        return ToolResult(
            tool_name=tool_name,
            status="failed",
            error="This tool requires Linux with systemd/journald; run integration tests on Ubuntu.",
            data={"supported": False, "platform": platform.system()},
        )
    return None


def _run_linux_command(
    tool_name: str,
    executable: str,
    arguments: Sequence[str],
    *,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
) -> tuple[subprocess.CompletedProcess[str] | None, ToolResult | None]:
    unsupported = _linux_tool_error(tool_name)
    if unsupported is not None:
        return None, unsupported
    resolved = shutil.which(executable)
    if resolved is None:
        return None, ToolResult(
            tool_name=tool_name,
            status="failed",
            error=f"Required executable '{executable}' is not installed or not on PATH.",
            data={"executable": executable},
        )
    try:
        completed = subprocess.run(
            [resolved, *arguments],
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return None, ToolResult(
            tool_name=tool_name,
            status="timeout",
            error=f"{executable} did not finish within {timeout_seconds:g} seconds.",
        )
    except (OSError, PermissionError) as exc:
        return None, ToolResult(
            tool_name=tool_name,
            status="failed",
            error=f"Could not execute {executable} ({type(exc).__name__}).",
        )
    if completed.returncode != 0:
        # Do not expose unbounded stderr to the model or CLI.
        detail = (completed.stderr or "").strip().replace("\x00", "")[:300]
        return None, ToolResult(
            tool_name=tool_name,
            status="failed",
            error=f"{executable} exited with code {completed.returncode}.",
            data={"stderr_excerpt": detail} if detail else {},
        )
    return completed, None


class FailedServicesTool:
    spec = ToolSpec(
        name="get_failed_services",
        description="List systemd services currently in a failed state.",
    )

    def execute(self, **kwargs: Any) -> ToolResult:
        del kwargs
        completed, error = _run_linux_command(
            self.spec.name,
            "systemctl",
            ['list-units', '--type=service', '--state=failed', '--no-legend', '--no-pager', '--plain', '--full'],
        )
        if error is not None:
            return error
        assert completed is not None
        failed_services: list[str] = []
        for line in completed.stdout.splitlines():
            parts = line.split()
            if parts and _SERVICE_NAME.fullmatch(parts[0]):
                failed_services.append(parts[0])
        return ToolResult(
            tool_name=self.spec.name,
            status="success",
            data={"failed_services": failed_services, "count": len(failed_services)},
            evidence=["Read failed service units from systemctl; no service was changed."],
        )


class ServiceLogsTool:
    spec = ToolSpec(
        name="get_service_logs",
        description="Read a bounded number of recent journal entries for one service.",
        parameters={
            "type": "object",
            "properties": {
                "service_name": {"type": "string", "minLength": 1, "maxLength": 255},
                "lines": {"type": "integer", "minimum": 1, "maximum": _MAX_LINES},
                "since_minutes": {"type": "integer", "minimum": 1, "maximum": _MAX_SINCE_MINUTES},
            },
            "required": ["service_name"],
            "additionalProperties": False,
        },
    )

    def execute(
        self,
        service_name: str,
        lines: int = 100,
        since_minutes: int = 60,
        **kwargs: Any,
    ) -> ToolResult:
        del kwargs
        invalid = validate_service_name(service_name)
        if invalid:
            return ToolResult(tool_name=self.spec.name, status="invalid_input", error=invalid)
        if isinstance(lines, bool) or not isinstance(lines, int) or not 1 <= lines <= _MAX_LINES:
            return ToolResult(tool_name=self.spec.name, status="invalid_input", error=f"lines must be between 1 and {_MAX_LINES}.")
        if isinstance(since_minutes, bool) or not isinstance(since_minutes, int) or not 1 <= since_minutes <= _MAX_SINCE_MINUTES:
            return ToolResult(tool_name=self.spec.name, status="invalid_input", error=f"since_minutes must be between 1 and {_MAX_SINCE_MINUTES}.")

        completed, error = _run_linux_command(
            self.spec.name,
            "journalctl",
            [
                "--unit", service_name,
                "--since", f"{since_minutes} minutes ago",
                "--no-pager",
                "--output=short-iso",
                f"--lines={lines}",
            ],
        )
        if error is not None:
            return error
        assert completed is not None
        entries = completed.stdout.splitlines()
        # journalctl prints this sentinel when there are no matching records.
        # It is human-readable status text, not an actual journal entry.
        if len(entries) == 1 and entries[0].strip() == "-- No entries --":
            entries = []
        entries = entries[-lines:]
        return ToolResult(
            tool_name=self.spec.name,
            status="success",
            data={
                "service_name": service_name,
                "lines": entries,
                "line_count": len(entries),
                "since_minutes": since_minutes,
            },
            evidence=[f"Read {len(entries)} journal entries for {service_name}; no service was changed."],
        )


class RecentErrorsTool:
    spec = ToolSpec(
        name="get_recent_errors",
        description="Read bounded recent system journal messages at error priority or higher.",
        parameters={
            "type": "object",
            "properties": {
                "lines": {"type": "integer", "minimum": 1, "maximum": _MAX_LINES},
                "since_minutes": {"type": "integer", "minimum": 1, "maximum": _MAX_SINCE_MINUTES},
            },
            "required": [],
            "additionalProperties": False,
        },
    )

    def execute(self, lines: int = 100, since_minutes: int = 60, **kwargs: Any) -> ToolResult:
        del kwargs
        if isinstance(lines, bool) or not isinstance(lines, int) or not 1 <= lines <= _MAX_LINES:
            return ToolResult(tool_name=self.spec.name, status="invalid_input", error=f"lines must be between 1 and {_MAX_LINES}.")
        if isinstance(since_minutes, bool) or not isinstance(since_minutes, int) or not 1 <= since_minutes <= _MAX_SINCE_MINUTES:
            return ToolResult(tool_name=self.spec.name, status="invalid_input", error=f"since_minutes must be between 1 and {_MAX_SINCE_MINUTES}.")
        completed, error = _run_linux_command(
            self.spec.name,
            "journalctl",
            [
                "--priority=err",
                "--since", f"{since_minutes} minutes ago",
                "--no-pager",
                "--output=short-iso",
                f"--lines={lines}",
            ],
        )
        if error is not None:
            return error
        assert completed is not None
        entries = completed.stdout.splitlines()
        # journalctl's sentinel is status text, not an actual error record.
        if len(entries) == 1 and entries[0].strip() == "-- No entries --":
            entries = []
        entries = entries[-lines:]
        return ToolResult(
            tool_name=self.spec.name,
            status="success",
            data={"errors": entries, "count": len(entries), "since_minutes": since_minutes},
            evidence=[f"Read {len(entries)} recent error-priority journal entries."],
        )


class KernelLogTool:
    """Read kernel log entries filtered by priority via journalctl --dmesg."""

    spec = ToolSpec(
        name="get_kernel_log",
        description=(
            "Read bounded kernel log entries from journalctl --dmesg filtered by "
            "priority. Use priority='err' (default) to surface OOM kills, hardware "
            "errors, and EXT4 failures without pulling the full ring buffer."
        ),
        parameters={
            "type": "object",
            "properties": {
                "lines": {"type": "integer", "minimum": 1, "maximum": _MAX_LINES},
                "since_minutes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": _MAX_SINCE_MINUTES,
                },
                "priority": {
                    "type": "string",
                    "enum": ["emerg", "alert", "crit", "err", "warning"],
                },
            },
            "required": [],
            "additionalProperties": False,
        },
    )

    _PRIORITY_MAP: ClassVar[dict[str, str]] = {
        "emerg": "0",
        "alert": "1",
        "crit": "2",
        "err": "3",
        "warning": "4",
    }

    def execute(
        self,
        lines: int = 100,
        since_minutes: int = 60,
        priority: str = "err",
        **kwargs: Any,
    ) -> ToolResult:
        del kwargs
        if isinstance(lines, bool) or not isinstance(lines, int) or not 1 <= lines <= _MAX_LINES:
            return ToolResult(
                tool_name=self.spec.name,
                status="invalid_input",
                error=f"lines must be between 1 and {_MAX_LINES}.",
            )
        if (
            isinstance(since_minutes, bool)
            or not isinstance(since_minutes, int)
            or not 1 <= since_minutes <= _MAX_SINCE_MINUTES
        ):
            return ToolResult(
                tool_name=self.spec.name,
                status="invalid_input",
                error=f"since_minutes must be between 1 and {_MAX_SINCE_MINUTES}.",
            )
        if priority not in self._PRIORITY_MAP:
            return ToolResult(
                tool_name=self.spec.name,
                status="invalid_input",
                error=f"priority must be one of: {sorted(self._PRIORITY_MAP)}.",
            )

        completed, error = _run_linux_command(
            self.spec.name,
            "journalctl",
            [
                "--dmesg",
                f"--priority={self._PRIORITY_MAP[priority]}",
                "--since",
                f"{since_minutes} minutes ago",
                "--no-pager",
                "--output=short-iso",
                f"--lines={lines}",
            ],
        )
        if error is not None:
            return error
        assert completed is not None
        entries = completed.stdout.splitlines()
        if len(entries) == 1 and entries[0].strip() == "-- No entries --":
            entries = []
        entries = entries[-lines:]
        return ToolResult(
            tool_name=self.spec.name,
            status="success",
            data={
                "messages": entries,
                "line_count": len(entries),
                "priority": priority,
                "since_minutes": since_minutes,
            },
            evidence=[
                f"Read {len(entries)} kernel log entr(y/ies) at priority >= {priority}."
            ],
        )


class AuthLogTool:
    """Analyze recent SSH/auth journal entries for login anomalies and brute force."""

    spec = ToolSpec(
        name="check_auth_log",
        description=(
            "Scan recent ssh/sshd/systemd-logind journal entries for failed logins, "
            "successful logins, sudo events, and per-source-IP failure counts. "
            "Flags brute-force suspicion when a single IP reaches the threshold."
        ),
        parameters={
            "type": "object",
            "properties": {
                "lines": {"type": "integer", "minimum": 1, "maximum": _MAX_LINES},
                "since_minutes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": _MAX_SINCE_MINUTES,
                },
                "brute_force_threshold": {
                    "type": "integer",
                    "minimum": 3,
                    "maximum": 100,
                },
            },
            "required": [],
            "additionalProperties": False,
        },
    )

    _SSH_EVENT = re.compile(
        r"^\S+\s+\S+\s+sshd(?:-session|-auth)?\[\d+\]: "
        r"(?P<outcome>Failed|Accepted) \S+ for (?:invalid user )?\S+ "
        r"from (?P<ip>\S+) port \d+\b"
    )

    def execute(
        self,
        lines: int = 200,
        since_minutes: int = 60,
        brute_force_threshold: int = 10,
        **kwargs: Any,
    ) -> ToolResult:
        del kwargs
        if isinstance(lines, bool) or not isinstance(lines, int) or not 1 <= lines <= _MAX_LINES:
            return ToolResult(
                tool_name=self.spec.name,
                status="invalid_input",
                error=f"lines must be between 1 and {_MAX_LINES}.",
            )
        if (
            isinstance(since_minutes, bool)
            or not isinstance(since_minutes, int)
            or not 1 <= since_minutes <= _MAX_SINCE_MINUTES
        ):
            return ToolResult(
                tool_name=self.spec.name,
                status="invalid_input",
                error=f"since_minutes must be between 1 and {_MAX_SINCE_MINUTES}.",
            )
        if (
            isinstance(brute_force_threshold, bool)
            or not isinstance(brute_force_threshold, int)
            or not 3 <= brute_force_threshold <= 100
        ):
            return ToolResult(
                tool_name=self.spec.name,
                status="invalid_input",
                error="brute_force_threshold must be between 3 and 100.",
            )

        completed, error = _run_linux_command(
            self.spec.name,
            "journalctl",
            [
                "--system",
                "--unit",
                "ssh",
                "--unit",
                "sshd",
                "--unit",
                "systemd-logind",
                "--since",
                f"{since_minutes} minutes ago",
                "--no-pager",
                "--output=short-iso",
                f"--lines={lines + 1}",
            ],
        )
        if error is not None:
            return error
        assert completed is not None
        if completed.stderr.strip():
            return ToolResult(
                self.spec.name, "failed",
                error="Không xác nhận được quyền đọc journal hệ thống đầy đủ.",
            )
        entries = [
            line for line in completed.stdout.splitlines()
            if line.strip() and line.strip() != "-- No entries --"
        ]
        complete = len(entries) <= lines
        entries = entries[-lines:]
        failures: dict[str, int] = {}
        accepted_after_failures: set[str] = set()
        recent_failures: list[str] = []
        success_count = failed_count = sudo_count = 0
        for line in entries:
            if re.search(r"\bsudo(?:\[\d+\])?: ", line):
                sudo_count += 1
            event = self._SSH_EVENT.search(line)
            if event is None:
                continue
            try:
                ip = str(ipaddress.ip_address(event["ip"]))
            except ValueError:
                continue
            if event["outcome"] == "Failed":
                failed_count += 1
                failures[ip] = failures.get(ip, 0) + 1
                recent_failures.append(line[:500])
            else:
                success_count += 1
                if failures.get(ip, 0) >= brute_force_threshold:
                    accepted_after_failures.add(ip)

        counts = [
            {"ip": ip, "failure_count": count}
            for ip, count in sorted(failures.items(), key=lambda item: (-item[1], item[0]))
        ]
        suspicious = [
            {**item, "accepted_after_failures": item["ip"] in accepted_after_failures}
            for item in counts if item["failure_count"] >= brute_force_threshold
        ]
        return ToolResult(
            tool_name=self.spec.name,
            status="success",
            data={
                "window_minutes": since_minutes,
                "coverage_complete": complete,
                "scanned_line_count": len(entries),
                "failed_login_count": failed_count,
                "successful_login_count": success_count,
                "sudo_event_count": sudo_count,
                "top_source_ips": counts[:10],
                "failed_source_ips": sorted(failures),
                "suspicious_ips": suspicious,
                "brute_force_suspected": bool(suspicious),
                "brute_force_threshold": brute_force_threshold,
                "recent_failures": recent_failures[-20:],
            },
            evidence=[
                f"SSH: {failed_count} failed and {success_count} accepted events.",
                f"{len(suspicious)} source(s) reached {brute_force_threshold} failures.",
                "Journal window read." if complete else "Journal window truncated.",
            ],
        )



def build_tools() -> list[object]:
    return [
        FailedServicesTool(),
        ServiceLogsTool(),
        RecentErrorsTool(),
        KernelLogTool(),
        AuthLogTool(),
    ]
