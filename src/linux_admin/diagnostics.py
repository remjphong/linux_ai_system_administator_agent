"""Deterministic, evidence-based incident diagnosis for the Linux admin agent.

This module never executes commands or changes the system. It interprets only
structured results returned by registered tools and distinguishes observed facts
from hypotheses and follow-up recommendations.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from linux_admin.contracts import ToolResult

DiagnosisClass = Literal[
    "endpoint_reachable",
    "endpoint_unreachable",
    "http_server_error",
    "http_client_error",
    "service_missing",
    "service_failed",
    "service_running",
    "service_inactive",
    "resource_pressure",
    "resource_snapshot_no_pressure_signal",
    "service_inventory_failed",
    "service_inventory_clean",
    "network_state_observed",
    "security_posture_review",
    "recent_system_errors",
    "no_recent_errors",
    "inconclusive",
]
Confidence = Literal["high", "medium", "low"]


@dataclass(frozen=True)
class DiagnosticReport:
    """A compact deterministic assessment built from observed tool evidence."""

    classification: DiagnosisClass
    confidence: Confidence
    summary: str
    confirmed_facts: tuple[str, ...] = ()
    hypotheses: tuple[str, ...] = ()
    next_checks: tuple[str, ...] = ()

    def to_findings(self) -> list[str]:
        """Render the structured report into the existing CLI findings format."""
        findings = [
            (
                f"Diagnosis: {self.summary} "
                f"(classification={self.classification}, confidence={self.confidence})."
            )
        ]
        findings.extend(f"Confirmed fact: {fact}" for fact in self.confirmed_facts)
        findings.extend(
            f"Unconfirmed hypothesis: {item}" for item in self.hypotheses
        )
        findings.extend(f"Recommended next check: {item}" for item in self.next_checks)
        return findings


def diagnose_incident(
    user_request: str,
    evidence: Sequence[ToolResult],
) -> DiagnosticReport:
    """Classify common endpoint and systemd outcomes without overstating certainty."""
    by_tool: dict[str, list[ToolResult]] = {}
    for result in evidence:
        by_tool.setdefault(result.tool_name, []).append(result)

    facts: list[str] = []
    hypotheses: list[str] = []
    next_checks: list[str] = []

    tcp_results = by_tool.get("check_tcp_connectivity", [])
    http_results = by_tool.get("check_http_endpoint", [])
    service_results = by_tool.get("get_service_status", [])
    log_results = by_tool.get("get_service_logs", [])
    failed_service_results = by_tool.get("get_failed_services", [])

    tcp_data = _last_success_data(tcp_results)
    http_data = _last_success_data(http_results)
    service_data = _last_success_data(service_results)

    # Endpoint diagnosis: a transport failure is distinct from an HTTP response.
    if tcp_data is not None or http_data is not None:
        endpoint_unreachable = (
            (tcp_data is not None and tcp_data.get("reachable") is False)
            or (http_data is not None and http_data.get("reachable") is False)
        )
        if endpoint_unreachable:
            host = (tcp_data or http_data or {}).get("host", "unknown host")
            port = (tcp_data or http_data or {}).get("port", "unknown port")
            error_type = (tcp_data or {}).get("error_type") or (http_data or {}).get(
                "error_type"
            )
            next_check = (
                "Identify the process/service intended to own this host and port "
                "before inspecting its state or logs."
            )

            if error_type == "ConnectionRefusedError":
                facts.append(
                    f"A connection to {host}:{port} was refused by the target endpoint."
                )

                host_normalized = str(host).casefold()
                is_loopback = (
                    host_normalized == "localhost"
                    or host_normalized == "::1"
                    or host_normalized.startswith("127.")
                )
                port_is_valid = (
                    isinstance(port, int) and not isinstance(port, bool)
                )
                listening_data = _last_success_data(
                    by_tool.get("inspect_listening_port", [])
                )
                matching_listener_check = (
                    is_loopback
                    and port_is_valid
                    and listening_data is not None
                    and listening_data.get("supported") is True
                    and listening_data.get("port") == port
                    and isinstance(listening_data.get("count"), int)
                    and not isinstance(listening_data.get("count"), bool)
                    and isinstance(listening_data.get("listeners"), list)
                )

                if (
                    matching_listener_check
                    and listening_data["count"] == 0
                    and not listening_data["listeners"]
                ):
                    facts.append(
                        f"Local socket inspection reported zero listening "
                        f"sockets on {host}:{port} at inspection time."
                    )
                    hypotheses.append(
                        "This is consistent with no local process listening on "
                        "the inspected port; the evidence does not identify which "
                        "service was expected to own the endpoint."
                    )
                    next_check = (
                        "Identify the expected service from its application or "
                        "deployment configuration, then check its status and "
                        "whether it should bind to this address and port."
                    )
                elif (
                    matching_listener_check
                    and listening_data["count"] > 0
                    and listening_data["listeners"]
                ):
                    facts.append(
                        f"Local socket inspection reported "
                        f"{listening_data['count']} listening socket(s) on "
                        f"local port {port}."
                    )
                    hypotheses.append(
                        "A local listener was reported even though the TCP "
                        "probe was refused; its bound address, namespace, or "
                        "state at probe time may differ. Service ownership "
                        "has not been established."
                    )
                    next_check = (
                        "Inspect the reported listener address and process "
                        "metadata, then verify that it matches the intended "
                        "endpoint."
                    )
                else:
                    hypotheses.append(
                        "No process may be listening on the target port, or "
                        "the connection may be actively rejected; the available "
                        "evidence does not distinguish these causes."
                    )
            elif error_type:
                facts.append(
                    f"The endpoint connection failed with {error_type}."
                )
                hypotheses.append(
                    "The failure may be caused by the listener, network path, "
                    "or endpoint configuration; the specific cause is not "
                    "established by this result alone."
                )
            else:
                facts.append(
                    f"The endpoint was reported unreachable at {host}:{port}."
                )
                hypotheses.append(
                    "The current evidence does not identify the root cause "
                    "of the connection failure."
                )

            next_checks.append(next_check)
            return DiagnosticReport(
                classification="endpoint_unreachable",
                confidence="high",
                summary="The endpoint was unreachable during this check; the root cause is not yet confirmed.",
                confirmed_facts=tuple(facts),
                hypotheses=tuple(hypotheses),
                next_checks=tuple(next_checks),
            )

        status_code = http_data.get("status_code") if http_data else None
        tcp_reachable = tcp_data is not None and tcp_data.get("reachable") is True

        if isinstance(status_code, int) and status_code >= 500:
            facts.append(f"The HTTP endpoint returned server-error status {status_code}.")
            if tcp_reachable:
                facts.append("TCP connectivity to the endpoint succeeded.")
            hypotheses.append(
                "The application or an upstream dependency may be failing; the HTTP status alone does not establish which component is responsible."
            )
            next_checks.append(
                "Inspect logs for the explicitly identified service or application; do not infer service ownership from the URL alone."
            )
            return DiagnosticReport(
                classification="http_server_error",
                confidence="high",
                summary=f"The endpoint is reachable at the HTTP layer but returned {status_code}.",
                confirmed_facts=tuple(facts),
                hypotheses=tuple(hypotheses),
                next_checks=tuple(next_checks),
            )

        if isinstance(status_code, int) and 400 <= status_code < 500:
            facts.append(f"The HTTP endpoint returned client-error status {status_code}.")
            facts.append("An HTTP response was received, so the endpoint is reachable at the HTTP layer.")
            hypotheses.append(
                "The path, request, authentication, or access policy may be incorrect; the status code alone does not identify which."
            )
            next_checks.append(
                "Verify the expected URL path and access requirements for this endpoint."
            )
            return DiagnosticReport(
                classification="http_client_error",
                confidence="high",
                summary=f"The endpoint responded with HTTP {status_code}; application-level success is not established.",
                confirmed_facts=tuple(facts),
                hypotheses=tuple(hypotheses),
                next_checks=tuple(next_checks),
            )

        if isinstance(status_code, int) and 300 <= status_code < 400:
            facts.append(f"The HTTP endpoint returned redirect status {status_code}.")
            facts.append("The client did not follow the redirect, so the final destination was not checked.")
            next_checks.append("Inspect the Location header and validate the intended destination separately.")
            return DiagnosticReport(
                classification="endpoint_reachable",
                confidence="high",
                summary=f"The endpoint responded with HTTP redirect {status_code}; the final destination was not verified.",
                confirmed_facts=tuple(facts),
                next_checks=tuple(next_checks),
            )

        if isinstance(status_code, int) and 200 <= status_code < 300:
            facts.append(f"The HTTP endpoint returned status {status_code}.")
            if tcp_reachable:
                facts.append("TCP connectivity succeeded.")
            facts.append(
                "This confirms endpoint reachability for this request, not every application function."
            )
            return DiagnosticReport(
                classification="endpoint_reachable",
                confidence="high",
                summary=f"The endpoint was reachable and returned HTTP {status_code}.",
                confirmed_facts=tuple(facts),
            )

        # We have an endpoint result, but insufficient successful detail to classify it.
        for result in tcp_results + http_results:
            if not result.ok:
                facts.append(
                    f"Tool {result.tool_name} did not complete successfully (status={result.status})."
                )
        return DiagnosticReport(
            classification="inconclusive",
            confidence="low",
            summary="Endpoint evidence was collected, but it is insufficient to classify the endpoint state.",
            confirmed_facts=tuple(facts),
            hypotheses=("The failure may be in the probe or endpoint path; more specific evidence is needed.",),
            next_checks=("Retry with a bounded TCP check and HTTP request, then compare their individual results.",),
        )

    # systemd service diagnosis: LoadState takes precedence over ActiveState.
    if service_data is not None:
        service_name = str(service_data.get("service_name", "the requested service"))
        load_state = service_data.get("load_state", "unknown")
        active_state = service_data.get("active_state", "unknown")
        sub_state = service_data.get("sub_state", "unknown")

        if load_state == "not-found":
            facts.append(f"systemd did not find the unit {service_name} (load_state=not-found).")
            hypotheses.append(
                "The unit name may be wrong or the service may not be installed; the current result does not distinguish these cases."
            )
            next_checks.append("Verify the exact unit name and whether the intended service is installed.")
            return DiagnosticReport(
                classification="service_missing",
                confidence="high",
                summary=f"The requested systemd unit {service_name} was not found.",
                confirmed_facts=tuple(facts),
                hypotheses=tuple(hypotheses),
                next_checks=tuple(next_checks),
            )

        if active_state == "failed":
            facts.append(f"systemd reports {service_name} in failed state.")
            result = service_data.get("result")
            exit_status = service_data.get("exec_main_status")
            if result is not None:
                facts.append(f"The last recorded systemd result is {result}.")
            if exit_status is not None:
                facts.append(f"The recorded main-process exit status is {exit_status}.")
            next_checks.append("Inspect recent logs and the recorded exit result for the explicitly named service.")
            return DiagnosticReport(
                classification="service_failed",
                confidence="high",
                summary=f"systemd reports {service_name} as failed; the root cause needs log evidence.",
                confirmed_facts=tuple(facts),
                hypotheses=("The service process or its startup/runtime dependency may have failed; logs are needed to determine why.",),
                next_checks=tuple(next_checks),
            )

        if active_state == "active":
            facts.append(f"systemd reports {service_name} as active ({sub_state}).")
            if failed_service_results:
                last_failed = failed_service_results[-1]
                if last_failed.ok and isinstance(last_failed.data.get("failed_services"), list):
                    count = len(last_failed.data["failed_services"])
                    facts.append(f"The failed-service query returned {count} failed service(s).")
            if log_results:
                last_logs = log_results[-1]
                if last_logs.ok and last_logs.data.get("line_count") == 0:
                    minutes = last_logs.data.get("since_minutes", "the requested window")
                    facts.append(f"No journal entries were returned for {service_name} in the last {minutes} minutes.")
            return DiagnosticReport(
                classification="service_running",
                confidence="high",
                summary=f"systemd reports {service_name} as active; this alone does not establish application-level health.",
                confirmed_facts=tuple(facts),
                hypotheses=("A service can be active while an application-level function is unhealthy.",),
                next_checks=("Use a service-specific health check if the service exposes one.",),
            )

        if active_state == "inactive":
            result = str(service_data.get("result", "unknown"))
            exit_status = str(service_data.get("exec_main_status", "unknown"))
            remain_after_exit = str(service_data.get("remain_after_exit", "unknown"))
            if result == "success" and exit_status == "0" and remain_after_exit == "no":
                facts.append(
                    f"{service_name} is inactive, but its last recorded execution succeeded and exited with status 0."
                )
                facts.append("An inactive state alone does not prove a service failure; one-shot services can exit normally.")
            else:
                facts.append(f"systemd reports {service_name} as inactive ({sub_state}).")
                facts.append("Inactive state alone does not establish whether the service should be running.")
            return DiagnosticReport(
                classification="service_inactive",
                confidence="high",
                summary=f"systemd reports {service_name} as inactive; whether this is expected depends on its intended role.",
                confirmed_facts=tuple(facts),
                hypotheses=("If the service is expected to remain running, it may have stopped unexpectedly; verify its intended operating mode.",),
                next_checks=("Confirm whether the unit is expected to be a long-running service or a one-shot task.",),
            )

    # Prefer evidence relevant to the requested subsystem over unrelated
    # CPU/RAM snapshots.
    import unicodedata

    normalized_request = user_request.casefold().replace("đ", "d")
    normalized_request = "".join(
        char
        for char in unicodedata.normalize("NFKD", normalized_request)
        if not unicodedata.combining(char)
    )

    def mentions(*terms: str) -> bool:
        return any(term in normalized_request for term in terms)

    def clean_journal_messages(data: dict | None) -> list[str]:
        if data is None:
            return []
        messages = data.get("errors", [])
        if not isinstance(messages, list):
            return []
        sentinels = {
            "",
            "-- no entries --",
            "no entries",
            "no journal entries",
        }
        return [
            str(message).strip()
            for message in messages
            if str(message).strip().casefold() not in sentinels
        ]

    service_intent = mentions(
        "service", "systemd", "daemon", "unit",
        "dich vu", "loi dich vu",
    )
    network_intent = mentions(
        "network", "internet", "wifi", "dns", "gateway",
        "network interface", "ip address", "packet loss",
        "mang", "ket noi mang", "dia chi ip",
    )
    security_intent = mentions(
        "security", "permission", "privilege", "authentication",
        "unauthorized", "firewall", "access denied",
        "bao mat", "quyen truy cap", "xac thuc",
    )
    journal_intent = mentions(
        "journal", "recent errors", "system errors", "error log",
        "logs", "log", "nhat ky", "loi he thong",
        "loi gan day", "phan tich cac loi",
    )

    journal_results = by_tool.get("get_recent_errors", [])
    journal_data = _last_success_data(journal_results)
    journal_checked = any(result.ok for result in journal_results)
    messages = clean_journal_messages(journal_data)

    # Generic service investigations may have an inventory without an
    # individual get_service_status result.
    inventory_data = _last_success_data(failed_service_results)

    if service_intent and inventory_data is not None:
        raw_services = inventory_data.get("failed_services", [])
        failed_names = (
            [str(item) for item in raw_services]
            if isinstance(raw_services, list)
            else []
        )

        if failed_names:
            facts.append(
                f"systemd reported {len(failed_names)} failed service unit(s)."
            )
            facts.extend(
                f"Reported failed unit: {name}"
                for name in failed_names[:10]
            )
            if journal_checked:
                facts.append(
                    f"The recent error-priority journal query returned "
                    f"{len(messages)} non-empty message(s)."
                )
            return DiagnosticReport(
                classification="service_inventory_failed",
                confidence="high",
                summary=(
                    "systemd reports one or more failed units; the cause of each "
                    "failure has not yet been established."
                ),
                confirmed_facts=tuple(facts),
                hypotheses=(
                    ("A unit may have failed because of its configuration, runtime, "
                        "or a dependency. The inventory alone does not distinguish these causes."),
                ),
                next_checks=(
                    "Inspect the status and recent logs of the relevant failed unit.",
                    "Confirm whether that unit is expected to be running.",
                ),
            )

        facts.append(
            "The systemd failed-service query returned no failed units."
        )
        if journal_checked:
            facts.append(
                f"The recent error-priority journal query returned "
                f"{len(messages)} non-empty message(s)."
            )
        return DiagnosticReport(
            classification="service_inventory_clean",
            confidence="high",
            summary=(
                "The query found no failed systemd units; this does not prove "
                "that every application is healthy."
            ),
            confirmed_facts=tuple(facts),
            hypotheses=(
                "An application can be unhealthy without a systemd unit in failed state.",
            ),
            next_checks=(
                "If the issue persists, inspect the affected application's own health check and logs.",
            ),
        )

    # Interface status is local evidence, not proof of Internet reachability.
    network_data = _last_success_data(by_tool.get("get_network_state", []))

    if network_intent and network_data is not None:
        interfaces = network_data.get("interfaces", [])
        if not isinstance(interfaces, list):
            interfaces = []

        active_count = 0
        facts.append(
            f"The network query returned {len(interfaces)} interface record(s)."
        )

        for interface in interfaces[:20]:
            if not isinstance(interface, dict):
                continue
            name = str(interface.get("name", "unknown"))
            is_up = interface.get("is_up")
            if is_up is True:
                active_count += 1

            addresses = interface.get("addresses", [])
            if not isinstance(addresses, list):
                addresses = []
            ip_addresses = [
                str(item.get("address"))
                for item in addresses
                if isinstance(item, dict) and item.get("address")
            ]
            facts.append(
                f"Interface {name}: is_up={is_up!r}; "
                f"IP address count={len(ip_addresses)}."
            )

        if journal_checked:
            facts.append(
                f"The recent error-priority journal query returned "
                f"{len(messages)} non-empty message(s)."
            )

        return DiagnosticReport(
            classification="network_state_observed",
            confidence="high",
            summary=(
                f"The local query reported {active_count} interface(s) up; "
                "Internet connectivity has not been verified."
            ),
            confirmed_facts=tuple(facts),
            hypotheses=(
                ("An interface being up does not establish DNS resolution, "
                    "gateway reachability, or connectivity to the Internet."),
            ),
            next_checks=(
                ("Test a known gateway or DNS resolver, then test a specific "
                    "external endpoint to isolate the failing network layer."),
            ),
        )

    # Report only the configured checks actually returned by the security tool.
    security_data = _last_success_data(
        by_tool.get("inspect_security_posture", [])
    )

    if security_intent and security_data is not None:
        overall = str(security_data.get("overall", "unknown")).casefold()
        raw_checks = security_data.get("checks", [])
        checks = raw_checks if isinstance(raw_checks, list) else []
        flagged = []

        facts.append(
            f"The registered security checks reported overall={overall!r}."
        )
        for check in checks[:20]:
            if not isinstance(check, dict):
                continue
            name = str(check.get("name", "unnamed"))
            status = str(check.get("status", "unknown"))
            facts.append(f"Security check {name}: status={status}.")
            detail = check.get("detail")
            if detail:
                facts.append(f"Security check detail: {detail}")
            if status.casefold() in {
                "fail", "failed", "warn", "warning", "unknown",
            }:
                flagged.append(name)

        all_pass = overall in {"pass", "ok", "healthy"} and not flagged
        return DiagnosticReport(
            classification="security_posture_review",
            confidence="high",
            summary=(
                "All registered security-posture checks passed."
                if all_pass
                else "One or more registered security checks need review."
            ),
            confirmed_facts=tuple(facts),
            hypotheses=(
                ("These results cover only the checks implemented by this agent, "
                    "not every possible host security risk."),
            ),
            next_checks=(
                (
                    "Review the flagged checks and inspect their underlying configuration."
                    if flagged
                    else
                    "For broader coverage, inspect patch status, exposed services, "
                    "and firewall rules."
                ),
            ),
        )

    # Treat journal sentinel text as an empty result, not as an actual log message.
    if journal_intent and journal_checked:
        if messages:
            facts.append(
                f"The journal query returned {len(messages)} non-empty message(s)."
            )
            facts.extend(
                f"Recent journal message: {message[:300]}"
                for message in messages[:5]
            )
            return DiagnosticReport(
                classification="recent_system_errors",
                confidence="medium",
                summary=(
                    "Recent error-priority journal messages were found; "
                    "they do not by themselves establish the incident's root cause."
                ),
                confirmed_facts=tuple(facts),
                hypotheses=(
                    ("Some entries may be unrelated to the current incident; "
                        "timestamps and affected components need correlation."),
                ),
                next_checks=(
                    "Correlate the messages with the incident time and inspect the relevant subsystem.",
                ),
            )

        facts.append(
            "No error-priority journal messages were returned in the queried time window."
        )
        return DiagnosticReport(
            classification="no_recent_errors",
            confidence="medium",
            summary=(
                "No error-priority journal messages were returned in the queried "
                "time window; this does not prove that the system has no problems."
            ),
            confirmed_facts=tuple(facts),
            hypotheses=(
                ("The incident may not have generated journal entries at this priority, "
                    "or relevant messages may be outside the queried time window."),
            ),
            next_checks=(
                "Expand the time window or inspect the affected application's own logs if the issue persists.",
            ),
        )

    # Resource diagnosis: a snapshot is not proof of sustained pressure.
    system_data = _last_success_data(by_tool.get("get_system_overview", []))
    disk_data = _last_success_data(by_tool.get("get_disk_usage", []))

    if system_data is not None or disk_data is not None:
        observed: list[str] = []
        pressure_indicators: list[str] = []

        cpu = _valid_percentage(system_data, "cpu_percent")
        memory = _valid_percentage(system_data, "memory_percent")
        swap = _valid_percentage(system_data, "swap_percent")
        disk_used = _valid_percentage(disk_data, "used_percent")

        if cpu is not None:
            observed.append(
                f"CPU utilization was {cpu:.1f}% in the collected snapshot."
            )
            if cpu >= 90:
                pressure_indicators.append(
                    f"CPU utilization reached {cpu:.1f}%, at or above the "
                    "90% high-utilization threshold."
                )

        if memory is not None:
            observed.append(f"RAM utilization was {memory:.1f}%.")
            if memory >= 90:
                pressure_indicators.append(
                    f"RAM utilization reached {memory:.1f}%, at or above the "
                    "90% high-utilization threshold."
                )

        if swap is not None:
            observed.append(f"Swap utilization was {swap:.1f}%.")
            if swap >= 80:
                pressure_indicators.append(
                    f"Swap utilization reached {swap:.1f}%, at or above the "
                    "80% investigation threshold."
                )

        if disk_used is not None:
            filesystem = str(disk_data.get("path", "the reported filesystem"))
            observed.append(
                f"Filesystem {filesystem} was {disk_used:.1f}% used."
            )
            if disk_used >= 90:
                pressure_indicators.append(
                    f"Filesystem {filesystem} was {disk_used:.1f}% used, "
                    "at or above the 90% investigation threshold."
                )

        if observed and pressure_indicators:
            return DiagnosticReport(
                classification="resource_pressure",
                confidence="medium",
                summary=(
                    "The resource snapshot contains one or more high-utilization "
                    "indicators; duration and cause are not yet established."
                ),
                confirmed_facts=tuple(observed + pressure_indicators),
                hypotheses=(
                    ("High utilization may reflect a workload spike, constrained "
                    "capacity, or another process; the snapshot does not establish "
                    "the root cause."),
                ),
                next_checks=(
                    ("Repeat resource measurements over a short interval to see "
                    "whether the indicators persist."),
                    ("Inspect top processes and relevant disk-I/O or application "
                    "latency evidence before attributing a cause."),
                ),
            )

        if observed:
            return DiagnosticReport(
                classification="resource_snapshot_no_pressure_signal",
                confidence="medium",
                summary=(
                    "No configured high-utilization threshold was crossed in this "
                    "resource snapshot; this does not establish overall system health."
                ),
                confirmed_facts=tuple(observed),
                hypotheses=(
                    ("A single sample may miss transient CPU load, I/O wait, or "
                    "short-lived memory pressure."),
                ),
                next_checks=(
                    ("If slowness is ongoing, collect repeated samples during the "
                    "problem and inspect disk I/O, process activity, and application "
                    "latency."),
                ),
            )

    # General evidence failures should never be rendered as a confident root cause.
    tool_failures = [result for result in evidence if not result.ok]
    if tool_failures:
        facts.extend(
            f"Tool {result.tool_name} returned status {result.status}."
            for result in tool_failures
        )

    if not facts:
        facts.append("No recognized endpoint or service evidence was available for deterministic diagnosis.")
    return DiagnosticReport(
        classification="inconclusive",
        confidence="low",
        summary="There is not enough structured evidence to determine a root cause.",
        confirmed_facts=tuple(facts),
        hypotheses=("Any specific root cause would be speculative with the evidence currently available.",),
        next_checks=("Collect evidence from a read-only tool directly related to the requested subsystem.",),
    )


def _valid_percentage(data: dict | None, key: str) -> float | None:
    """Return a validated percentage from a successful tool result."""
    if data is None:
        return None
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not 0 <= value <= 100:
        return None
    return float(value)


def _last_success_data(results: Sequence[ToolResult]) -> dict | None:
    """Return the latest successful tool data, if present."""
    for result in reversed(results):
        if result.ok and isinstance(result.data, dict):
            return result.data
    return None
