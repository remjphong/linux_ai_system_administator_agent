"""Bounded, read-only incident orchestration for the beta Agent.

The first implementation deliberately uses a rule-based planner. It collects
observable evidence through ToolRegistry and returns an IncidentContext. It does
not perform system-changing actions; those must be handled by control.py after
policy and approval checks have been implemented and tested.
"""

from __future__ import annotations

import re
from typing import Protocol, Sequence
from urllib.parse import urlsplit

from linux_admin.config import AppConfig
from linux_admin.contracts import IncidentContext, ToolResult, ToolSpec
from linux_admin.llm_client import AgentPlan, PlanStep
from linux_admin.registry import ToolRegistry


class AuditSink(Protocol):
    """Minimal audit interface consumed by the Agent."""

    def record_event(
        self,
        event_type: str,
        incident_id: str,
        details: dict,
        action_id: str | None = None,
    ) -> int:
        ...


class Planner(Protocol):
    """Planning interface used by the Agent."""

    def create_plan(
        self,
        user_request: str,
        available_tools: Sequence[ToolSpec],
    ) -> AgentPlan:
        ...


class RuleBasedPlanner:
    """Plan the three beta incidents without depending on an LLM or network."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def create_plan(
        self,
        user_request: str,
        available_tools: Sequence[ToolSpec],
    ) -> AgentPlan:
        request = user_request.casefold()
        available = {spec.name for spec in available_tools if not spec.changes_system}
        service_name = self._service_name_from_request(user_request)
        url = self._url_from_request(user_request) or "http://127.0.0.1:8080/health"
        parsed_url = urlsplit(url)
        host = parsed_url.hostname or "127.0.0.1"
        try:
            port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
        except ValueError:
            port = 80

        if self._looks_like_disk_pressure(request):
            candidates = [
                PlanStep("get_disk_usage", {"path": "/"}, "Measure filesystem usage"),
                PlanStep("get_system_overview", {}, "Collect system-level context"),
                PlanStep("list_top_processes", {"limit": 5}, "Inspect top processes"),
            ]
            rationale = "Disk-pressure triage: measure usage, then gather context."
        elif self._looks_like_unreachable(request):
            candidates = [
                PlanStep(
                    "check_tcp_connectivity",
                    {"host": host, "port": port},
                    "Check transport-level reachability",
                ),
                PlanStep(
                    "check_http_endpoint",
                    {"url": url},
                    "Check application-level HTTP response",
                ),
                PlanStep(
                    "get_service_status",
                    {"service_name": service_name},
                    "Check the likely backing service",
                ),
                PlanStep(
                    "get_service_logs",
                    {"service_name": service_name},
                    "Collect diagnostic logs",
                ),
            ]
            rationale = "Endpoint triage: compare TCP, HTTP, service, and log evidence."
        else:
            candidates = [
                PlanStep(
                    "get_service_status",
                    {"service_name": service_name},
                    "Check service state",
                ),
                PlanStep("get_failed_services", {}, "List failed services"),
                PlanStep(
                    "get_service_logs",
                    {"service_name": service_name},
                    "Collect service logs",
                ),
            ]
            rationale = "Service triage: inspect state, failed services, and logs."

        steps = tuple(step for step in candidates if step.tool_name in available)
        if not steps:
            rationale += " No matching read-only tools are registered."
        return AgentPlan(steps=steps, rationale=rationale)

    def _service_name_from_request(self, request: str) -> str:
        match = re.search(r"\b[a-zA-Z0-9_.@-]+\.service\b", request)
        if match:
            return match.group(0)
        if self._config.services.allowlist:
            return self._config.services.allowlist[0]
        return "demo-web.service"

    @staticmethod
    def _url_from_request(request: str) -> str | None:
        match = re.search(r"https?://[^\s'\"<>]+", request, re.IGNORECASE)
        if not match:
            return None
        return match.group(0).rstrip(".,);]")

    @staticmethod
    def _looks_like_disk_pressure(request: str) -> bool:
        keywords = (
            "disk pressure",
            "disk usage",
            "disk space",
            "filesystem",
            "disk full",
            "ổ đĩa",
            "dung lượng đĩa",
            "dung lượng ổ đĩa",
            "ổ cứng đầy",
        )
        return any(keyword in request for keyword in keywords)

    @staticmethod
    def _looks_like_unreachable(request: str) -> bool:
        keywords = (
            "unreachable",
            "endpoint",
            "tcp",
            "http",
            "not reachable",
            "cannot connect",
            "connection failed",
            "không truy cập",
            "khong truy cap",
            "không kết nối",
            "khong ket noi",
        )
        return any(keyword in request for keyword in keywords)


class Agent:
    """Run a bounded investigation using registered read-only tools.

    Args:
        registry: ToolRegistry containing explicitly registered tools.
        config: Validated configuration returned by ``load_config``.
        audit: An AuditLogger-compatible object. Required when audit is enabled.
        planner: Optional planner; defaults to RuleBasedPlanner.

    ``run`` returns the updated IncidentContext. A completed investigation means
    evidence collection finished; it does not mean the underlying incident was
    repaired.
    """

    def __init__(
        self,
        registry: ToolRegistry,
        config: AppConfig,
        audit: AuditSink | None,
        planner: Planner | None = None,
    ) -> None:
        self.registry = registry
        self.config = config
        self.audit = audit
        self.planner = planner or RuleBasedPlanner(config)
        if config.audit.enabled and audit is None:
            raise ValueError("An audit sink is required when audit.enabled is true")

    def run(self, user_request: str) -> IncidentContext:
        """Investigate one request and return evidence plus an explicit final state."""
        context = IncidentContext(user_request=user_request.strip())
        context.status = "investigating"

        if not self._record_event(
            "incident.started",
            context,
            {"request_length": len(context.user_request)},
        ):
            context.status = "failed"
            context.findings.append(
                "Audit failed; investigation stopped before tool use."
            )
            return context

        try:
            available_tools = [
                spec for spec in self.registry.list_tools() if not spec.changes_system
            ]
            plan = self.planner.create_plan(context.user_request, available_tools)
            if not isinstance(plan, AgentPlan):
                raise TypeError("Planner must return an AgentPlan")
        except Exception as exc:
            context.status = "failed"
            context.findings.append(f"Planning failed: {type(exc).__name__}.")
            self._record_event(
                "incident.planning_failed",
                context,
                {"error_type": type(exc).__name__},
            )
            self._record_final(context)
            return context

        context.findings.append(plan.rationale)
        plan_was_truncated = len(plan.steps) > self.config.agent.max_steps
        selected_steps = plan.steps[: self.config.agent.max_steps]
        if plan_was_truncated:
            context.findings.append(
                f"Plan limited to {self.config.agent.max_steps} steps by configuration."
            )

        plan_audited = self._record_event(
            "incident.plan_created",
            context,
            {
                "planned_step_count": len(plan.steps),
                "executed_step_limit": len(selected_steps),
                "tool_names": [step.tool_name for step in selected_steps],
            },
        )
        if not plan_audited:
            context.status = "failed"
            context.findings.append(
                "Audit failed while recording the plan; no tools were invoked."
            )
            self._record_final(context)
            return context

        if not selected_steps:
            context.status = "inconclusive"
            context.findings.append(
                "No applicable read-only tools were available; "
                "no system action was taken."
            )
            self._record_final(context)
            return context

        audit_failed = False
        for step in selected_steps:
            context.steps += 1
            spec = self.registry.get_spec(step.tool_name)
            if spec is None:
                result = ToolResult(
                    tool_name=step.tool_name,
                    status="failed",
                    error="Planned tool is not registered",
                )
            elif spec.changes_system:
                # Defense in depth: the investigation planner may never run actions.
                result = ToolResult(
                    tool_name=step.tool_name,
                    status="denied",
                    error="Agent investigation only permits read-only tools",
                )
            else:
                result = self.registry.invoke(step.tool_name, step.arguments)

            context.evidence.append(result)
            context.findings.append(self._summarize_result(result))
            event_type = "tool.completed" if result.ok else "tool.failed"
            if not self._record_event(
                event_type,
                context,
                {
                    "tool_name": result.tool_name,
                    "status": result.status,
                    "duration_ms": result.duration_ms,
                    "data_fields": sorted(result.data.keys()),
                    "evidence_count": len(result.evidence),
                },
            ):
                audit_failed = True
                break

        successful_results = sum(1 for result in context.evidence if result.ok)
        if audit_failed:
            context.status = "failed"
            context.findings.append(
                "Audit persistence failed during investigation; processing stopped."
            )
        elif successful_results == 0:
            context.status = "inconclusive"
            context.findings.append(
                "No tool returned successful evidence; the cause remains inconclusive."
            )
        else:
            context.status = "completed"
            if any(not result.ok for result in context.evidence):
                context.findings.append(
                    "Some tools failed; conclusions are limited by missing evidence."
                )
            context.findings.append(
                "Investigation completed. This does not mean the incident is repaired."
            )

        self._record_final(context)
        return context

    def _record_event(
        self,
        event_type: str,
        context: IncidentContext,
        details: dict,
    ) -> bool:
        if not self.config.audit.enabled:
            return True
        if self.audit is None:
            return False
        try:
            self.audit.record_event(
                event_type=event_type,
                incident_id=context.incident_id,
                details=details,
            )
        except Exception:
            # Do not leak DB paths, SQL, or secret-bearing exception text to the user.
            return False
        return True

    def _record_final(self, context: IncidentContext) -> None:
        # Final audit failure does not rewrite an already determined evidence result,
        # but is recorded in the returned context so the caller can report it.
        if not self._record_event(
            "incident.finished",
            context,
            {
                "status": context.status,
                "steps": context.steps,
                "evidence_count": len(context.evidence),
            },
        ):
            context.status = "failed"
            context.findings.append(
                "Could not persist the final audit event; report audit failure."
            )

    @staticmethod
    def _summarize_result(result: ToolResult) -> str:
        if not result.ok:
            error = result.error or "no error details"
            return f"{result.tool_name}: {result.status} ({error})."

        highlights: list[str] = []
        preferred_keys = (
            "active_state",
            "is_active",
            "used_percent",
            "usage_percent",
            "reachable",
            "status_code",
            "failed_services",
            "errors",
        )
        for key in preferred_keys:
            if key in result.data:
                highlights.append(f"{key}={result.data[key]!r}")
        if not highlights:
            fields = ",".join(sorted(result.data.keys())) or "(none)"
            highlights.append(f"output_fields={fields}")
        return f"{result.tool_name}: success; " + "; ".join(highlights) + "."
