"""Bounded, read-only incident orchestration for the beta Agent.

The first implementation deliberately uses a rule-based planner. It collects
observable evidence through ToolRegistry and returns an IncidentContext. It does
not perform system-changing actions; those must be handled by control.py after
policy and approval checks have been implemented and tested.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from typing import Protocol
from urllib.parse import urlsplit

from linux_admin.config import AppConfig
from linux_admin.contracts import IncidentContext, ToolResult, ToolSpec
from linux_admin.diagnostics import diagnose_incident
from linux_admin.llm_client import (
    AgentPlan,
    LLMClient,
    OpenAICompatibleLLMClient,
    PlanStep,
)
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
    """Select bounded, read-only probes for common Linux incidents."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def create_plan(
        self,
        user_request: str,
        available_tools: Sequence[ToolSpec],
    ) -> AgentPlan:
        request = self._normalize_request(user_request)
        available = {
            spec.name for spec in available_tools if not spec.changes_system
        }
        service_name = self._explicit_service_name_from_request(user_request)
        url = self._url_from_request(user_request)

        candidates: list[PlanStep] = []
        selected: set[str] = set()

        def add(name: str, arguments: dict, reason: str) -> None:
            if name in available and name not in selected:
                candidates.append(PlanStep(name, arguments, reason))
                selected.add(name)

        disk_issue = self._looks_like_disk_pressure(request)
        resource_issue = self._contains_any(
            request,
            (
                "cpu", "processor", "memory", "ram", "swap",
                "performance", "system health", "system overview",
                "resource usage", "top processes", "processes",
                "slow", "sluggish", "lag", "laggy", "running slowly",
                "system slowdown", "hieu nang", "bo nho",
                "tai nguyen he thong", "cham", "chay cham",
                "may cham", "may chay cham", "do", "giat",
                "ngon ram", "cpu cao", "ram cao",
            ),
        )
        security_issue = self._contains_any(
            request,
            (
                "security", "permission", "privilege", "authentication",
                "unauthorized", "firewall", "access denied", "bao mat",
                "quyen truy cap", "xac thuc", "dang nhap",
                "tu choi truy cap",
            ),
        )
        network_issue = self._contains_any(
            request,
            (
                "network", "internet", "wifi", "dns", "gateway",
                "network interface", "ip address", "packet loss",
                "mang internet", "ket noi mang", "mang may tinh",
                "mat ket noi", "dia chi ip", "khong co mang",
            ),
        )
        # An explicit user URL has priority. For a general network check,
        # use only the administrator-configured HTTPS probe, if present.
        if not url and network_issue:
            url = self._config.agent.connectivity_check_url

        service_issue = bool(service_name) or self._contains_any(
            request,
            (
                "service", "systemd", "daemon", "unit", "restart",
                "failed service", "service status", "dich vu",
                "khoi dong lai dich vu", "dich vu loi",
            ),
        )
        log_issue = self._contains_any(
            request,
            (
                "log", "journal", "error", "errors", "exception",
                "crash", "failure", "failed", "not starting",
                "keeps stopping", "system error", "loi he thong",
                "nhat ky", "khong khoi dong", "bi dung",
                "that bai",
            ),
        )
        endpoint_issue = bool(url) or self._looks_like_unreachable(request)

        # Probe the user-supplied endpoint only; never invent localhost targets.
        if url:
            parsed_url = urlsplit(url)
            host = parsed_url.hostname

            if host:
                try:
                    port = parsed_url.port or (
                        443 if parsed_url.scheme.casefold() == "https" else 80
                    )
                except ValueError:
                    port = None

                if port is not None and 1 <= port <= 65535:
                    add(
                        "check_tcp_connectivity",
                        {"host": host, "port": port},
                        "Check TCP connectivity to the supplied endpoint",
                    )

            add(
                "check_http_endpoint",
                {"url": url},
                "Inspect the HTTP response from the supplied endpoint",
            )

        # Explicit service failure: status -> failed-service context -> logs.
        if service_name:
            add(
                "get_service_status",
                {"service_name": service_name},
                "Inspect the explicitly named systemd unit",
            )
            if log_issue:
                add(
                    "get_failed_services",
                    {},
                    "Collect systemd failed-service context",
                )
            add(
                "get_service_logs",
                {"service_name": service_name},
                "Collect logs for the explicitly named unit",
            )

        if disk_issue:
            add(
                "get_disk_usage",
                {"path": "/"},
                "Measure root filesystem capacity",
            )
            add(
                "get_system_overview",
                {},
                "Collect system-level context for disk investigation",
            )
            add(
                "list_top_processes",
                {"limit": 5},
                "Inspect top processes for additional workload context",
            )

        if resource_issue and not disk_issue:
            add(
                "get_system_overview",
                {},
                "Collect CPU, memory, uptime, and process-count metrics",
            )
            add(
                "list_top_processes",
                {"limit": 10},
                "Identify processes with the largest memory footprint",
            )

        if security_issue:
            add(
                "inspect_security_posture",
                {},
                "Inspect high-level runtime security posture",
            )
            add(
                "get_recent_errors",
                {"lines": 50, "since_minutes": 60},
                "Collect recent system errors for security context",
            )

        if network_issue or (endpoint_issue and not url):
            add(
                "get_network_state",
                {},
                "Inspect network interfaces and assigned IP addresses",
            )
            add(
                "get_recent_errors",
                {"lines": 50, "since_minutes": 60},
                "Collect recent system errors relevant to connectivity",
            )

        if service_issue and not service_name:
            add(
                "get_failed_services",
                {},
                "List systemd services currently reported as failed",
            )
            add(
                "get_recent_errors",
                {"lines": 50, "since_minutes": 60},
                "Inspect recent errors for service-related evidence",
            )

        if log_issue and not service_name:
            add(
                "get_recent_errors",
                {"lines": 50, "since_minutes": 60},
                "Inspect recent error-level journal entries",
            )
            add(
                "get_failed_services",
                {},
                "Check for failed systemd services",
            )

        # An unclassified request gets a read-only survey, not an arbitrary
        # service restart, guessed service, or fabricated endpoint.
        if not candidates:
            add(
                "get_system_overview",
                {},
                "Establish a baseline of system resources",
            )
            add(
                "get_disk_usage",
                {"path": "/"},
                "Inspect root filesystem capacity",
            )
            add(
                "get_network_state",
                {},
                "Inspect local network configuration",
            )
            add(
                "get_failed_services",
                {},
                "Check for services reported as failed",
            )
            add(
                "get_recent_errors",
                {"lines": 50, "since_minutes": 60},
                "Inspect recent system error messages",
            )

        if not candidates:
            rationale = (
                "No applicable read-only diagnostic tools are registered."
            )
        elif not any(
            (
                disk_issue, resource_issue, security_issue, network_issue,
                service_issue, log_issue, endpoint_issue,
            )
        ):
            rationale = (
                "General system survey using registered read-only diagnostic tools."
            )
        else:
            categories = []
            if endpoint_issue:
                categories.append("endpoint connectivity")
            if service_issue:
                categories.append("service state")
            if disk_issue:
                categories.append("filesystem capacity")
            if resource_issue:
                categories.append("system resources")
            if network_issue:
                categories.append("network configuration")
            if security_issue:
                categories.append("security posture")
            if log_issue:
                categories.append("system errors and logs")

            rationale = (
                "Read-only investigation for "
                + ", ".join(categories)
                + "; conclusions depend on collected evidence."
            )

        return AgentPlan(steps=tuple(candidates), rationale=rationale)

    @staticmethod
    def _normalize_request(request: str) -> str:
        """Normalize case and Vietnamese diacritics for phrase matching."""
        import unicodedata

        request = request.casefold().replace("đ", "d")
        return "".join(
            character
            for character in unicodedata.normalize("NFKD", request)
            if not unicodedata.combining(character)
        )

    @staticmethod
    def _contains_any(request: str, phrases: Sequence[str]) -> bool:
        return any(phrase in request for phrase in phrases)

    @staticmethod
    def _explicit_service_name_from_request(request: str) -> str | None:
        """Return a systemd unit only if its name appears in the request."""
        match = re.search(r"\b[a-zA-Z0-9_.@-]+\.service\b", request)
        return match.group(0) if match else None

    def _default_service_name(self) -> str:
        """Compatibility helper; generic requests must not use this default."""
        if self._config.services.allowlist:
            return self._config.services.allowlist[0]
        return "demo-web.service"

    @staticmethod
    def _url_from_request(request: str) -> str | None:
        match = re.search(r"https?://[^\s'\"<>]+", request, re.IGNORECASE)
        if not match:
            return None
        return match.group(0).rstrip(".,);]")

    @classmethod
    def _looks_like_disk_pressure(cls, request: str) -> bool:
        normalized = cls._normalize_request(request)
        return cls._contains_any(
            normalized,
            (
                "disk pressure", "disk usage", "disk space", "filesystem",
                "disk full", "o dia", "dung luong dia", "o cung day",
            ),
        )

    @classmethod
    def _looks_like_unreachable(cls, request: str) -> bool:
        normalized = cls._normalize_request(request)
        return cls._contains_any(
            normalized,
            (
                "unreachable", "endpoint", "tcp", "http", "not reachable",
                "cannot connect", "connection failed", "connection refused",
                "khong truy cap", "khong ket noi", "khong the ket noi",
                "khong phan hoi", "ket noi that bai",
            ),
        )



class HybridPlanner:
    """Route clear Linux tasks to deterministic rules and complex tasks to LLM."""

    _RESEARCH_PHRASES = (
        "search the web",
        "search online",
        "web search",
        "official documentation",
        "official docs",
        "external sources",
        "research online",
        "tavily",
        "tra cuu",
        "tim kiem web",
        "tim tren internet",
        "tai lieu chinh thuc",
        "tai lieu chinh thong",
    )

    _COMPLEX_PHRASES = (
        "compare",
        "comparison",
        "correlate",
        "correlation",
        "across multiple",
        "root cause across",
        "architecture",
        "design a plan",
        "trade-off",
        "tradeoff",
        "so sanh",
        "tuong quan",
        "kien truc",
        "thiet ke",
        "phoi hop nhieu subsystem",
        "nhieu subsystem",
    )

    _LOCAL_INTENT_PHRASES = (
        "endpoint", "http", "tcp", "port",
        "connection refused", "connection failed",
        "service", "systemd", "daemon", "unit", "dich vu",
        "log", "journal", "error", "exception", "crash",
        "failure", "failed", "loi", "nhat ky",
        "cpu", "processor", "memory", "ram", "swap",
        "performance", "system health", "system overview",
        "process", "processes", "slow", "cham", "bo nho",
        "disk", "storage", "filesystem", "disk space",
        "o dia", "dung luong dia", "o cung day",
        "network", "internet", "wifi", "dns", "gateway",
        "mang", "security", "permission", "privilege",
        "authentication", "unauthorized", "firewall",
        "bao mat", "quyen truy cap", "xac thuc",
    )

    def __init__(
        self,
        config: AppConfig,
        rule_planner: RuleBasedPlanner,
        llm_planner: Planner,
    ) -> None:
        self._config = config
        self._rule_planner = rule_planner
        self._llm_planner = llm_planner

    @staticmethod
    def _urls_in_request(request: str) -> list[str]:
        raw_urls = re.findall(r"https?://\S+", request, re.IGNORECASE)
        return list(dict.fromkeys(
            url.rstrip(".,;:!?)]}")
            for url in raw_urls
        ))

    @classmethod
    def _research_requested(cls, normalized: str) -> bool:
        return any(
            phrase in normalized for phrase in cls._RESEARCH_PHRASES
        )

    @staticmethod
    def _search_query(request: str, normalized: str) -> str:
        error_match = re.search(
            r"\b[A-Za-z][A-Za-z0-9_]*(?:Error|Exception)\b",
            request,
        )
        if error_match:
            return (
                f"official documentation {error_match.group(0)} "
                "Python errno ECONNREFUSED Linux connect system call"
            )

        service_name = RuleBasedPlanner._explicit_service_name_from_request(
            request
        )
        if service_name:
            return (
                f"official systemd documentation {service_name} "
                "service status logs troubleshooting"
            )

        if RuleBasedPlanner._looks_like_disk_pressure(normalized):
            return "official Linux documentation filesystem disk space troubleshooting"

        if RuleBasedPlanner._contains_any(
            normalized, ("cpu", "memory", "ram", "swap", "performance", "bo nho")
        ):
            return "official Linux documentation CPU memory performance troubleshooting"

        if RuleBasedPlanner._contains_any(
            normalized, ("network", "internet", "wifi", "dns", "gateway", "mang")
        ):
            return "official Linux documentation network DNS connectivity troubleshooting"

        if RuleBasedPlanner._contains_any(
            normalized, ("security", "permission", "firewall", "bao mat", "quyen")
        ):
            return "official Linux documentation security permissions troubleshooting"

        if RuleBasedPlanner._contains_any(
            normalized, ("log", "journal", "error", "exception", "loi", "nhat ky")
        ):
            return "official Linux documentation system journal error troubleshooting"

        return "official Linux documentation troubleshooting"

    def create_plan(
        self,
        user_request: str,
        available_tools: Sequence[ToolSpec],
    ) -> AgentPlan:
        normalized = RuleBasedPlanner._normalize_request(user_request)
        urls = self._urls_in_request(user_request)
        service_name = RuleBasedPlanner._explicit_service_name_from_request(
            user_request
        )
        research_requested = self._research_requested(normalized)

        complex_request = (
            len(urls) > 1
            or any(
                phrase in normalized
                for phrase in self._COMPLEX_PHRASES
            )
        )
        local_action_requested = any(
            phrase in normalized
            for phrase in (
                "check", "inspect", "investigate", "diagnose",
                "probe", "measure", "collect evidence", "local evidence",
                "check status", "check logs", "inspect logs", "read logs",
                "kiem tra", "dieu tra", "chan doan",
                "thu thap bang chung", "kiem tra trang thai",
                "kiem tra ket noi", "kiem tra tai nguyen",
                "doc log", "doc nhat ky", "xem trang thai",
            )
        )
        local_topic_requested = any(
            phrase in normalized
            for phrase in self._LOCAL_INTENT_PHRASES
        )

        # A search request mentioning a topic such as DNS is not by itself
        # a request to inspect the local machine.
        web_only_request = (
            research_requested
            and not urls
            and not local_action_requested
        )
        local_action_requested = any(
            phrase in normalized
            for phrase in (
                "check", "inspect", "investigate", "diagnose",
                "probe", "measure", "collect evidence", "local evidence",
                "check status", "check logs", "inspect logs", "read logs",
                "kiem tra", "dieu tra", "chan doan",
                "thu thap bang chung", "kiem tra trang thai",
                "kiem tra ket noi", "kiem tra tai nguyen",
                "doc log", "doc nhat ky", "xem trang thai",
            )
        )
        local_topic_requested = any(
            phrase in normalized
            for phrase in self._LOCAL_INTENT_PHRASES
        )
        web_only_request = (
            research_requested
            and not urls
            and service_name is None
            and not local_action_requested
        )
        clear_local_intent = (
            len(urls) == 1
            or (
                not web_only_request
                and (
                    service_name is not None
                    or (
                        local_topic_requested
                        and (
                            local_action_requested
                            or not research_requested
                        )
                    )
                )
            )
        )

        # Explicit multi-URL diagnostics can be planned deterministically.
        # Keep web-research requests on their existing path.
        if len(urls) > 1 and not research_requested:
            available_names = {
                spec.name
                for spec in available_tools
                if not spec.changes_system
            }
            max_steps = max(1, self._config.agent.max_steps)

            # Prioritize one HTTP probe per explicit URL so endpoint
            # comparisons do not depend on LLM-generated JSON.
            endpoint_steps = [
                PlanStep(
                    "check_http_endpoint",
                    {"url": url},
                    f"Check explicitly supplied endpoint {url} using a read-only HTTP request",
                )
                for url in urls
                if "check_http_endpoint" in available_names
            ]

            # TCP probes follow the HTTP probes and use only the remaining
            # step budget. Never invent a host, port, or service.
            tcp_steps = []
            if "check_tcp_connectivity" in available_names:
                for url in urls:
                    parsed_url = urlsplit(url)
                    host = parsed_url.hostname
                    try:
                        port = parsed_url.port
                    except ValueError:
                        continue

                    if port is None:
                        port = (
                            443
                            if parsed_url.scheme.casefold() == "https"
                            else 80
                        )

                    if host and 1 <= port <= 65535:
                        tcp_steps.append(
                            PlanStep(
                                "check_tcp_connectivity",
                                {"host": host, "port": port},
                                f"Check TCP connectivity for explicitly supplied endpoint {url}",
                            )
                        )

            steps = (endpoint_steps + tcp_steps)[:max_steps]
            if steps:
                rationale = (
                    "Deterministic multi-endpoint plan: prioritize a "
                    "read-only HTTP probe for each supplied URL, then add "
                    "TCP probes within the configured step budget."
                )
                if len(endpoint_steps) > max_steps:
                    rationale += (
                        f" The configured max_steps={max_steps} is smaller "
                        "than the number of URLs, so not every endpoint "
                        "can be checked in this run."
                    )

                return AgentPlan(
                    steps=tuple(steps),
                    rationale=rationale,
                )

        # Let the LLM handle ambiguous or explicitly comparative/multi-system tasks.
        if complex_request or (
            not clear_local_intent and not research_requested
        ):
            return self._llm_planner.create_plan(
                user_request, available_tools
            )

        if clear_local_intent:
            base_plan = self._rule_planner.create_plan(
                user_request, available_tools
            )
            steps = list(base_plan.steps)
            rationale = base_plan.rationale
        else:
            steps = []
            rationale = (
                "External research request routed directly to the registered "
                "read-only web-search tool."
            )

        available_names = {
            spec.name
            for spec in available_tools
            if not spec.changes_system
        }
        max_steps = max(1, self._config.agent.max_steps)

        if research_requested:
            if "tavily_web_search" not in available_names:
                rationale += (
                    " Tavily search was requested but is not available "
                    "in the registered tool catalog."
                )
            elif not any(
                step.tool_name == "tavily_web_search" for step in steps
            ):
                search_step = PlanStep(
                    "tavily_web_search",
                    {"query": self._search_query(user_request, normalized)},
                    "Find external documentation; do not treat it as local evidence",
                )

                # Reserve a step for Tavily only if the configured budget allows
                # both local evidence collection and external search.
                if not clear_local_intent:
                    steps = [search_step]
                elif max_steps >= 2:
                    if len(steps) >= max_steps:
                        steps = steps[:max_steps - 1]
                    steps.append(search_step)
                else:
                    rationale += (
                        " Tavily was not added because max_steps=1 cannot "
                        "include both local diagnosis and external research."
                    )

        return AgentPlan(
            steps=tuple(steps[:max_steps]),
            rationale=rationale,
        )


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
        self._llm_client: LLMClient | None = None
        self._fallback_planner: RuleBasedPlanner | None = None

        if planner is not None:
            # Explicitly injected planners remain available for tests/integrations.
            self.planner = planner
        elif config.llm.enabled and config.llm.planning_mode == "llm":
            llm_client = OpenAICompatibleLLMClient(config.llm)
            rule_planner = RuleBasedPlanner(config)
            self.planner = HybridPlanner(
                config=config,
                rule_planner=rule_planner,
                llm_planner=llm_client,
            )
            if config.llm.summary_enabled:
                self._llm_client = llm_client
            if config.llm.fallback_to_rules:
                self._fallback_planner = rule_planner
        else:
            rule_planner = RuleBasedPlanner(config)
            self.planner = rule_planner
            if config.llm.enabled and config.llm.summary_enabled:
                self._llm_client = OpenAICompatibleLLMClient(config.llm)

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

        available_tools = [
            spec for spec in self.registry.list_tools() if not spec.changes_system
        ]
        used_rule_fallback = False
        try:
            plan = self.planner.create_plan(context.user_request, available_tools)
            if not isinstance(plan, AgentPlan):
                raise TypeError("Planner must return an AgentPlan")
        except Exception as exc:  # noqa: BLE001
            if self._fallback_planner is None:
                context.status = "failed"
                context.findings.append(f"Planning failed: {type(exc).__name__}.")
                self._record_event(
                    "incident.planning_failed",
                    context,
                    {"error_type": type(exc).__name__},
                )
                self._record_final(context)
                return context

            # Fallback is deterministic and read-only. Do not include exception text,
            # because provider errors can contain sensitive request metadata.
            used_rule_fallback = True
            planning_error_type = type(exc)
            planning_safe_detail = ""
            if (
                planning_error_type.__module__ == "linux_admin.llm_client"
                and planning_error_type.__name__ == "LLMClientError"
            ):
                error_message = str(exc)
                if error_message.startswith("LLM request timed out after "):
                    timeout = error_message.removeprefix("LLM request timed out after ").removesuffix(" seconds")
                    if timeout.replace(".", "", 1).isdigit():
                        planning_safe_detail = f" Detail: LLM request timed out after {timeout} seconds."
                elif error_message.startswith("LLM API returned HTTP "):
                    http_code = error_message.removeprefix("LLM API returned HTTP ").split(";", 1)[0].strip()
                    if http_code.isdigit() and len(http_code) == 3:
                        planning_safe_detail = f" Detail: LLM provider returned HTTP {http_code}."
                elif error_message in (
                    "Could not connect to the configured LLM endpoint",
                    "LLM network request failed",
                ):
                    planning_safe_detail = " Detail: LLM network connection failed."
                elif error_message in (
                    "LLM response had an unsupported format",
                    "LLM response content must be a string",
                    "LLM returned malformed JSON for its plan",
                    "LLM plan must be a JSON object",
                    "LLM plan must contain string rationale and list steps",
                ):
                    planning_safe_detail = " Detail: LLM returned an invalid response or plan."
            context.findings.append(
                f"LLM planning was unavailable ({planning_error_type.__name__}); "
                f"using the configured rule-based read-only fallback.{planning_safe_detail}"
            )
            if not self._record_event(
                "incident.llm_fallback",
                context,
                {"phase": "planning", "error_type": type(exc).__name__},
            ):
                context.status = "failed"
                context.findings.append(
                    "Audit failed while recording the LLM fallback; "
                    "no tools were invoked."
                )
                self._record_final(context)
                return context
            try:
                plan = self._fallback_planner.create_plan(
                    context.user_request, available_tools
                )
                if not isinstance(plan, AgentPlan):
                    raise TypeError("Fallback planner must return an AgentPlan")
            except Exception as fallback_exc:  # noqa: BLE001
                context.status = "failed"
                context.findings.append(
                    f"Rule-based fallback failed: {type(fallback_exc).__name__}."
                )
                self._record_event(
                    "incident.planning_failed",
                    context,
                    {"error_type": type(fallback_exc).__name__},
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
        pending_steps = list(selected_steps)
        executed_steps: list[PlanStep] = []
        executed_keys: set[tuple[str, str]] = set()

        while pending_steps and context.steps < self.config.agent.max_steps:
            step = pending_steps.pop(0)
            step_key = self._step_identity(step)
            # Execute explicitly planned steps, including repetitions, up to
            # max_steps. Adaptive follow-ups are de-duplicated by candidate().
            executed_keys.add(step_key)
            executed_steps.append(step)
            context.steps += 1

            spec = self.registry.get_spec(step.tool_name)
            if spec is None:
                result = ToolResult(
                    tool_name=step.tool_name,
                    status="failed",
                    error="Planned tool is not registered",
                )
            elif spec.changes_system:
                # Defense in depth: investigation may only invoke read-only tools.
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

            # A systemd unit reported as not-found cannot provide useful
            # current unit logs. Skip only queued log checks for that exact unit.
            if (
                result.tool_name == "get_service_status"
                and result.ok
                and result.data.get("load_state") == "not-found"
            ):
                service_name = result.data.get("service_name")
                if isinstance(service_name, str) and service_name:
                    previous_pending_count = len(pending_steps)
                    pending_steps = [
                        pending_step
                        for pending_step in pending_steps
                        if not (
                            pending_step.tool_name == "get_service_logs"
                            and pending_step.arguments.get("service_name")
                            == service_name
                        )
                    ]
                    skipped_log_count = (
                        previous_pending_count - len(pending_steps)
                    )

                    if skipped_log_count:
                        audit_ok = self._record_event(
                            "incident.plan_step_skipped",
                            context,
                            {
                                "trigger_tool": result.tool_name,
                                "reason": "systemd_unit_not_found",
                                "skipped_tool": "get_service_logs",
                                "service_name": service_name,
                                "skipped_count": skipped_log_count,
                            },
                        )
                        if not audit_ok:
                            audit_failed = True
                            context.findings.append(
                                "Audit persistence failed while recording "
                                "a skipped service-log check; processing stopped."
                            )
                            break

                        context.findings.append(
                            f"Skipped {skipped_log_count} queued "
                            f"get_service_logs check(s) for {service_name}: "
                            "systemd reported load_state=not-found."
                        )

            follow_up = self._choose_adaptive_follow_up(
                result=result,
                evidence=context.evidence,
                executed_steps=executed_steps,
                pending_steps=pending_steps,
                available_tools=available_tools,
            )
            if follow_up is not None:
                if not self._record_event(
                    "incident.follow_up_planned",
                    context,
                    {
                        "trigger_tool": result.tool_name,
                        "trigger_status": result.status,
                        "follow_up_tool": follow_up.tool_name,
                        "arguments": dict(follow_up.arguments),
                        "purpose": follow_up.purpose,
                    },
                ):
                    audit_failed = True
                    context.findings.append(
                        "Audit persistence failed while recording adaptive follow-up; "
                        "no further tool was invoked."
                    )
                    break

                pending_steps.insert(0, follow_up)
                context.findings.append(
                    f"Adaptive follow-up selected: {follow_up.tool_name} — "
                    f"{follow_up.purpose}."
                )

        if pending_steps and context.steps >= self.config.agent.max_steps:
            context.findings.append(
                "Investigation reached the configured max_steps limit; "
                "some queued diagnostic checks were not run."
            )

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

        # Add a deterministic, evidence-based diagnosis. This layer does not call
        # the LLM and never executes commands or changes system state.
        if context.evidence:
            diagnostic_report = diagnose_incident(
                context.user_request,
                context.evidence,
            )
            context.findings.extend(diagnostic_report.to_findings())

        # When the real LLM planned the investigation, send bounded tool evidence
        # back for synthesis. A summary failure must be visible and must not erase
        # the local evidence collected during the investigation.
        if (
            context.status == "completed"
            and self._llm_client is not None
            and not used_rule_fallback
        ):
            try:
                executed_plan = AgentPlan(
                    steps=tuple(executed_steps), rationale=plan.rationale
                )
                summary = self._llm_client.summarize(
                    context.user_request, executed_plan, context.evidence
                )
                context.findings.append(f"LLM analysis: {summary}")
                audit_ok = self._record_event(
                    "incident.llm_summary_completed",
                    context,
                    {
                        "model": self.config.llm.model,
                        "summary_characters": len(summary),
                        "evidence_count": len(context.evidence),
                    },
                )
                if not audit_ok:
                    context.status = "failed"
                    context.findings.append(
                        "Audit failed while recording the LLM analysis; "
                        "report audit failure."
                    )
            except Exception as exc:  # noqa: BLE001
                error_type = type(exc)
                safe_detail = ""
                if (
                    error_type.__module__ == "linux_admin.llm_client"
                    and error_type.__name__ == "LLMClientError"
                ):
                    safe_detail = f" Detail: {exc}."

                if self.config.llm.fallback_to_rules:
                    context.findings.append(
                        f"LLM evidence analysis failed ({error_type.__name__}); "
                        "using the deterministic tool findings instead. "
                        f"No LLM diagnosis was produced.{safe_detail}"
                    )
                else:
                    context.findings.append(
                        f"LLM evidence analysis failed ({error_type.__name__}); "
                        "the collected tool evidence remains available, but no "
                        f"LLM diagnosis was produced.{safe_detail}"
                    )
                if not self._record_event(
                    "incident.llm_summary_failed",
                    context,
                    {"error_type": type(exc).__name__},
                ):
                    context.status = "failed"
                    context.findings.append(
                        "Audit failed while recording the LLM analysis failure."
                    )

        self._record_final(context)
        return context

    @staticmethod
    def _step_identity(step: PlanStep) -> tuple[str, str]:
        """Create a stable identity for de-duplicating bounded tool calls."""
        return (
            step.tool_name,
            json.dumps(
                dict(step.arguments),
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ),
        )

    def _choose_adaptive_follow_up(
        self,
        *,
        result: ToolResult,
        evidence: Sequence[ToolResult],
        executed_steps: Sequence[PlanStep],
        pending_steps: Sequence[PlanStep],
        available_tools: Sequence[ToolSpec],
    ) -> PlanStep | None:
        """Select one evidence-driven, read-only next step when useful."""
        available = {
            spec.name for spec in available_tools if not spec.changes_system
        }
        executed_keys = {
            self._step_identity(step) for step in executed_steps
        }
        pending_keys = {
            self._step_identity(step) for step in pending_steps
        }

        def candidate(
            name: str,
            arguments: dict,
            purpose: str,
        ) -> PlanStep | None:
            if name not in available:
                return None
            step = PlanStep(name, arguments, purpose)
            identity = self._step_identity(step)
            if identity in executed_keys or identity in pending_keys:
                return None
            return step

        def is_loopback(host: object) -> bool:
            value = str(host or "").strip().strip("[]").casefold()
            return (
                value == "localhost"
                or value == "::1"
                or value.startswith("127.")
            )

        # If systemd reports failed units, inspect the first unit not already
        # covered by the current plan. The result decides whether logs are useful.
        if result.tool_name == "get_failed_services" and result.ok:
            raw_units = result.data.get("failed_services", [])
            if isinstance(raw_units, list):
                for raw_unit in raw_units[:5]:
                    if not isinstance(raw_unit, str) or not raw_unit.strip():
                        continue
                    unit = raw_unit.strip()
                    status_step = candidate(
                        "get_service_status",
                        {"service_name": unit},
                        f"Inspect reported failed unit {unit}",
                    )
                    if status_step is not None:
                        return status_step

                    matching_status = None
                    for step, tool_result in zip(executed_steps, evidence):
                        if (
                            step.tool_name == "get_service_status"
                            and step.arguments.get("service_name") == unit
                        ):
                            matching_status = tool_result
                            break

                    if (
                        matching_status is not None
                        and matching_status.ok
                        and matching_status.data.get("active_state") == "failed"
                    ):
                        log_step = candidate(
                            "get_service_logs",
                            {"service_name": unit},
                            f"Inspect recent logs for failed unit {unit}",
                        )
                        if log_step is not None:
                            return log_step

        # A failed status result can also trigger targeted logs if no matching
        # log check is already queued.
        if (
            result.tool_name == "get_service_status"
            and result.ok
            and result.data.get("active_state") == "failed"
        ):
            unit = result.data.get("service_name")
            if isinstance(unit, str) and unit.strip():
                log_step = candidate(
                    "get_service_logs",
                    {"service_name": unit},
                    f"Inspect recent logs for failed unit {unit}",
                )
                if log_step is not None:
                    return log_step

        # A refused TCP connection to loopback calls for local listener inspection,
        # rather than assuming that DNS or the Internet is the cause.
        if (
            result.tool_name == "check_tcp_connectivity"
            and result.data.get("reachable") is False
        ):
            host = result.data.get("host")
            port = result.data.get("port")
            if (
                is_loopback(host)
                and isinstance(port, int)
                and not isinstance(port, bool)
                and 1 <= port <= 65535
            ):
                return candidate(
                    "inspect_listening_port",
                    {"port": port},
                    f"Inspect local listeners for refused endpoint port {port}",
                )

            if result.status == "timeout":
                return candidate(
                    "get_network_state",
                    {},
                    "Inspect local interfaces after a TCP timeout",
                )

        # If the loopback listener query shows no listener, finish any already
        # planned endpoint/service checks before collecting generic journal context.
        if (
            result.tool_name == "inspect_listening_port"
            and result.ok
            and isinstance(result.data.get("listeners"), list)
            and not result.data["listeners"]
        ):
            pending_primary = {
                "check_tcp_connectivity",
                "check_http_endpoint",
                "get_service_status",
                "get_service_logs",
                "get_recent_errors",
            }
            if not any(step.tool_name in pending_primary for step in pending_steps):
                return candidate(
                    "get_recent_errors",
                    {"lines": 50, "since_minutes": 60},
                    "Collect recent system errors after finding no local listener",
                )

        # Once an HTTP probe confirms that a loopback endpoint is unavailable,
        # use the earlier socket evidence to decide whether journal context is useful.
        if (
            result.tool_name == "check_http_endpoint"
            and result.data.get("reachable") is False
        ):
            host = result.data.get("host")
            port = result.data.get("port")
            if isinstance(port, int) and not isinstance(port, bool) and is_loopback(host):
                no_listener_found = any(
                    step.tool_name == "inspect_listening_port"
                    and step.arguments.get("port") == port
                    and tool_result.ok
                    and isinstance(tool_result.data.get("listeners"), list)
                    and not tool_result.data["listeners"]
                    for step, tool_result in zip(executed_steps, evidence)
                )
                pending_specific_checks = {
                    "check_tcp_connectivity",
                    "check_http_endpoint",
                    "get_service_status",
                    "get_service_logs",
                    "get_recent_errors",
                }
                if no_listener_found and not any(
                    step.tool_name in pending_specific_checks
                    for step in pending_steps
                ):
                    return candidate(
                        "get_recent_errors",
                        {"lines": 50, "since_minutes": 60},
                        "Collect recent system errors after an unavailable local endpoint",
                    )

            if result.status == "timeout":
                return candidate(
                    "get_network_state",
                    {},
                    "Inspect local interfaces after an HTTP timeout",
                )

        return None

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
        except Exception:  # noqa: BLE001
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

        if result.tool_name == "get_service_status":
            data = result.data
            service_name = data.get("service_name", "unknown")
            load_state = data.get("load_state", "unknown")
            active_state = data.get("active_state", "unknown")
            sub_state = data.get("sub_state", "unknown")

            # LoadState takes precedence: systemd may report ActiveState=inactive
            # for a unit that it did not find.
            if load_state == "not-found":
                return (
                    f"get_service_status: success; service '{service_name}' "
                    "was not found by systemd (load_state=not-found)."
                )

            if active_state == "active":
                return (
                    f"get_service_status: success; service '{service_name}' "
                    f"is active ({sub_state})."
                )

            if active_state == "failed":
                return (
                    f"get_service_status: success; service '{service_name}' "
                    "is in failed state; inspect its logs and execution result "
                    "to investigate the cause."
                )

            if active_state == "inactive":
                service_type = data.get("service_type", "unknown")
                last_result = data.get("result", "unknown")
                exit_status = str(data.get("exec_main_status", "unknown"))
                remain_after_exit = data.get("remain_after_exit", "unknown")
                success_evidence = (
                    last_result == "success" and exit_status == "0"
                )
                if success_evidence:
                    detail = (
                        "systemd reports the last execution result as success "
                        "with exit status 0"
                    )
                else:
                    detail = (
                        f"last_result={last_result}, "
                        f"exec_main_status={exit_status}"
                    )
                return (
                    f"get_service_status: success; service '{service_name}' "
                    f"is currently inactive ({sub_state}); type={service_type}; "
                    f"{detail}; remain_after_exit={remain_after_exit}. "
                    "Inactive state alone does not establish a failure."
                )

            highlights = [
                f"load_state={load_state!r}",
                f"active_state={active_state!r}",
                f"sub_state={sub_state!r}",
            ]
            return (
                f"get_service_status: success; service '{service_name}'; "
                + "; ".join(highlights)
                + ". State is not classified; inspect the returned evidence."
            )

        highlights: list[str] = []
        preferred_keys = (
            "load_state",
            "active_state",
            "sub_state",
            "is_active",
            "service_type",
            "result",
            "exec_main_code",
            "exec_main_status",
            "remain_after_exit",
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
