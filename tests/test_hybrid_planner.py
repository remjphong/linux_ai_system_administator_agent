"""Offline tests for routing clear tasks through the hybrid planner."""

from linux_admin.agent import HybridPlanner, RuleBasedPlanner
from linux_admin.contracts import ToolSpec
from linux_admin.llm_client import AgentPlan


class FakeLLMPlanner:
    def __init__(self):
        self.calls = 0

    def create_plan(self, user_request, available_tools):
        del user_request, available_tools
        self.calls += 1
        return AgentPlan(steps=(), rationale="Fake LLM plan")


def _tools(include_tavily=True):
    specs = [
        ToolSpec("check_tcp_connectivity", "Check TCP connectivity"),
        ToolSpec(
            "check_http_endpoint",
            "Check an explicit HTTP endpoint",
            parameters={
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
                "additionalProperties": False,
            },
        ),
        ToolSpec(
            "get_service_status",
            "Read systemd unit status",
            parameters={
                "type": "object",
                "properties": {"service_name": {"type": "string"}},
                "required": ["service_name"],
                "additionalProperties": False,
            },
        ),
        ToolSpec(
            "get_service_logs",
            "Read a service journal",
            parameters={
                "type": "object",
                "properties": {"service_name": {"type": "string"}},
                "required": ["service_name"],
                "additionalProperties": False,
            },
        ),
        ToolSpec("get_failed_services", "List failed systemd services"),
        ToolSpec("get_recent_errors", "Read recent system errors"),
        ToolSpec("get_system_overview", "Read CPU and memory metrics"),
        ToolSpec(
            "list_top_processes",
            "List processes by memory usage",
            parameters={
                "type": "object",
                "properties": {"limit": {"type": "integer"}},
                "required": [],
                "additionalProperties": False,
            },
        ),
        ToolSpec(
            "get_disk_usage",
            "Read filesystem capacity",
            parameters={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
                "additionalProperties": False,
            },
        ),
        ToolSpec("get_network_state", "Read local network interfaces"),
        ToolSpec("inspect_security_posture", "Read security posture"),
    ]

    if include_tavily:
        specs.append(
            ToolSpec(
                "tavily_web_search",
                "Search public web references",
                parameters={
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                    "additionalProperties": False,
                },
            )
        )

    return specs


def _hybrid(app_config, include_tavily=True):
    llm = FakeLLMPlanner()
    rules = RuleBasedPlanner(app_config)
    hybrid = HybridPlanner(app_config, rules, llm)
    return hybrid, llm, _tools(include_tavily)


def test_single_endpoint_and_requested_research_use_hybrid_fast_path(
    app_config,
):
    planner, llm, tools = _hybrid(app_config)

    plan = planner.create_plan(
        "Kiểm tra endpoint HTTP http://127.0.0.1:1/. "
        "Tra cứu tài liệu chính thức về ConnectionRefusedError bằng Tavily.",
        tools,
    )

    names = [step.tool_name for step in plan.steps]
    assert "check_http_endpoint" in names
    assert "tavily_web_search" in names
    assert llm.calls == 0

    http_step = next(
        step for step in plan.steps
        if step.tool_name == "check_http_endpoint"
    )
    search_step = next(
        step for step in plan.steps
        if step.tool_name == "tavily_web_search"
    )
    assert http_step.arguments["url"] == "http://127.0.0.1:1/"
    assert "ConnectionRefusedError" in search_step.arguments["query"]


def test_clear_cpu_and_memory_request_uses_rules(app_config):
    planner, llm, tools = _hybrid(app_config)

    plan = planner.create_plan("Check CPU and memory usage", tools)

    names = {step.tool_name for step in plan.steps}
    assert "get_system_overview" in names
    assert "list_top_processes" in names
    assert llm.calls == 0


def test_explicit_service_status_and_logs_use_rules(app_config):
    planner, llm, tools = _hybrid(app_config)

    plan = planner.create_plan(
        "Check status and logs for nginx.service",
        tools,
    )

    names = [step.tool_name for step in plan.steps]
    assert "get_service_status" in names
    assert "get_service_logs" in names
    assert llm.calls == 0


def test_multiple_urls_are_delegated_to_llm(app_config):
    planner, llm, tools = _hybrid(app_config)

    plan = planner.create_plan(
        "Compare http://127.0.0.1:1/ and http://127.0.0.1:2/",
        tools,
    )

    assert plan.rationale == "Fake LLM plan"
    assert llm.calls == 1


def test_web_only_request_uses_tavily_without_llm(app_config):
    planner, llm, tools = _hybrid(app_config)

    plan = planner.create_plan(
        "Search the web for official documentation about Linux DNS troubleshooting",
        tools,
    )

    assert [step.tool_name for step in plan.steps] == ["tavily_web_search"]
    assert llm.calls == 0


def test_tavily_not_registered_is_not_added_to_plan(app_config):
    planner, llm, tools = _hybrid(app_config, include_tavily=False)

    plan = planner.create_plan(
        "Check http://127.0.0.1:1/ and search official documentation.",
        tools,
    )

    assert "tavily_web_search" not in {
        step.tool_name for step in plan.steps
    }
    assert "not available" in plan.rationale
    assert llm.calls == 0
