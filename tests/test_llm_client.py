"""Offline tests for the real LLM adapter and structured plan validation."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any

import pytest

from linux_admin.agent import Agent
from linux_admin.config import AppConfig
from linux_admin.contracts import ToolSpec
from linux_admin.llm_client import (
    AgentPlan,
    LLMClientError,
    OpenAICompatibleLLMClient,
    PlanStep,
)


def _client(app_config: AppConfig) -> OpenAICompatibleLLMClient:
    settings = replace(
        app_config.llm,
        enabled=True,
        provider="openai_compatible",
        model="test-model",
        api_key="unit-test-key",
        base_url="https://llm.example/v1",
        timeout_seconds=1,
        max_output_tokens=256,
    )
    return OpenAICompatibleLLMClient(settings)


def test_llm_client_parses_plan_for_registered_read_only_tools(app_config) -> None:
    client = _client(app_config)
    tools = [
        ToolSpec(
            name="get_service_status",
            description="Read service status",
            parameters={
                "type": "object",
                "properties": {"service_name": {"type": "string"}},
                "required": ["service_name"],
                "additionalProperties": False,
            },
        )
    ]
    response = json.dumps(
        {
            "rationale": "Inspect the service state first.",
            "steps": [
                {
                    "tool_name": "get_service_status",
                    "arguments": {"service_name": "demo-web.service"},
                    "purpose": "Check whether the unit is active.",
                }
            ],
        }
    )
    plan = client._parse_plan(response, tools)

    assert plan.rationale == "Inspect the service state first."
    assert len(plan.steps) == 1
    assert plan.steps[0].tool_name == "get_service_status"

def test_select_relevant_tools_for_endpoint_request(app_config) -> None:
    client_config = replace(
        app_config.llm,
        enabled=True,
        model="qwen-test",
        base_url="http://127.0.0.1:11434/v1",
    )
    client = OpenAICompatibleLLMClient(client_config)

    tools = [
        ToolSpec(
            name="check_tcp_connectivity",
            description="Check TCP connectivity",
        ),
        ToolSpec(
            name="check_http_endpoint",
            description="Check an HTTP endpoint",
        ),
        ToolSpec(
            name="get_service_status",
            description="Read service status",
        ),
        ToolSpec(
            name="restart_service",
            description="Restart a service",
            risk_level="high",
            changes_system=True,
            requires_approval=True,
        ),
    ]

    selected = client._select_relevant_tools(
        "Check whether http://127.0.0.1:11434/ is reachable",
        tools,
    )

    assert {tool.name for tool in selected} == {
        "check_tcp_connectivity",
        "check_http_endpoint",
    }
    assert all(not tool.changes_system for tool in selected)


def test_llm_client_rejects_unregistered_or_state_changing_tool(app_config) -> None:
    client = _client(app_config)
    tools = [
        ToolSpec(
            name="restart_service",
            description="Restart a service",
            parameters={
                "type": "object",
                "properties": {"service_name": {"type": "string"}},
                "required": ["service_name"],
            },
            risk_level="high",
            changes_system=True,
            requires_approval=True,
        )
    ]
    response = json.dumps(
        {
            "rationale": "Try restarting the service.",
            "steps": [
                {
                    "tool_name": "restart_service",
                    "arguments": {"service_name": "demo-web.service"},
                }
            ],
        }
    )

    with pytest.raises(LLMClientError, match="not in the read-only tool catalog"):
        client._parse_plan(response, tools)


def test_llm_client_rejects_malformed_plan_json(app_config) -> None:
    client = _client(app_config)
    with pytest.raises(LLMClientError, match="malformed JSON"):
        client._parse_plan("not json", [])


def test_llm_client_sends_chat_completion_request_and_parses_response(
    app_config, monkeypatch
) -> None:
    client = _client(app_config)
    seen: dict[str, Any] = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self, limit: int) -> bytes:
            assert limit > 0
            return json.dumps(
                {"choices": [{"message": {"content": "hello from test"}}]}
            ).encode()

    def fake_urlopen(request, timeout):
        seen["url"] = request.full_url
        seen["timeout"] = timeout
        seen["authorization"] = request.get_header("Authorization")
        seen["payload"] = json.loads(request.data.decode())
        return FakeResponse()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    assert client._chat("system", "user") == "hello from test"
    assert seen["url"] == "https://llm.example/v1/chat/completions"
    assert seen["authorization"] == "Bearer unit-test-key"
    assert seen["payload"]["model"] == "test-model"
    assert seen["timeout"] == 1


def test_agent_uses_configured_llm_and_summarizes_evidence(
    app_config, audit_logger, registry_factory, monkeypatch
) -> None:
    settings = replace(
        app_config.llm,
        enabled=True,
        provider="openai_compatible",
        model="test-model",
        api_key="unit-test-key",
        base_url="https://llm.example/v1",
        fallback_to_rules=False,
        planning_mode="llm",
        summary_enabled=True,
    )
    llm_config = replace(app_config, llm=settings)

    class FakeConfiguredLLM:
        def __init__(self, unused_settings) -> None:
            del unused_settings

        def create_plan(self, user_request, available_tools):
            del user_request, available_tools
            return AgentPlan(
                steps=(
                    PlanStep(
                        "get_service_status",
                        {"service_name": "demo-web.service"},
                    ),
                ),
                rationale="Planned by test LLM",
            )

        def summarize(self, user_request, plan, evidence):
            assert user_request
            assert plan.steps
            assert evidence
            return "The service is inactive based on the observed evidence."

    monkeypatch.setattr(
        "linux_admin.agent.OpenAICompatibleLLMClient", FakeConfiguredLLM
    )
    incident = Agent(
        registry=registry_factory(), config=llm_config, audit=audit_logger
    ).run("Why is the web service not working?")

    assert incident.status == "completed"
    assert any("LLM analysis:" in item for item in incident.findings)
    assert any("inactive" in item for item in incident.findings)


def test_agent_falls_back_to_rules_when_llm_planning_fails(
    app_config, audit_logger, registry_factory, monkeypatch
) -> None:
    settings = replace(
        app_config.llm,
        enabled=True,
        provider="openai_compatible",
        model="test-model",
        api_key="unit-test-key",
        base_url="https://llm.example/v1",
        fallback_to_rules=True,
        planning_mode="llm",
    )
    llm_config = replace(app_config, llm=settings)

    class BrokenLLM:
        def __init__(self, unused_settings) -> None:
            del unused_settings

        def create_plan(self, user_request, available_tools):
            del user_request, available_tools
            raise LLMClientError("private provider error text should not surface")

        def summarize(self, user_request, plan, evidence):
            raise AssertionError("summary should not be retried after plan fallback")

    monkeypatch.setattr("linux_admin.agent.OpenAICompatibleLLMClient", BrokenLLM)
    incident = Agent(
        registry=registry_factory(), config=llm_config, audit=audit_logger
    ).run("Investigate service failure for demo-web.service")

    assert incident.status == "completed"
    assert any("rule-based read-only fallback" in item for item in incident.findings)
    assert not any("private provider error text" in item for item in incident.findings)


def test_llm_summary_redacts_sensitive_evidence_before_remote_send(
    app_config, monkeypatch
) -> None:
    from linux_admin.contracts import ToolResult

    client = _client(app_config)
    sent = {}

    def fake_chat(system_prompt, user_prompt, *, max_output_tokens=None):
        del system_prompt, max_output_tokens
        sent["prompt"] = user_prompt
        return "Service failed because the process exited."

    monkeypatch.setattr(client, "_chat", fake_chat)
    summary = client.summarize(
        "Investigate the web service",
        AgentPlan(
            steps=(
                PlanStep(
                    "get_service_status", {"service_name": "demo.service"}
                ),
            )
        ),
        [
            ToolResult(
                tool_name="get_service_status",
                status="success",
                data={
                    "api_key": "tvly-secret-must-not-leak",
                    "message": "password=cleartext-must-not-leak",
                },
            )
        ],
    )

    assert summary.startswith("Service failed")
    assert "tvly-secret-must-not-leak" not in sent["prompt"]
    assert "cleartext-must-not-leak" not in sent["prompt"]
    assert "[REDACTED]" in sent["prompt"]


def test_llm_timeout_is_reported_without_provider_details(
    app_config, monkeypatch
) -> None:
    client = _client(app_config)

    def timeout(*args, **kwargs):
        raise TimeoutError("private timeout metadata")

    monkeypatch.setattr("urllib.request.urlopen", timeout)
    with pytest.raises(LLMClientError, match="timed out") as captured:
        client._chat("system", "user")
    assert "private timeout metadata" not in str(captured.value)

def test_tool_selection_includes_tavily_for_external_research():
    from types import SimpleNamespace

    from linux_admin.llm_client import OpenAICompatibleLLMClient

    tools = [
        SimpleNamespace(name="get_system_overview", changes_system=False),
        SimpleNamespace(name="tavily_web_search", changes_system=False),
        SimpleNamespace(name="restart_service", changes_system=True),
    ]

    web_tools = OpenAICompatibleLLMClient._select_relevant_tools(
        "Search the web for official Ubuntu documentation",
        tools,
    )
    web_names = {tool.name for tool in web_tools}

    assert "tavily_web_search" in web_names
    assert "restart_service" not in web_names

    local_tools = OpenAICompatibleLLMClient._select_relevant_tools(
        "Check CPU usage and system performance",
        tools,
    )
    local_names = {tool.name for tool in local_tools}

    assert "get_system_overview" in local_names
    assert "tavily_web_search" not in local_names

