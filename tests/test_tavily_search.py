"""Offline tests for the optional Tavily web-search tool."""

from __future__ import annotations

import json
from dataclasses import replace

from linux_admin.config import AppConfig
from linux_admin.registry import ToolRegistry
from linux_admin.tools import register_builtin_tools
from linux_admin.tools.tavily_search import TavilyWebSearchTool


def test_tavily_search_returns_bounded_results_and_marks_them_untrusted(
    app_config: AppConfig, monkeypatch
) -> None:
    settings = replace(
        app_config.tavily,
        enabled=True,
        api_key="tvly-unit-test-key",
        timeout_seconds=2.0,
        max_results=2,
    )
    tool = TavilyWebSearchTool(settings)
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self, limit: int) -> bytes:
            assert limit > 0
            return json.dumps(
                {
                    "results": [
                        {
                            "title": "systemd official manual",
                            "url": (
                                "https://www.freedesktop.org/software/systemd/man/"
                                "latest/systemctl.html"
                            ),
                            "content": "Use systemctl to inspect a service.",
                            "score": 0.92,
                        },
                        {
                            "title": "second result",
                            "url": "https://example.com/docs",
                            "content": "Reference text",
                            "score": 0.5,
                        },
                        {
                            "title": "extra result should not appear",
                            "url": "https://example.com/extra",
                            "content": "extra",
                            "score": 0.1,
                        },
                    ]
                }
            ).encode()

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["authorization"] = request.get_header("Authorization")
        captured["timeout"] = timeout
        captured["payload"] = json.loads(request.data.decode())
        return FakeResponse()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    result = tool.execute(query="official systemd service documentation", max_results=2)

    assert result.ok is True
    assert result.data["result_count"] == 2
    assert result.data["untrusted_external_content"] is True
    assert captured["url"] == "https://api.tavily.com/search"
    assert captured["authorization"] == "Bearer tvly-unit-test-key"
    assert captured["payload"]["query"] == "official systemd service documentation"
    assert captured["payload"]["max_results"] == 2


def test_tavily_invalid_query_does_not_call_network(
    app_config: AppConfig, monkeypatch
) -> None:
    settings = replace(app_config.tavily, enabled=True, api_key="tvly-unit-test-key")
    tool = TavilyWebSearchTool(settings)

    def unexpected_network(*args, **kwargs):
        raise AssertionError("network must not be called for invalid input")

    monkeypatch.setattr("urllib.request.urlopen", unexpected_network)
    result = tool.execute(query="x")
    assert result.status == "invalid_input"


def test_tavily_tool_is_registered_only_when_enabled(app_config: AppConfig) -> None:
    disabled_config = replace(
        app_config,
        tavily=replace(app_config.tavily, enabled=False),
    )
    disabled_registry = register_builtin_tools(ToolRegistry(), disabled_config)
    assert disabled_registry.get_spec("tavily_web_search") is None

    enabled_config = replace(
        app_config,
        tavily=replace(app_config.tavily, enabled=True, api_key="tvly-unit-test-key"),
    )
    enabled_registry = register_builtin_tools(ToolRegistry(), enabled_config)
    assert enabled_registry.get_spec("tavily_web_search") is not None
