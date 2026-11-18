"""Offline tests for rendering untrusted external search references."""

from linux_admin.contracts import ToolResult
from linux_admin.main import _extract_external_references


def test_extract_external_references_from_successful_tavily_result() -> None:
    evidence = [
        ToolResult(
            tool_name="check_http_endpoint",
            status="success",
            data={"url": "http://127.0.0.1:1/", "reachable": False},
        ),
        ToolResult(
            tool_name="tavily_web_search",
            status="success",
            data={
                "source": "Tavily Search API",
                "untrusted_external_content": True,
                "results": [
                    {
                        "title": "Python errno documentation",
                        "url": "https://docs.python.org/3/library/errno.html",
                        "content": "ECONNREFUSED maps to ConnectionRefusedError.",
                        "score": 0.91,
                    }
                ],
            },
        ),
    ]

    references = _extract_external_references(evidence)

    assert len(references) == 1
    assert references[0]["title"] == "Python errno documentation"
    assert references[0]["url"] == (
        "https://docs.python.org/3/library/errno.html"
    )
    assert "ECONNREFUSED" in references[0]["snippet"]
    assert references[0]["score"] == 0.91
    assert references[0]["source"] == "Tavily Search API"
    assert references[0]["untrusted_external_content"] is True


def test_external_references_skip_failed_tools_and_unsafe_urls() -> None:
    evidence = [
        ToolResult(
            tool_name="tavily_web_search",
            status="failed",
            error="Simulated search failure",
        ),
        ToolResult(
            tool_name="tavily_web_search",
            status="success",
            data={
                "results": [
                    {
                        "title": "Unsafe URL",
                        "url": "javascript:alert(1)",
                        "content": "Not a valid web reference.",
                        "score": 0.99,
                    },
                    {
                        "title": "Valid documentation",
                        "url": "https://docs.python.org/3/library/errno.html",
                        "content": "Reference text.",
                        "score": 0.8,
                    },
                    {
                        "title": "Duplicate reference",
                        "url": "https://docs.python.org/3/library/errno.html",
                        "content": "Duplicate URL.",
                        "score": 0.7,
                    },
                ]
            },
        ),
    ]

    references = _extract_external_references(evidence)

    assert len(references) == 1
    assert references[0]["title"] == "Valid documentation"
    assert references[0]["untrusted_external_content"] is True


def test_external_references_are_limited_to_five() -> None:
    results = [
        {
            "title": f"Documentation {index}",
            "url": f"https://example.com/docs/{index}",
            "content": f"Snippet {index}",
            "score": 0.5,
        }
        for index in range(8)
    ]
    evidence = [
        ToolResult(
            tool_name="tavily_web_search",
            status="success",
            data={"results": results},
        )
    ]

    references = _extract_external_references(evidence)

    assert len(references) == 5
