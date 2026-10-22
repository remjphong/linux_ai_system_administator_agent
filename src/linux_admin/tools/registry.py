
from typing import Any

from linux_admin.core.contracts import Tool, ToolResult


class ToolRegistry:
    """Quản lý các tool được đăng ký với Agent."""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"Tool already registered: {tool.name}")

        self._tools[tool.name] = tool

    def list_tools(self) -> list[str]:
        return sorted(self._tools.keys())

    def execute(self, name: str, **kwargs: Any) -> ToolResult:
        tool = self._tools.get(name)

        if tool is None:
            return ToolResult(
                success=False,
                tool_name=name,
                error="Unknown tool",
            )

        return tool.execute(**kwargs)

