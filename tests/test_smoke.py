
from linux_admin.core.contracts import ToolResult
from linux_admin.tools.registry import ToolRegistry


class ExampleTool:
    name = "example"

    def execute(self, **kwargs: object) -> ToolResult:
        return ToolResult(
            success=True,
            tool_name=self.name,
            data={"message": "ok"},
        )


def test_registry_registers_and_executes_tool() -> None:
    registry = ToolRegistry()
    registry.register(ExampleTool())

    result = registry.execute("example")

    assert result.success is True
    assert result.tool_name == "example"
    assert result.data["message"] == "ok"


def test_registry_rejects_unknown_tool() -> None:
    registry = ToolRegistry()

    result = registry.execute("missing")

    assert result.success is False
    assert result.error == "Unknown tool"


def test_registry_rejects_duplicate_tool() -> None:
    registry = ToolRegistry()
    registry.register(ExampleTool())

    try:
        registry.register(ExampleTool())
    except ValueError:
        pass
    else:
        raise AssertionError("Expected duplicate registration to fail")

