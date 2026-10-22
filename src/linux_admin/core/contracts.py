
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class ToolResult:
    """Kết quả chuẩn hóa do một tool trả về."""

    success: bool
    tool_name: str
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class Tool(Protocol):
    """Giao diện mà các tool trong hệ thống cần tuân theo."""

    name: str

    def execute(self, **kwargs: Any) -> ToolResult:
        """Thực hiện một tác vụ và trả về kết quả chuẩn hóa."""
        ...
@dataclass
class ActionRequest:
    """Hành động agent đề xuất, Executor sẽ kiểm tra policy/approval."""
    action_type: str
    target: str
    parameters: dict[str, Any] = field(default_factory=dict)
