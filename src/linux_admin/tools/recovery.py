"""Recovery tool — đề xuất bước xử lý khi phục hồi thất bại."""
from __future__ import annotations

from linux_admin.core.contracts import ToolResult


class SuggestManualInterventionTool:
    name = "suggest_manual_intervention"

    def execute(self, reason: str) -> ToolResult:
        return ToolResult(
            success=True,
            tool_name=self.name,
            data={
                "suggestion": f"Can thiệp thủ công cần thiết: {reason}",
                "next_steps": [
                    "Kiểm tra log service bằng journalctl",
                    "Xác minh cấu hình service",
                    "Liên hệ quản trị viên nếu không tự xử lý được",
                ],
            },
        )

