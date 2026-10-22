"""Executor — cổng duy nhất cho mọi action thay đổi hệ thống.

Luồng: policy → approval → audit → tool adapter.
FAIL-CLOSED: policy/approval/audit lỗi → KHÔNG gọi tool.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from linux_admin.core.contracts import ActionRequest, ToolResult

from .approval import ApprovalManager
from .audit import AuditLogger
from .policy_engine import PolicyDecision, PolicyEngine

logger = logging.getLogger(__name__)


@dataclass
class ExecutionResult:
    ok: bool
    status: str  # success | denied | approval_required | failed | timeout
    message: str
    policy_decision: PolicyDecision | None = None
    data: dict[str, Any] = field(default_factory=dict)


class Executor:
    def __init__(
        self,
        policy: PolicyEngine | None = None,
        approvals: ApprovalManager | None = None,
        audit: AuditLogger | None = None,
    ) -> None:
        self.policy = policy or PolicyEngine()
        self.approvals = approvals or ApprovalManager()
        self.audit = audit or AuditLogger()

    # ------------------------------------------------------------------ public
    def execute(self, request: ActionRequest) -> ExecutionResult:
        """Thực thi một ActionRequest theo policy. Fail-closed ở mọi bước."""
        action_type = request.action_type
        target = request.target
        parameters = request.parameters or {}

        # 1. Policy quyết định
        decision = self.policy.evaluate_action(action_type, target)
        self.audit.log_event(
            event_type="policy_decision",
            action_type=action_type,
            target=target,
            decision="allow" if decision.allowed else "deny",
            details=decision.reason,
        )

        # 1a. Policy từ chối → không gọi tool
        if not decision.allowed:
            return ExecutionResult(
                ok=False,
                status="denied",
                message=decision.reason,
                policy_decision=decision,
            )

        # 2. Approval (nếu policy yêu cầu)
        if decision.requires_approval and not self.approvals.check(
            action_type, target, parameters
        ):
            self.audit.log_event(
                event_type="approval_missing",
                action_type=action_type,
                target=target,
                decision="approval_required",
                details="Chưa có approval hợp lệ",
            )
            return ExecutionResult(
                ok=False,
                status="approval_required",
                message="Cần approval hợp lệ trước khi thực thi",
                policy_decision=decision,
            )

        # 3. Audit bắt buộc trước khi chạy action thật
        logged = self.audit.log_event(
            event_type="action_start",
            action_type=action_type,
            target=target,
            decision="executing",
            details=str(parameters),
        )
        if not logged:
            return ExecutionResult(
                ok=False,
                status="failed",
                message="Không ghi được audit — fail-closed",
                policy_decision=decision,
            )

        # 4. Dispatch tool
        try:
            tool_result = self._dispatch(action_type, target, parameters)
        except TimeoutError as exc:
            self.audit.log_event(
                event_type="action_result",
                action_type=action_type,
                target=target,
                decision="timeout",
                details=str(exc),
            )
            return ExecutionResult(
                ok=False,
                status="timeout",
                message=f"Timeout: {exc}",
                policy_decision=decision,
            )
        except Exception as exc:  # noqa: BLE001 — fail-closed: mọi lỗi dispatch đều phải bị chặn
            self.audit.log_event(
                event_type="action_result",
                action_type=action_type,
                target=target,
                decision="failed",
                details=str(exc),
            )
            return ExecutionResult(
                ok=False,
                status="failed",
                message=f"Thực thi thất bại: {exc}",
                policy_decision=decision,
            )

        # 5. Tool trả về success=False → coi như failed
        if not tool_result.success:
            self.audit.log_event(
                event_type="action_result",
                action_type=action_type,
                target=target,
                decision="failed",
                details=tool_result.error or "",
            )
            return ExecutionResult(
                ok=False,
                status="failed",
                message=tool_result.error or "Tool thất bại",
                policy_decision=decision,
            )

        # 6. Thành công
        self.audit.log_event(
            event_type="action_result",
            action_type=action_type,
            target=target,
            decision="success",
            details=str(tool_result.data),
        )
        return ExecutionResult(
            ok=True,
            status="success",
            message="Action đã thực thi",
            policy_decision=decision,
            data=tool_result.data,
        )

    # ------------------------------------------------------------------ dispatch
    def _dispatch(
        self,
        action_type: str,
        target: str,
        parameters: dict[str, Any],
    ) -> ToolResult:
        """Điều phối tool thật. Chỉ đến đây khi policy + approval đã OK."""
        if action_type == "restart_service":
            from linux_admin.tools.services import RestartServiceTool

            # Không dùng dry_run riêng — policy đã chặn nếu allowed: false.
            # Nếu tới được đây, tức policy + approval đã OK → gọi thật.
            return RestartServiceTool().execute(
                service_name=target,
                is_dry_run=False,
            )
        raise NotImplementedError(
            f"Action '{action_type}' chưa có tool được nối"
        )
