from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from linux_admin.contracts import (
    ActionRequest,
    ApprovalRecord,
    PolicyDecision,
    ToolResult,
)

logger = logging.getLogger(__name__)


class PolicyEngine:
    """Đưa ra quyết định allow / deny / approval_required dựa trên config."""

    def __init__(
        self,
        policy_path: str | Path = "config/policy.yaml",
        services_path: str | Path = "config/services.yaml",
    ) -> None:
        self.policy_path = Path(policy_path)
        self.services_path = Path(services_path)
        self.policy_config: dict[str, Any] = {}
        self.actions_block: dict[str, Any] = {}
        self.services_config: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        try:
            if self.policy_path.exists():
                with open(self.policy_path, "r", encoding="utf-8") as f:
                    raw = yaml.safe_load(f) or {}
                    self.policy_config = raw.get("policy", {}) or {}
                    self.actions_block = raw.get("actions", {}) or {}
            else:
                logger.warning("Không tìm thấy policy config: %s", self.policy_path)
        except (OSError, yaml.YAMLError) as exc:
            logger.error("Lỗi đọc policy config: %s", exc)
            self.policy_config = {}
            self.actions_block = {}

        try:
            if self.services_path.exists():
                with open(self.services_path, "r", encoding="utf-8") as f:
                    raw_services = yaml.safe_load(f) or {}
                    self.services_config = raw_services.get("services", raw_services)
            else:
                logger.warning("Không tìm thấy services config: %s", self.services_path)
        except (OSError, yaml.YAMLError) as exc:
            logger.error("Lỗi đọc services config: %s", exc)
            self.services_config = {}

    def _default_decision(self) -> str:
        val = self.policy_config.get("default_decision", "deny")
        return val if val in ("allow", "deny") else "deny"

    def _action_rule(self, action_name: str) -> dict[str, Any] | None:
        rule = self.actions_block.get(action_name)
        return rule if isinstance(rule, dict) else None

    def evaluate(self, request: ActionRequest) -> PolicyDecision:
        """Đánh giá một ActionRequest, trả về PolicyDecision.

        Fail-closed ở mọi nhánh không rõ.
        """
        action_name = request.action_name

        if not action_name:
            return PolicyDecision(
                action_id=request.action_id,
                action_fingerprint=request.fingerprint,
                outcome="deny",
                reason="action_name rỗng — fail-closed",
            )

        rule = self._action_rule(action_name)

        if rule is None:
            default = self._default_decision()
            return PolicyDecision(
                action_id=request.action_id,
                action_fingerprint=request.fingerprint,
                outcome="allow" if default == "allow" else "deny",
                reason=(
                    f"Action '{action_name}' không có rule — "
                    f"default_decision={default}"
                ),
            )

        allowed = bool(rule.get("allowed", False))
        requires_approval = bool(rule.get("requires_approval", False))

        if not allowed:
            return PolicyDecision(
                action_id=request.action_id,
                action_fingerprint=request.fingerprint,
                outcome="deny",
                reason=f"Action '{action_name}' bị chặn (allowed: false)",
            )

        if action_name == "restart_service":
            target_service = request.arguments.get("service_name", "")
            allowlist = self.services_config.get("allowlist", [])
            if not isinstance(allowlist, list) or target_service not in allowlist:
                return PolicyDecision(
                    action_id=request.action_id,
                    action_fingerprint=request.fingerprint,
                    outcome="deny",
                    reason=f"Service '{target_service}' không nằm trong allowlist",
                )
            if not self.services_config.get("restart_enabled", False):
                return PolicyDecision(
                    action_id=request.action_id,
                    action_fingerprint=request.fingerprint,
                    outcome="deny",
                    reason="Restart đang bị tắt trong services.yaml",
                )

        if requires_approval:
            return PolicyDecision(
                action_id=request.action_id,
                action_fingerprint=request.fingerprint,
                outcome="approval_required",
                reason=f"Action '{action_name}' cần được phê duyệt",
            )

        return PolicyDecision(
            action_id=request.action_id,
            action_fingerprint=request.fingerprint,
            outcome="allow",
            reason=f"Action '{action_name}' được phép",
        )


class ApprovalManager:
    """Quản lý approval gắn với action_id và fingerprint."""

    def __init__(self) -> None:
        self._records: dict[str, ApprovalRecord] = {}

    def grant(
        self,
        request: ActionRequest,
        approver: str = "admin",
        reason: str = "Approved",
    ) -> ApprovalRecord:
        record = ApprovalRecord(
            action_id=request.action_id,
            action_fingerprint=request.fingerprint,
            approved=True,
            approver=approver,
            reason=reason,
        )
        self._records[request.action_id] = record
        return record

    def deny(
        self,
        request: ActionRequest,
        approver: str = "admin",
        reason: str = "Denied",
    ) -> ApprovalRecord:
        record = ApprovalRecord(
            action_id=request.action_id,
            action_fingerprint=request.fingerprint,
            approved=False,
            approver=approver,
            reason=reason,
        )
        self._records[request.action_id] = record
        return record

    def check(self, request: ActionRequest) -> ApprovalRecord | None:
        """Trả về ApprovalRecord nếu hợp lệ, None nếu thiếu hoặc fingerprint sai."""
        record = self._records.get(request.action_id)
        if not record:
            return None
        if record.action_fingerprint != request.fingerprint:
            return None
        return record


class ControlledExecutor:
    """Cổng duy nhất cho mọi action thay đổi hệ thống.

    Luồng: policy → approval → re-check policy → dispatch tool.
    """

    def __init__(
        self,
        policy: PolicyEngine,
        approvals: ApprovalManager,
        audit_logger: Any | None = None,
    ) -> None:
        self.policy = policy
        self.approvals = approvals
        self.audit = audit_logger

    def execute(self, request: ActionRequest) -> tuple[PolicyDecision, ToolResult | None]:
        """Thực thi request theo policy + approval. Trả về (decision, tool_result)."""

        # 1. Policy
        decision = self.policy.evaluate(request)
        self._audit(
            "policy_decision",
            action_id=request.action_id,
            action_name=request.action_name,
            decision=decision.outcome,
            reason=decision.reason,
        )

        if decision.outcome == "deny":
            return decision, None

        # 2. Approval
        if decision.outcome == "approval_required":
            approval = self.approvals.check(request)
            if not approval or not approval.approved:
                self._audit(
                    "approval_missing",
                    action_id=request.action_id,
                    action_name=request.action_name,
                    decision="approval_required",
                    reason="Chưa có approval hợp lệ",
                )
                return decision, None

        # 3. Re-check policy ngay trước khi dispatch (TOCTOU)
        final_decision = self.policy.evaluate(request)
        if final_decision.outcome == "deny":
            self._audit(
                "policy_recheck_denied",
                action_id=request.action_id,
                action_name=request.action_name,
                decision="deny",
                reason=f"Policy thay đổi trước thực thi: {final_decision.reason}",
            )
            return final_decision, None

        # 4. Dispatch tool
        self._audit(
            "action_start",
            action_id=request.action_id,
            action_name=request.action_name,
            decision="executing",
            reason=str(dict(request.arguments)),
        )

        try:
            tool_result = self._dispatch(request)
        except TimeoutError as exc:
            self._audit(
                "action_result",
                action_id=request.action_id,
                action_name=request.action_name,
                decision="timeout",
                reason=str(exc),
            )
            return final_decision, ToolResult(
                tool_name=request.action_name,
                status="timeout",
                error=str(exc),
            )
        except Exception as exc:  # noqa: BLE001 — fail-closed, mọi lỗi dispatch đều bị chặn
            self._audit(
                "action_result",
                action_id=request.action_id,
                action_name=request.action_name,
                decision="failed",
                reason=str(exc),
            )
            return final_decision, ToolResult(
                tool_name=request.action_name,
                status="failed",
                error=str(exc),
            )

        self._audit(
            "action_result",
            action_id=request.action_id,
            action_name=request.action_name,
            decision=tool_result.status,
            reason=tool_result.error or "",
        )
        return final_decision, tool_result

    def _dispatch(self, request: ActionRequest) -> ToolResult:
        if request.action_name == "restart_service":
            from linux_admin.tools.services import restart_service

            service_name = request.arguments.get("service_name", "")
            is_dry_run = bool(request.arguments.get("dry_run", True))
            return restart_service(service_name, is_dry_run=is_dry_run)

        return ToolResult(
            tool_name=request.action_name,
            status="failed",
            error=f"Tool '{request.action_name}' chưa được nối",
        )

    def _audit(self, event_type: str, **kwargs: Any) -> None:
        """Ghi audit nếu có audit_logger được inject. Không làm hỏng flow nếu audit lỗi."""
        if self.audit is None:
            return
        try:
            if hasattr(self.audit, "record_event"):
                self.audit.record_event(event_type=event_type, details=kwargs)
            elif hasattr(self.audit, "log_event"):
                self.audit.log_event(event_type=event_type, details=str(kwargs))
        except Exception as exc:  # noqa: BLE001 — không để audit làm hỏng flow
            logger.error("Ghi audit thất bại: %s", exc)
