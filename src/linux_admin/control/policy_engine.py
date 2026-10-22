"""Policy Engine — quyết định allow / deny / approval_required.

Đọc đúng schema config/policy.yaml của nhóm:

    policy:
      default_decision: deny
      require_approval_for_disruptive_actions: true
      allow_privilege_escalation: false
    actions:
      <action_name>:
        allowed: <bool>
        requires_approval: <bool>

Đọc thêm config/services.yaml để kiểm tra allowlist cho restart_service.

Nguyên tắc FAIL-CLOSED:
- Lỗi cấu hình → deny.
- Action không có trong `actions:` → default_decision (deny).
- allowed: false → deny (bất kể approval).
- restart_service: service phải nằm trong allowlist VÀ phải là test service.
- requires_approval: true → approval_required (chưa phải allow tuyệt đối).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str
    requires_approval: bool = False
    action_type: str = ""
    target: str = ""


class PolicyEngine:
    """Đọc config/policy.yaml + config/services.yaml, đưa ra quyết định."""

    def __init__(
        self,
        policy_path: str | Path = "config/policy.yaml",
        services_path: str | Path = "config/services.yaml",
    ) -> None:
        self.policy_path = Path(policy_path)
        self.services_path = Path(services_path)
        self.raw: dict[str, Any] = {}
        self.policy_block: dict[str, Any] = {}
        self.actions_block: dict[str, Any] = {}
        self.services_config: dict[str, Any] = {}
        self._load()

    # ------------------------------------------------------------------ load
    def _load(self) -> None:
        # policy.yaml
        try:
            if self.policy_path.exists():
                with open(self.policy_path, "r", encoding="utf-8") as f:
                    self.raw = yaml.safe_load(f) or {}
                self.policy_block = self.raw.get("policy", {}) or {}
                self.actions_block = self.raw.get("actions", {}) or {}
            else:
                logger.warning("Không tìm thấy policy config: %s", self.policy_path)
        except (OSError, yaml.YAMLError) as exc:
            logger.error("Lỗi đọc policy config: %s", exc)
            self.raw = {}
            self.policy_block = {}
            self.actions_block = {}

        # services.yaml
        try:
            if self.services_path.exists():
                with open(self.services_path, "r", encoding="utf-8") as f:
                    self.services_config = yaml.safe_load(f) or {}
            else:
                logger.warning("Không tìm thấy services config: %s", self.services_path)
        except (OSError, yaml.YAMLError) as exc:
            logger.error("Lỗi đọc services config: %s", exc)
            self.services_config = {}

    # ------------------------------------------------------------------ helpers
    def _default_decision(self) -> str:
        val = self.policy_block.get("default_decision", "deny")
        return val if val in ("allow", "deny") else "deny"

    def _allow_privilege_escalation(self) -> bool:
        return bool(self.policy_block.get("allow_privilege_escalation", False))

    def _action_rule(self, action_type: str) -> dict[str, Any] | None:
        rule = self.actions_block.get(action_type)
        return rule if isinstance(rule, dict) else None

    # ------------------------------------------------------------------ API
    def evaluate_action(
        self,
        action_type: str,
        target: str = "",
    ) -> PolicyDecision:
        """Đánh giá một action. Fail-closed ở mọi nhánh không rõ."""

        # 0. Thiếu action_type → deny
        if not action_type:
            return PolicyDecision(
                allowed=False,
                reason="action_type rỗng — fail-closed",
            )

        # 1. Privilege escalation luôn bị chặn nếu policy không cho phép
        if (
            action_type in ("sudo", "su", "privilege_escalation")
            and not self._allow_privilege_escalation()
        ):
            return PolicyDecision(
                allowed=False,
                reason="Privilege escalation bị cấm bởi policy",
                action_type=action_type,
                target=target,
            )

        # 2. Tra rule trong actions:
        rule = self._action_rule(action_type)

        # 2a. Action không khai báo → dùng default_decision
        if rule is None:
            default = self._default_decision()
            return PolicyDecision(
                allowed=(default == "allow"),
                reason=(
                    f"Action '{action_type}' không được khai báo — "
                    f"dùng default_decision={default}"
                ),
                action_type=action_type,
                target=target,
            )

        allowed = bool(rule.get("allowed", False))
        requires_approval = bool(rule.get("requires_approval", False))

        # 3. allowed: false → deny tuyệt đối (bất kể approval)
        if not allowed:
            return PolicyDecision(
                allowed=False,
                reason=f"Action '{action_type}' bị chặn bởi policy (allowed: false)",
                action_type=action_type,
                target=target,
            )

        # 3b. Với restart_service: kiểm tra allowlist + test service
        if action_type == "restart_service":
            if not self.is_service_allowed(target):
                return PolicyDecision(
                    allowed=False,
                    reason=f"Service '{target}' không nằm trong allowlist",
                    action_type=action_type,
                    target=target,
                )
            if not self.is_test_service(target):
                test_svc = self.services_config.get(
                    "test_service_for_restart", "?"
                )
                return PolicyDecision(
                    allowed=False,
                    reason=(
                        f"Beta chỉ cho phép restart service thử nghiệm "
                        f"'{test_svc}', không phải '{target}'"
                    ),
                    action_type=action_type,
                    target=target,
                )

        # 4. allowed: true + requires_approval: true → approval_required
        if requires_approval:
            return PolicyDecision(
                allowed=True,
                reason=f"Action '{action_type}' hợp lệ nhưng cần approval",
                requires_approval=True,
                action_type=action_type,
                target=target,
            )

        # 5. allowed: true + không cần approval → allow luôn
        return PolicyDecision(
            allowed=True,
            reason=f"Action '{action_type}' được phép",
            requires_approval=False,
            action_type=action_type,
            target=target,
        )

    # ------------------------------------------------------------------ service helpers
    def is_service_allowed(self, service_name: str) -> bool:
        allowed = self.services_config.get("allowed_services", [])
        return isinstance(allowed, list) and service_name in allowed

    def is_test_service(self, service_name: str) -> bool:
        return self.services_config.get("test_service_for_restart") == service_name

    def systemctl_timeout(self) -> int:
        val = self.services_config.get("systemctl_timeout", 30)
        return int(val) if isinstance(val, int) and val > 0 else 30
