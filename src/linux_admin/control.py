"""Deterministic policy, approval, and controlled action execution.

This module is the only intended application route for state-changing tools.
It uses no shell, never elevates privileges, and fails closed when policy or
required audit writes fail. Real actions additionally require dry_run=False,
assisted mode, explicit policy permission, service allowlisting (for restart),
and an approval bound to the exact action fingerprint.
"""

from __future__ import annotations

import getpass
from collections.abc import Callable, Mapping
from typing import Any

from linux_admin.audit import AuditLogger
from linux_admin.config import AppConfig
from linux_admin.contracts import (
    ActionRequest,
    ApprovalRecord,
    PolicyDecision,
    ToolResult,
)
from linux_admin.registry import ToolRegistry


class PolicyEngine:
    """Evaluate state-changing actions using deterministic configuration only."""

    def __init__(self, config: AppConfig, registry: ToolRegistry) -> None:
        self.config = config
        self.registry = registry

    def evaluate(self, request: ActionRequest) -> PolicyDecision:
        spec = self.registry.get_spec(request.action_name)

        def decision(outcome: str, reason: str, matched_rule: str | None = None) -> PolicyDecision:
            return PolicyDecision(
                action_id=request.action_id,
                outcome=outcome,  # type: ignore[arg-type]
                reason=reason,
                action_fingerprint=request.fingerprint,
                matched_rule=matched_rule,
            )

        if spec is None:
            return decision("deny", "Action is not registered.")
        if not spec.changes_system:
            return decision("deny", "Control accepts only explicitly state-changing tools.")
        if self.config.audit.enabled is False:
            return decision("deny", "Audit is disabled; state-changing actions require audit.")
        if self.config.agent.mode != "assisted":
            return decision("deny", "Agent mode is observe; state-changing actions are disabled.")

        rule = self.config.policy.actions.get(request.action_name)
        if rule is None:
            if self.config.policy.default_decision == "deny":
                return decision("deny", "No explicit policy rule exists for this action.")
            return decision("deny", "Unsupported policy default; action denied.")
        if not rule.allowed:
            return decision("deny", "Policy explicitly disables this action.", request.action_name)

        if request.action_name == "restart_service":
            service_name = request.arguments.get("service_name")
            if not self.config.services.restart_enabled:
                return decision("deny", "Service restart is disabled by configuration.", request.action_name)
            if not isinstance(service_name, str) or service_name not in self.config.services.allowlist:
                return decision("deny", "Service is not in the configured allowlist.", request.action_name)

        needs_approval = (
            spec.requires_approval
            or rule.requires_approval
            or (
                self.config.policy.require_approval_for_disruptive_actions
                and spec.risk_level in {"high", "critical"}
            )
        )
        if needs_approval:
            return decision("approval_required", "Explicit approval is required for this action.", request.action_name)
        return decision("allow", "Action is allowed by the explicit policy rule.", request.action_name)


class ApprovalManager:
    """Create and validate approval records bound to an exact action request.

    The console helper is intended for a locally operated beta CLI. It is not an
    identity provider; deployments with multiple users need authenticated approval.
    """

    def create_record(
        self,
        request: ActionRequest,
        *,
        approved: bool,
        approver: str,
        reason: str,
    ) -> ApprovalRecord:
        if not isinstance(approved, bool):
            raise TypeError("approved must be a bool")
        return ApprovalRecord(
            action_id=request.action_id,
            action_fingerprint=request.fingerprint,
            approved=approved,
            approver=approver.strip(),
            reason=reason.strip(),
        )


    def request_console_approval(
        self,
        request: ActionRequest,
        *,
        input_fn: Callable[[str], str] = input,
        output_fn: Callable[[str], Any] = print,
    ) -> ApprovalRecord:
        """Ask the local operator to type APPROVE; all other input denies."""
        output_fn("\nACTION APPROVAL REQUIRED")
        output_fn(f"Action: {request.action_name}")
        output_fn(f"Arguments: {dict(request.arguments)!r}")
        output_fn(f"Reason: {request.reason}")
        output_fn(f"Action ID: {request.action_id}")
        output_fn("Approval applies only to the action and arguments shown above.")

        try:
            answer = input_fn("Type APPROVE to approve this action: ")
        except EOFError:
            answer = ""

        approved = answer == "APPROVE"
        return self.create_record(
            request,
            approved=approved,
            approver=getpass.getuser(),
            reason=(
                "Approved by local console operator"
                if approved
                else "Not approved by local console operator"
            ),
        )


    @staticmethod
    def matches(request: ActionRequest, approval: ApprovalRecord | None) -> bool:
        return bool(
            approval is not None
            and approval.approved is True
            and approval.action_id == request.action_id
            and approval.action_fingerprint == request.fingerprint
            and approval.approver.strip()
        )


class ControlledExecutor:
    """Policy-gated entry point for state-changing tools."""

    def __init__(
        self,
        config: AppConfig,
        registry: ToolRegistry,
        audit: AuditLogger | None,
        policy_engine: PolicyEngine | None = None,
        approval_manager: ApprovalManager | None = None,
        incident_id: str | None = None,
    ) -> None:
        self.config = config
        self.registry = registry
        self.audit = audit
        self.policy_engine = policy_engine or PolicyEngine(config, registry)
        self.approval_manager = approval_manager or ApprovalManager()
        self.incident_id = incident_id
        if config.audit.enabled and audit is None:
            raise ValueError("AuditLogger is required when audit.enabled is true")

    def execute(
        self,
        request: ActionRequest,
        approval: ApprovalRecord | None = None,
    ) -> ToolResult:
        decision = self.policy_engine.evaluate(request)
        if not self._record(
            "action.policy_decision",
            request,
            {"outcome": decision.outcome, "reason": decision.reason, "matched_rule": decision.matched_rule},
        ):
            return ToolResult(
                tool_name=request.action_name,
                status="failed",
                error="Audit write failed; action was not executed.",
                data={
                    "action_id": request.action_id,
                    "executed": False,
                    "audit_failed_before_execution": True,
                },
            )

        if decision.outcome == "deny":
            audit_ok = self._record(
                "action.denied", request, {"reason": decision.reason}
            )
            if not audit_ok:
                return ToolResult(
                    tool_name=request.action_name,
                    status="failed",
                    error=(
                        "Audit write failed while recording policy denial; "
                        "action was not executed."
                    ),
                    data={
                        "action_id": request.action_id,
                        "executed": False,
                        "policy_outcome": decision.outcome,
                        "audit_failed_before_execution": True,
                    },
                )
            return ToolResult(
                tool_name=request.action_name,
                status="denied",
                error=decision.reason,
                data={
                    "action_id": request.action_id,
                    "executed": False,
                    "policy_outcome": decision.outcome,
                },
            )

        if self.config.agent.dry_run:
            audit_ok = self._record(
                "action.dry_run",
                request,
                {"reason": "dry_run is enabled", "executed": False, "policy_outcome": decision.outcome},
            )
            if not audit_ok:
                return ToolResult(
                    tool_name=request.action_name,
                    status="failed",
                    error="Audit write failed; action was not executed.",
                    data={
                        "action_id": request.action_id,
                        "executed": False,
                        "audit_failed_before_execution": True,
                    },
                )
            return ToolResult(
                tool_name=request.action_name,
                status="denied",
                error="Dry-run is enabled; the state-changing action was not executed.",
                data={"action_id": request.action_id, "executed": False, "dry_run": True, "policy_outcome": decision.outcome},
                evidence=["No system-changing command was run."],
            )

        approval_required = decision.outcome == "approval_required"

        # Distinguish an explicit rejection from a missing or invalid approval.
        # Only trust a rejection record bound to this exact action.
        if (
            approval_required
            and approval is not None
            and approval.approved is False
            and approval.action_id == request.action_id
            and approval.action_fingerprint == request.fingerprint
        ):
            rejection_audited = self._record(
                "action.rejected",
                request,
                {
                    "approver": approval.approver,
                    "rejection_reason": approval.reason,
                    "rejected_at": approval.decided_at,
                    "fingerprint": approval.action_fingerprint,
                    "executed": False,
                },
            )
            if not rejection_audited:
                return ToolResult(
                    tool_name=request.action_name,
                    status="failed",
                    error=(
                        "Could not audit the rejection; "
                        "action was not executed."
                    ),
                    data={
                        "action_id": request.action_id,
                        "executed": False,
                        "audit_failed_before_execution": True,
                    },
                )

            return ToolResult(
                tool_name=request.action_name,
                status="denied",
                error="The operator rejected the proposed action.",
                data={
                    "action_id": request.action_id,
                    "executed": False,
                    "policy_outcome": "approval_required",
                    "approval_rejected": True,
                },
            )

        if approval_required and not self.approval_manager.matches(request, approval):
            audit_ok = self._record(
                "action.approval_missing_or_invalid",
                request,
                {"approval_present": approval is not None, "executed": False},
            )
            if not audit_ok:
                return ToolResult(
                    tool_name=request.action_name,
                    status="failed",
                    error="Audit write failed; action was not executed.",
                    data={
                        "action_id": request.action_id,
                        "executed": False,
                        "audit_failed_before_execution": True,
                    },
                )
            return ToolResult(
                tool_name=request.action_name,
                status="denied",
                error="A matching approved ApprovalRecord is required.",
                data={"action_id": request.action_id, "executed": False, "policy_outcome": "approval_required"},
            )

        if approval_required and approval is not None:
            approval_audited = self._record(
                "action.approved",
                request,
                {
                    "approver": approval.approver,
                    "approval_reason": approval.reason,
                    "approved_at": approval.decided_at,
                    "fingerprint": approval.action_fingerprint,
                },
            )
            if not approval_audited:
                return ToolResult(
                    tool_name=request.action_name,
                    status="failed",
                    error="Could not audit the approval; action was not executed.",
                    data={
                        "action_id": request.action_id,
                        "executed": False,
                        "audit_failed_before_execution": True,
                    },
                )

        if not self._record(
            "action.execution_started",
            request,
            {"arguments": dict(request.arguments), "fingerprint": request.fingerprint},
        ):
            return ToolResult(
                tool_name=request.action_name,
                status="failed",
                error="Audit write failed; action was not executed.",
                data={
                    "action_id": request.action_id,
                    "executed": False,
                    "audit_failed_before_execution": True,
                },
            )

        result = self.registry.invoke_authorized_action(request, decision, approval)
        audit_ok = self._record(
            "action.execution_finished",
            request,
            {"result_status": result.status, "executed": bool(result.data.get("executed", result.ok)), "error": result.error},
        )
        if not audit_ok:
            return ToolResult(
                tool_name=request.action_name,
                status="failed",
                error="Action may have executed, but the result could not be audited. Verify system state before retrying.",
                data={**result.data, "action_id": request.action_id, "audit_failed_after_execution": True},
                evidence=result.evidence,
            )
        return result

    def _record(self, event_type: str, request: ActionRequest, details: Mapping[str, Any]) -> bool:
        if not self.config.audit.enabled:
            # PolicyEngine denies system-changing actions when auditing is disabled.
            return False
        if self.audit is None:
            return False
        try:
            self.audit.record_event(
                event_type=event_type,
                incident_id=(
                    self.incident_id or f"action:{request.action_id}"
                ),
                action_id=request.action_id,
                details={"action_name": request.action_name, **dict(details)},
            )
        except Exception:  # noqa: BLE001
            # The audit adapter may fail in more than one way. Never execute an
            # action if audit persistence is uncertain; return a generic failure.
            return False
        return True
