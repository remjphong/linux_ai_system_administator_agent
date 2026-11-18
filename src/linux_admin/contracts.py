"""Shared contracts used by the agent, tools, policy, and executor.

Keep this module independent from application modules. Changes here affect every
team member and must be reviewed before they are merged.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Literal, Protocol
from uuid import uuid4

ToolStatus = Literal["success", "invalid_input", "denied", "timeout", "failed"]
RiskLevel = Literal["read_only", "low", "medium", "high", "critical"]
PolicyOutcome = Literal["allow", "deny", "approval_required"]
IncidentStatus = Literal[
    "open", "investigating", "waiting_approval", "completed", "failed", "inconclusive"
]

_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")


class ContractError(ValueError):
    """Raised when a shared contract is invalid."""


@dataclass
class ToolResult:
    """Normalized result returned by every tool.

    `ok` is derived from `status` to avoid contradictory combinations such as
    `ok=True` with `status='failed'`.
    """

    tool_name: str
    status: ToolStatus
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    evidence: list[str] = field(default_factory=list)
    duration_ms: int | None = None

    def __post_init__(self) -> None:
        if not self.tool_name or not self.tool_name.strip():
            raise ContractError("tool_name must be a non-empty string")
        if self.status not in (
            "success", "invalid_input", "denied", "timeout", "failed"
        ):
            raise ContractError(f"Unsupported tool status: {self.status}")
        if self.status == "success" and self.error is not None:
            raise ContractError("A successful ToolResult must not include an error")
        if self.duration_ms is not None and self.duration_ms < 0:
            raise ContractError("duration_ms must be non-negative")

    @property
    def ok(self) -> bool:
        """Return whether the tool completed successfully."""
        return self.status == "success"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation for CLI output and audit."""
        return {
            "tool_name": self.tool_name,
            "ok": self.ok,
            "status": self.status,
            "data": self.data,
            "error": self.error,
            "evidence": list(self.evidence),
            "duration_ms": self.duration_ms,
        }


@dataclass(frozen=True)
class ToolSpec:
    """Stable metadata for a registered tool.

    `parameters` uses a deliberately small JSON-Schema-like subset. The registry
    validates basic types, required keys, enum values, and unknown keys.
    """

    name: str
    description: str
    parameters: dict[str, Any] = field(
        default_factory=lambda: {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        }
    )
    risk_level: RiskLevel = "read_only"
    changes_system: bool = False
    requires_approval: bool = False

    def __post_init__(self) -> None:
        if not _NAME_PATTERN.fullmatch(self.name):
            raise ContractError(
                "Tool name must use lowercase letters, digits, and underscores "
                "and start with a letter"
            )
        if not isinstance(self.description, str) or not self.description.strip():
            raise ContractError("Tool description must not be empty")
        if not isinstance(self.parameters, dict):
            raise ContractError("Tool parameters must be a mapping")
        if self.risk_level not in ("read_only", "low", "medium", "high", "critical"):
            raise ContractError(f"Unsupported risk level: {self.risk_level}")
        if self.changes_system and self.risk_level == "read_only":
            raise ContractError("A system-changing tool cannot be marked read_only")
        if self.changes_system and not self.requires_approval:
            raise ContractError(
                "System-changing tools must declare requires_approval=True"
            )
        if self.parameters.get("type", "object") != "object":
            raise ContractError("Tool parameters schema must have type='object'")
        properties = self.parameters.get("properties", {})
        required = self.parameters.get("required", [])
        if not isinstance(properties, dict):
            raise ContractError("Tool parameter properties must be a mapping")
        if not isinstance(required, list) or not all(
            isinstance(item, str) for item in required
        ):
            raise ContractError("Tool parameter required must be a list of strings")
        unknown_required = set(required) - set(properties)
        if unknown_required:
            raise ContractError(
                f"Required parameter(s) missing from properties: "
                f"{', '.join(sorted(unknown_required))}"
            )
        for parameter_name, definition in properties.items():
            if not isinstance(parameter_name, str) or not isinstance(definition, dict):
                raise ContractError(
                    "Each parameter must have a name and mapping schema"
                )
            if definition.get("type") not in {
                "string", "integer", "number", "boolean", "array", "object"
            }:
                raise ContractError(
                    f"Unsupported type for parameter '{parameter_name}'"
                )


@dataclass(frozen=True)
class ActionRequest:
    """A proposed system action; it is not authorization to execute it."""

    action_name: str
    arguments: Mapping[str, Any]
    reason: str
    requested_by: str = "agent"
    action_id: str = field(default_factory=lambda: str(uuid4()))
    requested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not _NAME_PATTERN.fullmatch(self.action_name):
            raise ContractError("action_name must be a valid lowercase tool name")
        if not isinstance(self.arguments, Mapping):
            raise ContractError("ActionRequest.arguments must be a mapping")
        copied_arguments = copy.deepcopy(dict(self.arguments))
        try:
            json.dumps(copied_arguments, sort_keys=True, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ContractError(
                "ActionRequest arguments must be JSON-serializable"
            ) from exc
        object.__setattr__(self, "arguments", MappingProxyType(copied_arguments))
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ContractError("ActionRequest.reason must not be empty")
        if not isinstance(self.requested_by, str) or not self.requested_by.strip():
            raise ContractError("ActionRequest.requested_by must not be empty")
        if not isinstance(self.action_id, str) or not self.action_id.strip():
            raise ContractError("ActionRequest.action_id must not be empty")
        if self.requested_at.tzinfo is None:
            raise ContractError("requested_at must include a timezone")

    @property
    def fingerprint(self) -> str:
        """Hash action name and arguments so approval can bind to exact parameters."""
        canonical = json.dumps(
            {"action_name": self.action_name, "arguments": dict(self.arguments)},
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PolicyDecision:
    """Decision made by deterministic policy code, never by the LLM."""

    action_id: str
    outcome: PolicyOutcome
    reason: str
    action_fingerprint: str
    matched_rule: str | None = None

    def __post_init__(self) -> None:
        if self.outcome not in ("allow", "deny", "approval_required"):
            raise ContractError(f"Unsupported policy outcome: {self.outcome}")
        if not self.action_id.strip() or not self.reason.strip():
            raise ContractError("PolicyDecision requires action_id and reason")
        if not self.action_fingerprint.strip():
            raise ContractError("PolicyDecision requires action_fingerprint")


@dataclass(frozen=True)
class ApprovalRecord:
    """Approval tied to one exact action ID and argument fingerprint."""

    action_id: str
    action_fingerprint: str
    approved: bool
    approver: str
    reason: str
    decided_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not self.action_id.strip() or not self.approver.strip():
            raise ContractError("ApprovalRecord requires action_id and approver")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ContractError("ApprovalRecord.reason must not be empty")
        if not self.action_fingerprint.strip():
            raise ContractError("ApprovalRecord requires action_fingerprint")
        if self.decided_at.tzinfo is None:
            raise ContractError("decided_at must include a timezone")


@dataclass
class IncidentContext:
    """Shared state for one incident investigation."""

    user_request: str
    incident_id: str = field(default_factory=lambda: str(uuid4()))
    status: IncidentStatus = "open"
    evidence: list[ToolResult] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    steps: int = 0
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not self.user_request.strip():
            raise ContractError("IncidentContext.user_request must not be empty")
        valid_statuses = {
            "open",
            "investigating",
            "waiting_approval",
            "completed",
            "failed",
            "inconclusive",
        }
        if self.status not in valid_statuses:
            raise ContractError(f"Unsupported incident status: {self.status}")
        if self.steps < 0:
            raise ContractError("IncidentContext.steps must be non-negative")
        if self.started_at.tzinfo is None:
            raise ContractError("started_at must include a timezone")


class Tool(Protocol):
    """Structural interface implemented by all registered tools."""

    @property
    def spec(self) -> ToolSpec:
        """Return the tool's immutable metadata."""
        ...

    def execute(self, **kwargs: Any) -> ToolResult:
        """Execute a validated read-only operation or controlled adapter."""
        ...
