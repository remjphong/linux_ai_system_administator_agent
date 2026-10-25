"""LLM planning contracts and a deterministic fake client for development.

No network API is called from this module yet. A provider-specific client can be
added later while keeping the same ``create_plan`` interface. Model output must
be parsed and validated before it is handed to the agent; this module never
executes tools or shell commands.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping, Protocol, Sequence

from linux_admin.contracts import ToolSpec

_TOOL_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")


class PlanValidationError(ValueError):
    """Raised when a plan is malformed or contains invalid data."""


@dataclass(frozen=True)
class PlanStep:
    """One proposed read-only tool call in an investigation plan."""

    tool_name: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    purpose: str = "Collect diagnostic evidence"

    def __post_init__(self) -> None:
        if not isinstance(self.tool_name, str) or not _TOOL_NAME_PATTERN.fullmatch(
            self.tool_name
        ):
            raise PlanValidationError("tool_name must be a valid lowercase tool name")
        if not isinstance(self.arguments, Mapping):
            raise PlanValidationError("PlanStep.arguments must be a mapping")
        arguments = copy.deepcopy(dict(self.arguments))
        try:
            json.dumps(arguments, sort_keys=True, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise PlanValidationError(
                "PlanStep.arguments must be JSON-serializable"
            ) from exc
        if not isinstance(self.purpose, str) or not self.purpose.strip():
            raise PlanValidationError("PlanStep.purpose must not be empty")
        object.__setattr__(self, "arguments", MappingProxyType(arguments))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation of this planned tool call."""
        return {
            "tool_name": self.tool_name,
            "arguments": dict(self.arguments),
            "purpose": self.purpose,
        }


@dataclass(frozen=True)
class AgentPlan:
    """A bounded sequence of proposed tool calls; it is not authorization."""

    steps: tuple[PlanStep, ...] = ()
    rationale: str = ""

    def __post_init__(self) -> None:
        normalized_steps = tuple(self.steps)
        if not all(isinstance(step, PlanStep) for step in normalized_steps):
            raise PlanValidationError("Every AgentPlan step must be a PlanStep")
        if not isinstance(self.rationale, str):
            raise PlanValidationError("AgentPlan.rationale must be a string")
        object.__setattr__(self, "steps", normalized_steps)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rationale": self.rationale,
            "steps": [step.to_dict() for step in self.steps],
        }


class LLMClient(Protocol):
    """Interface for clients that propose structured plans."""

    def create_plan(
        self,
        user_request: str,
        available_tools: Sequence[ToolSpec],
    ) -> AgentPlan:
        """Return a structured plan; never execute the proposed tool calls."""
        ...


class FakeLLMClient:
    """Deterministic client for tests and development without a real API.

    Supply either ``default_plan`` or ``plans_by_request``. Keys in
    ``plans_by_request`` are matched after trimming and case-folding the request.
    An unknown request returns an empty plan rather than inventing tool calls.
    The ``available_tools`` argument is accepted to match the production
    interface; the Agent remains responsible for checking each proposed tool.
    """

    def __init__(
        self,
        default_plan: AgentPlan | None = None,
        *,
        plans_by_request: Mapping[str, AgentPlan] | None = None,
    ) -> None:
        self._default_plan = default_plan
        self._plans_by_request = {
            key.strip().casefold(): value
            for key, value in (plans_by_request or {}).items()
        }
        if default_plan is not None and not isinstance(default_plan, AgentPlan):
            raise TypeError("default_plan must be an AgentPlan or None")
        if not all(
            isinstance(value, AgentPlan)
            for value in self._plans_by_request.values()
        ):
            raise TypeError("Every plans_by_request value must be an AgentPlan")

    def create_plan(
        self,
        user_request: str,
        available_tools: Sequence[ToolSpec],
    ) -> AgentPlan:
        del available_tools  # The Agent validates availability before invocation.
        key = user_request.strip().casefold()
        plan = self._plans_by_request.get(key, self._default_plan)
        if plan is None:
            return AgentPlan(
                steps=(),
                rationale="No fake plan is configured for this request.",
            )
        return plan
