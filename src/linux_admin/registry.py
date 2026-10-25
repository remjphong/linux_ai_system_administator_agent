"""Central registry for explicitly registered tools.

The registry is intentionally not a shell runner. Only objects registered by
application code can be invoked, and every invocation receives validated args.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from linux_admin.contracts import (
    ActionRequest,
    ApprovalRecord,
    PolicyDecision,
    Tool,
    ToolResult,
    ToolSpec,
)

logger = logging.getLogger(__name__)


class ToolRegistryError(ValueError):
    """Raised for invalid registration operations."""


class ToolRegistry:
    """Store and invoke tools by stable name."""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        spec = getattr(tool, "spec", None)
        execute = getattr(tool, "execute", None)
        if not isinstance(spec, ToolSpec) or not callable(execute):
            raise ToolRegistryError(
                "Tool must expose a ToolSpec as '.spec' and a callable '.execute()'"
            )
        if spec.name in self._tools:
            raise ToolRegistryError(f"Tool already registered: {spec.name}")
        self._tools[spec.name] = tool

    def get_spec(self, name: str) -> ToolSpec | None:
        tool = self._tools.get(name)
        return tool.spec if tool is not None else None

    def list_tools(self) -> list[ToolSpec]:
        return [self._tools[name].spec for name in sorted(self._tools)]

    def invoke(
        self, name: str, arguments: Mapping[str, Any] | None = None
    ) -> ToolResult:
        """Validate and call a registered tool; failures become ToolResult values."""
        if not isinstance(name, str) or not name.strip():
            return ToolResult(
                tool_name=str(name),
                status="invalid_input",
                error="Tool name must be a non-empty string",
            )

        tool = self._tools.get(name)
        if tool is None:
            return ToolResult(
                tool_name=name,
                status="failed",
                error=f"Unknown tool: {name}",
            )

        if arguments is None:
            normalized_arguments: dict[str, Any] = {}
        elif isinstance(arguments, Mapping):
            normalized_arguments = dict(arguments)
        else:
            return ToolResult(
                tool_name=name,
                status="invalid_input",
                error="Tool arguments must be a mapping/object",
            )

        if tool.spec.changes_system:
            return ToolResult(
                tool_name=name,
                status="denied",
                error=(
                    "System-changing tools must be invoked through the controlled "
                    "action path"
                ),
            )

        validation_error = self._validate_arguments(tool.spec, normalized_arguments)
        if validation_error:
            return ToolResult(
                tool_name=name,
                status="invalid_input",
                error=validation_error,
            )
        return self._execute_registered(tool, normalized_arguments)

    def invoke_authorized_action(
        self,
        request: ActionRequest,
        decision: PolicyDecision,
        approval: ApprovalRecord | None = None,
    ) -> ToolResult:
        """Invoke a state-changing tool only with matching policy/approval records.

        `control.py` should be the only application component calling this method.
        This method checks record consistency; it does not replace the policy engine.
        """
        name = request.action_name
        tool = self._tools.get(name)
        if tool is None:
            return ToolResult(
                tool_name=name, status="failed", error=f"Unknown tool: {name}"
            )
        if not tool.spec.changes_system:
            return ToolResult(
                tool_name=name,
                status="invalid_input",
                error="Authorized-action path accepts only system-changing tools",
            )
        if (
            decision.action_id != request.action_id
            or decision.action_fingerprint != request.fingerprint
        ):
            return ToolResult(
                tool_name=name,
                status="denied",
                error="Policy decision does not match this exact action request",
            )
        if decision.outcome == "deny":
            return ToolResult(
                tool_name=name,
                status="denied",
                error="Policy denied this action",
            )
        if decision.outcome not in {"allow", "approval_required"}:
            return ToolResult(
                tool_name=name,
                status="denied",
                error="Unsupported policy decision",
            )

        approval_needed = (
            tool.spec.requires_approval or decision.outcome == "approval_required"
        )
        if approval_needed:
            if approval is None:
                return ToolResult(
                    tool_name=name,
                    status="denied",
                    error="A matching approval record is required",
                )
            approval_matches = (
                approval.action_id == request.action_id
                and approval.action_fingerprint == request.fingerprint
                and approval.approved is True
            )
            if not approval_matches:
                return ToolResult(
                    tool_name=name,
                    status="denied",
                    error=(
                        "Approval is missing, rejected, or bound to a different action"
                    ),
                )

        validation_error = self._validate_arguments(tool.spec, dict(request.arguments))
        if validation_error:
            return ToolResult(
                tool_name=name, status="invalid_input", error=validation_error
            )
        return self._execute_registered(tool, dict(request.arguments))

    @staticmethod
    def _execute_registered(tool: Tool, arguments: dict[str, Any]) -> ToolResult:
        name = tool.spec.name
        try:
            result = tool.execute(**arguments)
        except TimeoutError:
            logger.warning("Tool '%s' timed out", name)
            return ToolResult(
                tool_name=name,
                status="timeout",
                error="Tool execution timed out",
            )
        except Exception:
            logger.exception("Tool '%s' raised an exception", name)
            return ToolResult(
                tool_name=name,
                status="failed",
                error="Tool execution failed; consult application logs",
            )

        if not isinstance(result, ToolResult):
            logger.error("Tool '%s' returned a non-ToolResult value", name)
            return ToolResult(
                tool_name=name,
                status="failed",
                error="Tool returned an invalid result type",
            )
        if result.tool_name != name:
            logger.error("Tool '%s' returned result for '%s'", name, result.tool_name)
            return ToolResult(
                tool_name=name,
                status="failed",
                error="Tool result name does not match registered tool name",
            )
        return result

    @staticmethod
    def _validate_arguments(spec: ToolSpec, arguments: dict[str, Any]) -> str | None:
        schema = spec.parameters
        properties = schema.get("properties", {})
        required = schema.get("required", [])

        missing = [key for key in required if key not in arguments]
        if missing:
            return f"Missing required argument(s): {', '.join(sorted(missing))}"

        allow_extra = schema.get("additionalProperties", False)
        extra = set(arguments) - set(properties)
        if extra and not allow_extra:
            return f"Unexpected argument(s): {', '.join(sorted(extra))}"

        for key, value in arguments.items():
            definition = properties.get(key)
            if definition is None:
                continue
            expected = definition.get("type")
            if not ToolRegistry._matches_type(value, expected):
                return f"Argument '{key}' must be of type '{expected}'"
            if "enum" in definition and value not in definition["enum"]:
                return f"Argument '{key}' must be one of: {definition['enum']}"
            if isinstance(value, str):
                if len(value) < definition.get("minLength", 0):
                    return f"Argument '{key}' is too short"
                max_length = definition.get("maxLength")
                if max_length is not None and len(value) > max_length:
                    return f"Argument '{key}' is too long"
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                if "minimum" in definition and value < definition["minimum"]:
                    return f"Argument '{key}' is below the minimum"
                if "maximum" in definition and value > definition["maximum"]:
                    return f"Argument '{key}' exceeds the maximum"
        return None

    @staticmethod
    def _matches_type(value: Any, expected: str | None) -> bool:
        if expected == "string":
            return isinstance(value, str)
        if expected == "integer":
            return isinstance(value, int) and not isinstance(value, bool)
        if expected == "number":
            return isinstance(value, (int, float)) and not isinstance(value, bool)
        if expected == "boolean":
            return isinstance(value, bool)
        if expected == "array":
            return isinstance(value, list)
        if expected == "object":
            return isinstance(value, dict)
        return False
