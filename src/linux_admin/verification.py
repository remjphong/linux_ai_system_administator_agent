"""Post-action health verification and bounded recovery assessment.

Verification may retry a small, finite number of times. The manager never repeats
an action that changes the system; it only repeats read-only health checks.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from linux_admin.config import AppConfig
from linux_admin.contracts import ToolResult, ToolSpec
from linux_admin.tools.network import perform_http_check
from linux_admin.tools.services import query_service_status


class VerifyServiceHealthTool:
    """Check whether a systemd service is active."""

    spec = ToolSpec(
        name="verify_service_health",
        description="Verify that a systemd service is active after a controlled action.",
        parameters={
            "type": "object",
            "properties": {
                "service_name": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 255,
                }
            },
            "required": ["service_name"],
            "additionalProperties": False,
        },
    )

    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def execute(self, service_name: str, **kwargs: Any) -> ToolResult:
        del kwargs
        result = query_service_status(
            service_name, self.config.agent.tool_timeout_seconds
        )
        data = dict(result.data)
        data["healthy"] = result.ok and data.get("is_active") is True
        data["verification"] = "service_active_state"

        if not result.ok:
            return ToolResult(
                tool_name=self.spec.name,
                status=result.status,
                error=result.error,
                data=data,
                evidence=result.evidence,
            )

        return ToolResult(
            tool_name=self.spec.name,
            status="success",
            data=data,
           evidence=[
    (
        "Service health was checked after the action; "
        f"active_state={data.get('active_state')}."
    ),
],

        )

class VerifyEndpointTool:
    """Check whether an HTTP(S) endpoint is reachable and healthy."""

    spec = ToolSpec(
        name="verify_endpoint",
        description="Verify an HTTP(S) endpoint after an action using a bounded request.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "minLength": 8, "maxLength": 2048},
                "timeout_seconds": {
                    "type": "number",
                    "minimum": 0.1,
                    "maximum": 5.0,
                },
            },
            "required": ["url"],
            "additionalProperties": False,
        },
    )

    def execute(
        self, url: str, timeout_seconds: float = 2.5, **kwargs: Any
    ) -> ToolResult:
        del kwargs
        result = perform_http_check(url, timeout_seconds)
        data = dict(result.data)
        # HTTP reachability alone is not enough: a 5xx response is reachable but
        # unhealthy. Only trust an explicit healthy=True from a successful probe.
        data["healthy"] = result.ok and data.get("healthy") is True
        data["verification"] = "http_endpoint"
        return ToolResult(
            tool_name=self.spec.name,
            status=result.status,
            data=data,
            error=result.error,
            evidence=result.evidence,
        )


class RecoveryManager:
    """Retry health checks only; never re-run a restart or other state change."""

    def __init__(
        self,
        max_attempts: int = 2,
        interval_seconds: float = 1.0,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if (
            isinstance(max_attempts, bool)
            or not isinstance(max_attempts, int)
            or not 1 <= max_attempts <= 3
        ):
            raise ValueError("max_attempts must be between 1 and 3")
        if (
            isinstance(interval_seconds, bool)
            or not isinstance(interval_seconds, (int, float))
            or not 0 <= interval_seconds <= 3
        ):
            raise ValueError("interval_seconds must be between 0 and 3")
        self.max_attempts = max_attempts
        self.interval_seconds = float(interval_seconds)
        self._sleep = sleeper

    def verify_until_healthy(self, check: Callable[[], ToolResult]) -> ToolResult:
        """Retry a read-only health check within fixed attempt/time bounds."""
        attempts: list[dict[str, Any]] = []
        last_result: ToolResult | None = None

        for number in range(1, self.max_attempts + 1):
            try:
                candidate = check()
                if not isinstance(candidate, ToolResult):
                    raise TypeError("Health check callback must return ToolResult")
                last_result = candidate
            except Exception as exc:  # noqa: BLE001
                # This is an intentional fault boundary around an injected checker.
                # Convert failures into an unhealthy result; never treat exceptions
                # or malformed callback results as proof that recovery succeeded.
                last_result = ToolResult(
                    tool_name="health_check",
                    status="failed",
                    error=f"Health check raised {type(exc).__name__}.",
                    data={"healthy": False},
                )

            is_healthy = last_result.ok and last_result.data.get("healthy") is True
            attempts.append(
                {
                    "attempt": number,
                    "status": last_result.status,
                    "healthy": is_healthy,
                }
            )
            if is_healthy:
                return ToolResult(
                    tool_name=last_result.tool_name,
                    status="success",
                    data={
                        **last_result.data,
                        "healthy": True,
                        "verification_attempts": attempts,
                        "recovery_action_retried": False,
                    },
                    evidence=[
                        *last_result.evidence,
                        f"Health confirmed on verification attempt {number}.",
                    ],
                )

            if number < self.max_attempts and self.interval_seconds:
                self._sleep(self.interval_seconds)

        # The validated minimum is one attempt, so last_result must be populated.
        if last_result is None:  # defensive guard against future loop changes
            return ToolResult(
                tool_name="health_check",
                status="failed",
                error="Health check did not produce a result.",
                data={
                    "healthy": False,
                    "verification_attempts": attempts,
                    "recovery_action_retried": False,
                },
            )

        data = {
            **last_result.data,
            "healthy": False,
            "verification_attempts": attempts,
            "recovery_action_retried": False,
        }
        return ToolResult(
            tool_name=last_result.tool_name,
            status="failed",
            data=data,
            error=(
                "Health verification did not succeed within the configured retry "
                "limit; no further action was attempted."
            ),
evidence=[
    *last_result.evidence,
    (
        "Stopped after bounded verification attempts; manual investigation "
        "may be required."
    ),
],

        )

    @staticmethod
    def handle_recovery_failure(
        *, incident_id: str, action_name: str, last_result: ToolResult
    ) -> dict[str, Any]:
        """Build a safe incident disposition after verification failed."""
        return {
            "incident_id": incident_id,
            "action_name": action_name,
            "status": "recovery_failed",
            "last_verification_status": last_result.status,
            "error": last_result.error,
            "next_step": "Stop automated actions, preserve evidence, and require manual review.",
            "automatic_follow_up_action": False,
        }


def build_tools(config: AppConfig) -> list[object]:
    """Build the read-only verification tools for registration."""
    return [VerifyServiceHealthTool(config), VerifyEndpointTool()]
