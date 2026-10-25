"""Unit tests for the shared contracts used by A, B, and C.

These tests must not call Linux commands, a network, or an LLM. They should
run identically on Windows 10/11 and Ubuntu.
"""

from datetime import datetime, timezone

import pytest

from linux_admin.contracts import (
    ActionRequest,
    ApprovalRecord,
    ContractError,
    IncidentContext,
    PolicyDecision,
    ToolResult,
    ToolSpec,
)


def test_tool_result_success_is_derived_from_status() -> None:
    result = ToolResult(
        tool_name="get_disk_usage",
        status="success",
        data={"used_percent": 42.0},
        evidence=["filesystem: /"],
        duration_ms=12,
    )

    assert result.ok is True
    assert result.to_dict()["ok"] is True
    assert result.to_dict()["status"] == "success"
    assert result.to_dict()["data"] == {"used_percent": 42.0}
    assert result.to_dict()["evidence"] == ["filesystem: /"]
    assert result.to_dict()["duration_ms"] == 12


def test_tool_result_failure_is_not_success() -> None:
    result = ToolResult(
        tool_name="get_service_logs",
        status="failed",
        error="Permission denied",
    )

    assert result.ok is False
    assert result.to_dict()["error"] == "Permission denied"


@pytest.mark.parametrize(
    "status",
    ["invalid_input", "denied", "timeout", "failed"],
)
def test_tool_result_supported_failure_statuses_are_accepted(status: str) -> None:
    result = ToolResult(tool_name="example_tool", status=status)  # type: ignore[arg-type]
    assert result.ok is False


def test_tool_result_rejects_unknown_status() -> None:
    with pytest.raises(ContractError, match="Unsupported tool status"):
        ToolResult(tool_name="example_tool", status="unknown")  # type: ignore[arg-type]


def test_tool_result_rejects_error_on_success() -> None:
    with pytest.raises(ContractError, match="must not include an error"):
        ToolResult(
            tool_name="example_tool",
            status="success",
            error="Contradictory result",
        )


def test_tool_result_rejects_negative_duration() -> None:
    with pytest.raises(ContractError, match="non-negative"):
        ToolResult(tool_name="example_tool", status="success", duration_ms=-1)


def test_tool_spec_accepts_read_only_tool() -> None:
    spec = ToolSpec(
        name="get_disk_usage",
        description="Return filesystem usage information",
        parameters={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False,
        },
    )

    assert spec.name == "get_disk_usage"
    assert spec.risk_level == "read_only"
    assert spec.changes_system is False


def test_tool_spec_rejects_invalid_tool_name() -> None:
    with pytest.raises(ContractError, match="Tool name"):
        ToolSpec(name="Restart Service", description="Invalid spaced name")


def test_system_changing_tool_must_be_non_read_only_and_require_approval() -> None:
    with pytest.raises(ContractError, match="cannot be marked read_only"):
        ToolSpec(
            name="restart_service",
            description="Restart a configured service",
            risk_level="read_only",
            changes_system=True,
            requires_approval=True,
        )

    with pytest.raises(ContractError, match="requires_approval=True"):
        ToolSpec(
            name="restart_service",
            description="Restart a configured service",
            risk_level="high",
            changes_system=True,
            requires_approval=False,
        )


def test_tool_spec_rejects_required_parameter_not_in_properties() -> None:
    with pytest.raises(ContractError, match="missing from properties"):
        ToolSpec(
            name="get_disk_usage",
            description="Return filesystem usage information",
            parameters={
                "type": "object",
                "properties": {},
                "required": ["path"],
            },
        )


def test_action_request_fingerprint_is_stable_for_argument_order() -> None:
    first = ActionRequest(
        action_name="restart_service",
        arguments={"service_name": "demo-web.service", "timeout": 10},
        reason="The service is confirmed unhealthy",
    )
    second = ActionRequest(
        action_name="restart_service",
        arguments={"timeout": 10, "service_name": "demo-web.service"},
        reason="The service is confirmed unhealthy",
    )

    assert first.action_id != second.action_id
    assert first.fingerprint == second.fingerprint


def test_action_request_is_a_proposal_not_authorization() -> None:
    request = ActionRequest(
        action_name="restart_service",
        arguments={"service_name": "demo-web.service"},
        reason="The service is confirmed unhealthy",
    )

    assert request.action_name == "restart_service"
    assert request.requested_by == "agent"
    assert len(request.fingerprint) == 64  # SHA-256 hexadecimal digest
    with pytest.raises(TypeError):
        request.arguments["service_name"] = "another.service"  # type: ignore[index]


def test_action_request_rejects_non_json_serializable_arguments() -> None:
    with pytest.raises(ContractError, match="JSON-serializable"):
        ActionRequest(
            action_name="restart_service",
            arguments={"unsupported": object()},
            reason="Test invalid arguments",
        )


def test_action_request_rejects_naive_datetime() -> None:
    with pytest.raises(ContractError, match="timezone"):
        ActionRequest(
            action_name="restart_service",
            arguments={"service_name": "demo-web.service"},
            reason="Test request",
            requested_at=datetime(2026, 1, 1),
        )


def test_policy_decision_binds_to_action_identity_and_fingerprint() -> None:
    request = ActionRequest(
        action_name="restart_service",
        arguments={"service_name": "demo-web.service"},
        reason="The service is confirmed unhealthy",
    )
    decision = PolicyDecision(
        action_id=request.action_id,
        outcome="approval_required",
        reason="Restart requires explicit approval",
        action_fingerprint=request.fingerprint,
        matched_rule="restart_service",
    )

    assert decision.action_id == request.action_id
    assert decision.action_fingerprint == request.fingerprint
    assert decision.outcome == "approval_required"


def test_policy_decision_rejects_unknown_outcome() -> None:
    with pytest.raises(ContractError, match="Unsupported policy outcome"):
        PolicyDecision(
            action_id="action-1",
            outcome="maybe",  # type: ignore[arg-type]
            reason="Invalid outcome",
            action_fingerprint="fingerprint",
        )


def test_approval_record_is_bound_to_specific_action() -> None:
    request = ActionRequest(
        action_name="restart_service",
        arguments={"service_name": "demo-web.service"},
        reason="The service is confirmed unhealthy",
    )
    approval = ApprovalRecord(
        action_id=request.action_id,
        action_fingerprint=request.fingerprint,
        approved=True,
        approver="test-operator",
        reason="Approved for the isolated test service",
        decided_at=datetime.now(timezone.utc),
    )

    assert approval.approved is True
    assert approval.action_id == request.action_id
    assert approval.action_fingerprint == request.fingerprint


def test_approval_record_rejects_naive_datetime() -> None:
    with pytest.raises(ContractError, match="timezone"):
        ApprovalRecord(
            action_id="action-1",
            action_fingerprint="fingerprint",
            approved=True,
            approver="test-operator",
            reason="Test approval",
            decided_at=datetime(2026, 1, 1),
        )


def test_incident_context_starts_open() -> None:
    incident = IncidentContext(user_request="Investigate failed service")

    assert incident.status == "open"
    assert incident.steps == 0
    assert incident.evidence == []
    assert incident.findings == []
    assert incident.incident_id


def test_incident_context_rejects_empty_request_and_negative_steps() -> None:
    with pytest.raises(ContractError, match="must not be empty"):
        IncidentContext(user_request="   ")

    with pytest.raises(ContractError, match="non-negative"):
        IncidentContext(user_request="Investigate disk pressure", steps=-1)
