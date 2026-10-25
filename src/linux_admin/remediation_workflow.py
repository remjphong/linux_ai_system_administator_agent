"""Evidence-gated interactive remediation workflow.

Only proposes a service restart when the user explicitly named one systemd unit
and read-only evidence reports that exact unit as failed. The LLM never chooses
or authorizes the state-changing action; PolicyEngine and ControlledExecutor do.
"""

from __future__ import annotations

import getpass
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from linux_admin.audit import AuditLogger
from linux_admin.config import AppConfig
from linux_admin.contracts import (
    ActionRequest,
    ApprovalRecord,
    IncidentContext,
    ToolResult,
)
from linux_admin.control import ApprovalManager, ControlledExecutor, PolicyEngine
from linux_admin.registry import ToolRegistry
from linux_admin.verification import RecoveryManager

_SERVICE_RE = re.compile(r"\b[A-Za-z0-9_.@-]+\.service\b")
_NO_CHANGE_PHRASES = (
    "do not restart", "don't restart", "no restart", "without restarting",
    "do not change", "don't change", "leave it alone",
    "không khởi động lại", "đừng khởi động lại", "không restart",
    "đừng restart", "không thay đổi", "chỉ phân tích", "chỉ kiểm tra",
)


@dataclass(frozen=True)
class RemediationProposal:
    """A deterministic, evidence-backed proposal; never an authorization."""

    request: ActionRequest
    title: str
    rationale: str
    evidence: tuple[str, ...]
    expected_result: str
    risk_note: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "action_name": self.request.action_name,
            "arguments": dict(self.request.arguments),
            "reason": self.rationale,
            "evidence": list(self.evidence),
            "expected_result": self.expected_result,
            "risk_note": self.risk_note,
            "action_id": self.request.action_id,
            "action_fingerprint": self.request.fingerprint,
        }


def build_remediation_proposal(
    incident: IncidentContext,
    config: AppConfig,
    registry: ToolRegistry,
) -> RemediationProposal | None:
    """Build a restart proposal only for an explicitly named failed service.

    A generic "machine is slow" request is deliberately not mapped to a restart:
    CPU/RAM snapshots do not establish which service is safe to restart.
    """
    request_text = incident.user_request.strip()
    folded = request_text.casefold()
    if any(phrase in folded for phrase in _NO_CHANGE_PHRASES):
        return None

    names = {match.group(0) for match in _SERVICE_RE.finditer(request_text)}
    if len(names) != 1:
        return None
    service_name = next(iter(names))

    action_spec = registry.get_spec("restart_service")
    if action_spec is None or not action_spec.changes_system:
        return None

    matching_result = None
    for result in reversed(incident.evidence):
        if result.tool_name != "get_service_status" or not result.ok:
            continue
        if result.data.get("service_name") == service_name:
            matching_result = result
            break

    if matching_result is None:
        return None
    data = matching_result.data
    if data.get("load_state") == "not-found" or data.get("active_state") != "failed":
        return None

    load_state = str(data.get("load_state", "unknown"))
    result_value = str(data.get("result", "unknown"))
    evidence = (
        f"Read-only systemd inspection found {service_name} in active_state=failed.",
        f"The observed unit load_state is {load_state}; last systemd result is {result_value}.",
    )
    action_request = ActionRequest(
        action_name="restart_service",
        arguments={"service_name": service_name},
        reason=(
            f"Read-only investigation found explicitly named service {service_name} "
            "in failed state; request operator approval before attempting restart."
        ),
        requested_by="local-cli-agent-workflow",
    )
    return RemediationProposal(
        request=action_request,
        title=f"Restart failed service {service_name}",
        rationale=(
            "The requested unit is present but systemd reports it as failed. "
            "A restart may restore service availability, but may not resolve the underlying cause."
        ),
        evidence=evidence,
        expected_result=(
            "The service health check reports active after restart. This verifies service state, "
            "not full application correctness."
        ),
        risk_note=(
            "Restarting interrupts this service briefly and can discard in-memory work. "
            "No action will run unless policy permits it and the operator types APPROVE."
        ),
    )


def _problem_resolution(
    status: str,
    message: str,
    checks: Sequence[dict[str, Any]] = (),
) -> dict[str, Any]:
    """Report the original problem's outcome separately from action execution."""
    return {
        "status": status,
        "resolved": status == "resolved",
        "message": message,
        "checks": list(checks),
    }


def no_proposal_result(
    user_request: str,
    findings: Sequence[str] = (),
    *,
    investigation_status: str = "completed",
) -> dict[str, Any]:
    """Explain why no system change is proposed for the diagnosed incident."""
    classification = "inconclusive"
    for finding in findings:
        match = re.search(r"classification=([a-z_]+)", finding)
        if match:
            classification = match.group(1)
            break

    folded = user_request.casefold()
    is_vietnamese = any(
        marker in folded
        for marker in (
            "kiểm tra", "phân tích", "mạng", "dịch vụ", "lỗi",
            "bảo mật", "ổ đĩa", "nhật ký", "máy", "tại sao",
            "khắc phục", "sửa lỗi", "không truy cập được",
        )
    )

    vn_labels = {
        "endpoint_reachable": "endpoint kiểm tra đã phản hồi ở tầng HTTP",
        "endpoint_unreachable": "endpoint kiểm tra không kết nối được tại thời điểm kiểm tra",
        "http_server_error": "endpoint trả về lỗi HTTP phía máy chủ",
        "http_client_error": "endpoint trả về mã lỗi HTTP phía client",
        "service_missing": "không tìm thấy systemd unit được yêu cầu",
        "service_failed": "systemd báo dịch vụ đang ở trạng thái failed",
        "service_running": "systemd báo dịch vụ đang active",
        "service_inactive": "systemd báo dịch vụ đang inactive",
        "inconclusive": "chưa đủ bằng chứng để kết luận",
        "network_state_observed": "đã quan sát trạng thái mạng cục bộ",
        "service_inventory_clean": "không tìm thấy dịch vụ systemd ở trạng thái failed",
        "service_inventory_failed": "đã phát hiện dịch vụ systemd lỗi",
        "security_posture_review": "đã kiểm tra các mục bảo mật được đăng ký",
        "no_recent_errors": "không tìm thấy bản ghi lỗi trong khoảng thời gian được truy vấn",
        "recent_system_errors": "đã tìm thấy thông báo lỗi hệ thống gần đây",
        "resource_snapshot_no_pressure_signal": "snapshot chưa cho thấy áp lực tài nguyên vượt ngưỡng",
        "resource_pressure": "snapshot có dấu hiệu áp lực tài nguyên",
    }
    en_labels = {
        "endpoint_reachable": "the checked endpoint responded at the HTTP layer",
        "endpoint_unreachable": "the checked endpoint was unreachable during the probe",
        "http_server_error": "the endpoint returned an HTTP server-error response",
        "http_client_error": "the endpoint returned an HTTP client-error response",
        "service_missing": "the requested systemd unit was not found",
        "service_failed": "systemd reported the service as failed",
        "service_running": "systemd reported the service as active",
        "service_inactive": "systemd reported the service as inactive",
        "inconclusive": "there is insufficient evidence to reach a conclusion",
        "network_state_observed": "local network state was observed",
        "service_inventory_clean": "no failed systemd units were reported",
        "service_inventory_failed": "failed systemd units were reported",
        "security_posture_review": "the registered security checks were reviewed",
        "no_recent_errors": "no journal errors were returned in the queried time window",
        "recent_system_errors": "recent system error messages were found",
        "resource_snapshot_no_pressure_signal": "the resource snapshot showed no configured pressure threshold breach",
        "resource_pressure": "the resource snapshot contained pressure indicators",
    }

    vn_next = {
        "endpoint_reachable": "Endpoint kiểm tra đã phản hồi, nhưng điều này không chứng minh mọi dịch vụ Internet đều hoạt động. Nếu vẫn có sự cố, hãy kiểm tra đúng endpoint của ứng dụng bị ảnh hưởng.",
        "endpoint_unreachable": "So sánh kết quả TCP và HTTP, kiểm tra DNS hoặc gateway; chưa đủ căn cứ để quy kết nguyên nhân cho một dịch vụ cụ thể.",
        "http_server_error": "Kiểm tra log ứng dụng, trạng thái service và các dependency liên quan đến endpoint.",
        "http_client_error": "Kiểm tra đường dẫn URL, thông tin xác thực và chính sách truy cập của endpoint.",
        "service_missing": "Kiểm tra tên unit systemd chính xác và xác nhận dịch vụ có được cài đặt hay không.",
        "service_failed": "Kiểm tra status và log của đúng dịch vụ bị lỗi trước khi chọn biện pháp xử lý.",
        "service_running": "Kiểm tra health check ở cấp ứng dụng nếu chức năng vẫn lỗi dù systemd báo active.",
        "service_inactive": "Xác nhận dịch vụ có được kỳ vọng phải chạy liên tục hay không; inactive không phải lúc nào cũng là lỗi.",
        "inconclusive": "Thu thập thêm bằng chứng chỉ đọc từ subsystem liên quan trước khi xác định nguyên nhân hoặc chọn hành động.",
        "network_state_observed": (
            "Interface đang up chưa chứng minh Internet hoạt động. Kiểm tra "
            "gateway hoặc DNS, sau đó thử một endpoint cụ thể."
        ),
        "service_inventory_clean": (
            "Truy vấn không thấy unit systemd nào ở trạng thái failed. Nếu ứng "
            "dụng vẫn lỗi, xác định đúng unit rồi kiểm tra status, journal hoặc "
            "health check của ứng dụng."
        ),
        "service_inventory_failed": (
            "Kiểm tra status và nhật ký của các unit lỗi; xác định unit liên "
            "quan trước khi đề xuất hành động khắc phục."
        ),
        "security_posture_review": (
            "Rà soát từng security check và đánh giá tác động trước khi đề xuất "
            "thay đổi cấu hình hoặc policy."
        ),
        "no_recent_errors": (
            "Mở rộng khoảng thời gian truy vấn hoặc kiểm tra log riêng của ứng "
            "dụng. Không có bản ghi trong cửa sổ hiện tại không chứng minh hệ "
            "thống hoàn toàn khỏe mạnh."
        ),
        "recent_system_errors": (
            "Đối chiếu thời điểm thông báo lỗi với sự cố rồi kiểm tra subsystem "
            "hoặc dịch vụ liên quan."
        ),
        "resource_snapshot_no_pressure_signal": (
            "Đo CPU/RAM nhiều lần khi hiện tượng chậm xảy ra; kiểm tra thêm disk "
            "I/O, tiến trình và độ trễ ứng dụng."
        ),
        "resource_pressure": (
            "Lặp lại phép đo để xác nhận áp lực có kéo dài không, sau đó đối "
            "chiếu tiến trình và disk I/O trước khi chọn biện pháp."
        ),
    }
    en_next = {
        "endpoint_reachable": "The checked endpoint responded, but this does not prove every Internet service is working. Probe the specific affected application if the problem persists.",
        "endpoint_unreachable": "Compare TCP and HTTP results and check DNS or gateway reachability before attributing the cause to a specific service.",
        "http_server_error": "Inspect application logs, service state, and dependencies relevant to the endpoint.",
        "http_client_error": "Check the URL path, authentication, and endpoint access policy.",
        "service_missing": "Verify the exact systemd unit name and whether the service is installed.",
        "service_failed": "Inspect the failed service status and logs before selecting remediation.",
        "service_running": "Run an application-level health check if functionality is still failing despite systemd reporting active.",
        "service_inactive": "Confirm whether the unit is expected to run continuously; inactive does not always mean failure.",
        "inconclusive": "Collect additional read-only evidence from the affected subsystem before selecting remediation.",
        "network_state_observed": (
            "Interface state does not prove Internet access. Check a gateway "
            "or DNS resolver, then probe a specific endpoint."
        ),
        "service_inventory_clean": (
            "No failed systemd units were reported. If an application remains "
            "unhealthy, inspect its unit status, logs, or health check."
        ),
        "service_inventory_failed": (
            "Inspect failed units and their logs, then identify which unit is "
            "relevant before proposing remediation."
        ),
        "security_posture_review": (
            "Review individual security checks and assess the impact before "
            "proposing configuration or policy changes."
        ),
        "no_recent_errors": (
            "Expand the journal time window or inspect application-specific "
            "logs; an empty query does not prove the system is healthy."
        ),
        "recent_system_errors": (
            "Correlate error timestamps with the incident and inspect the "
            "relevant subsystem."
        ),
        "resource_snapshot_no_pressure_signal": (
            "Collect repeated CPU/RAM samples while the slowdown occurs and "
            "inspect disk I/O, processes, and application latency."
        ),
        "resource_pressure": (
            "Repeat measurements to determine whether pressure persists, then "
            "inspect processes and disk I/O before selecting remediation."
        ),
    }

    refused_target = None
    for finding in findings:
        match = re.search(
            r"connection to ([^\\s]+) was refused by the target endpoint",
            finding,
            re.IGNORECASE,
        )
        if match:
            refused_target = match.group(1)
            break

    if is_vietnamese:
        label = vn_labels.get(
            classification, "chưa đủ bằng chứng để kết luận"
        )
        next_step = vn_next.get(
            classification,
            "Thu thập thêm bằng chứng chỉ đọc từ subsystem liên quan trước khi chọn hành động khắc phục.",
        )
        if classification == "endpoint_unreachable" and refused_target:
            no_listener_evidence = any(
                "local socket inspection reported zero listening sockets"
                in finding.casefold()
                for finding in findings
            )
            if no_listener_evidence:
                next_step = (
                    f"Kết nối TCP tới {refused_target} bị từ chối và kiểm tra "
                    "socket cục bộ không tìm thấy listener trên cổng đó. "
                    "Xác định dịch vụ dự kiến cung cấp endpoint từ cấu hình "
                    "ứng dụng hoặc deployment, sau đó kiểm tra trạng thái "
                    "dịch vụ và cấu hình địa chỉ/cổng bind. Không tự động "
                    "restart dịch vụ chưa xác định."
                )
            else:
                next_step = (
                    f"Kết nối TCP tới {refused_target} bị từ chối. "
                    "Xác minh listener và dịch vụ sở hữu endpoint, sau đó "
                    "kiểm tra status và log. Không tự động restart dịch vụ "
                    "chưa xác định."
                )
        message = (
            f"Kết quả hiện tại: {label}. Không có hành động thay đổi hệ thống "
            "nào được đề xuất vì chưa xác định được biện pháp đủ bằng chứng "
            "và được policy cho phép. Không có thay đổi nào được thực hiện."
        )
    else:
        label = en_labels.get(
            classification,
            "there is insufficient evidence to reach a conclusion",
        )
        next_step = en_next.get(
            classification,
            "Collect additional read-only evidence from the affected subsystem before selecting remediation.",
        )
        if classification == "endpoint_unreachable" and refused_target:
            next_step = (
                f"The TCP connection to {refused_target} was refused. "
                "Identify the process listening on that port and the service "
                "owning the endpoint, then inspect its status and logs. Do not "
                "restart an unidentified service automatically."
            )
        message = (
            f"Current finding: {label}. No state-changing action was proposed "
            "because a suitable, evidence-backed, policy-compliant action has "
            "not been established. No changes were made."
        )

    if investigation_status == "completed":
        problem_resolution = _problem_resolution(
            "diagnosis_only",
            "The investigation completed, but no state-changing action "
            "was proposed or verified.",
        )
    else:
        problem_resolution = _problem_resolution(
            "not_attempted",
            f"The investigation ended with status={investigation_status}. "
            "No change was executed and resolution was not verified.",
        )
        if is_vietnamese:
            message = (
                "Cuộc điều tra chưa hoàn tất với đủ bằng chứng đáng tin cậy. "
                "Không có hành động thay đổi hệ thống nào được thực hiện."
            )
            next_step = (
                "Kiểm tra findings và lỗi của các công cụ; bổ sung thông tin "
                "liên quan rồi chạy lại điều tra trước khi đề xuất thay đổi."
            )
        else:
            message = (
                "The investigation did not complete with sufficient reliable "
                "evidence. No state-changing action was performed."
            )
            next_step = (
                "Review the findings and tool failures, provide more specific "
                "subsystem context, and rerun the investigation before proposing changes."
            )

    # Ask for missing diagnostic context only when it can help continue
    # an investigation. A check-only request must not be pushed into remediation.
    follow_up_question = None
    if investigation_status == "completed":
        repair_phrases = (
            "khắc phục", "sửa lỗi", "sửa chữa", "khởi động lại",
            "restart", "fix", "repair", "restore", "recover", "resolve",
        )
        check_only_phrases = (
            "kiểm tra endpoint", "kiểm tra trạng thái",
            "kiểm tra kết nối", "có truy cập được không",
            "có hoạt động không", "chỉ kiểm tra", "chỉ phân tích",
            "check endpoint", "check status", "check connectivity",
            "check whether", "check if", "is it reachable",
            "is it accessible", "is it working", "what is the status",
            "only check", "just check", "read-only",
        )
        explicit_repair = any(
            phrase in folded for phrase in repair_phrases
        )
        explicitly_check_only = (
            any(phrase in folded for phrase in _NO_CHANGE_PHRASES)
            or (
                not explicit_repair
                and any(phrase in folded for phrase in check_only_phrases)
            )
        )

        if not explicitly_check_only:
            if is_vietnamese:
                if classification == "endpoint_unreachable":
                    if refused_target:
                        follow_up_question = (
                            f"Endpoint {refused_target} dự kiến do ứng dụng "
                            "hoặc systemd unit nào cung cấp?"
                        )
                    else:
                        follow_up_question = (
                            "Endpoint hoặc ứng dụng cụ thể nào đang bị ảnh hưởng?"
                        )
                elif classification == "service_missing":
                    follow_up_question = (
                        "Tên systemd unit này có chính xác không, và dịch vụ "
                        "có được kỳ vọng cài đặt trên máy này không?"
                    )
                elif classification == "resource_pressure":
                    follow_up_question = (
                        "Hiện tượng chậm bắt đầu từ khi nào và ứng dụng nào "
                        "bị ảnh hưởng rõ nhất?"
                    )
                elif classification == "service_inventory_failed":
                    follow_up_question = (
                        "Dịch vụ nào trong danh sách failed liên quan trực tiếp "
                        "đến sự cố ban đầu?"
                    )
                elif classification in {
                    "http_server_error", "http_client_error"
                }:
                    follow_up_question = (
                        "Ứng dụng hoặc systemd unit nào dự kiến cung cấp endpoint này?"
                    )
                else:
                    follow_up_question = (
                        "Triệu chứng cụ thể nào vẫn còn xảy ra và ứng dụng "
                        "hoặc dịch vụ nào bị ảnh hưởng?"
                    )
            else:
                if classification == "endpoint_unreachable":
                    if refused_target:
                        follow_up_question = (
                            f"Which application or systemd unit is expected "
                            f"to provide endpoint {refused_target}?"
                        )
                    else:
                        follow_up_question = (
                            "Which specific endpoint or application is affected?"
                        )
                elif classification == "service_missing":
                    follow_up_question = (
                        "Is this systemd unit name correct, and should the "
                        "service be installed on this host?"
                    )
                elif classification == "resource_pressure":
                    follow_up_question = (
                        "When did the slowdown begin, and which application "
                        "is most affected?"
                    )
                elif classification in {
                    "http_server_error", "http_client_error"
                }:
                    follow_up_question = (
                        "Which application or systemd unit is expected to "
                        "provide this endpoint?"
                    )
                else:
                    follow_up_question = (
                        "What specific symptom remains, and which application "
                        "or service is affected?"
                    )

    return {
        "status": "not_proposed",
        "message": message,
        "recommended_next_step": next_step,
        "follow_up_question": follow_up_question,
        "changes_made": False,
        "problem_resolution": problem_resolution,
    }


def _surface_pre_execution_audit_failure(
    output: dict[str, Any],
    action_result: Any,
) -> bool:
    """Expose an audit failure without claiming that an action was executed."""
    if action_result.data.get("audit_failed_before_execution") is not True:
        return False

    output.update(
        status="audit_failure_before_execution",
        action=action_result.to_dict(),
        changes_made=False,
        message=(
            action_result.error
            or "Required audit persistence failed before execution."
        ),
    )
    output["problem_resolution"] = _problem_resolution(
        "not_attempted",
        "Required audit persistence failed before the action began. "
        "No system change was made; the original problem remains unverified.",
    )
    return True


def run_remediation_workflow(
    proposal: RemediationProposal,
    *,
    incident_id: str,
    config: AppConfig,
    registry: ToolRegistry,
    audit: AuditLogger | None,
    diagnosis_findings: Sequence[str] = (),
    verification_url: str | None = None,
    endpoint_verification_required: bool = False,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], Any] = print,
) -> dict[str, Any]:
    """Present, gate, execute and verify one proposed action without auto-retry."""
    request = proposal.request
    policy_engine = PolicyEngine(config, registry)
    decision = policy_engine.evaluate(request)
    output: dict[str, Any] = {
        "status": "proposed",
        "proposal": proposal.to_dict(),
        "policy": {"outcome": decision.outcome, "reason": decision.reason},
        "action": None,
        "verification": None,
        "endpoint_verification": None,
        "changes_made": False,
        "problem_resolution": _problem_resolution(
            "not_attempted",
            "The proposed change has not yet been executed or verified.",
        ),
    }

    output_fn("\nINVESTIGATION FINDINGS")
    for finding in diagnosis_findings:
        output_fn(f"- {finding}")
    output_fn("\nREMEDIATION PROPOSAL")
    output_fn(f"Action: {request.action_name} {dict(request.arguments)!r}")
    output_fn(f"Reason: {proposal.rationale}")
    output_fn(f"Evidence: {'; '.join(proposal.evidence)}")
    output_fn(f"Expected verification: {proposal.expected_result}")
    output_fn(f"Risk: {proposal.risk_note}")
    output_fn(f"Policy: {decision.outcome} — {decision.reason}")

    executor = ControlledExecutor(
        config=config,
        registry=registry,
        audit=audit,
        policy_engine=policy_engine,
        incident_id=incident_id,
    )

    # Even denied and dry-run proposals go through the controlled executor so
    # policy outcomes and no-op decisions are audited through the existing path.
    if decision.outcome == "deny":
        action_result = executor.execute(request, None)
        if _surface_pre_execution_audit_failure(output, action_result):
            return output
        output.update(
            status="blocked_by_policy",
            action=action_result.to_dict(),
            message=f"Action not executed: {decision.reason}",
        )
        output["problem_resolution"] = _problem_resolution(
            "blocked_by_policy",
            "Policy blocked the proposed action. The original problem "
            "has not been verified as resolved.",
        )
        return output

    if config.agent.dry_run:
        action_result = executor.execute(request, None)
        if _surface_pre_execution_audit_failure(output, action_result):
            return output
        output.update(
            status="dry_run_no_change",
            action=action_result.to_dict(),
            message="Dry-run is enabled; the proposal was not executed and no change was made.",
        )
        output["problem_resolution"] = _problem_resolution(
            "not_attempted",
            "Dry-run prevented the change. The original problem remains "
            "unverified and no state change was made.",
        )
        return output

    approval: ApprovalRecord | None = None
    if decision.outcome == "approval_required":
        output_fn("Approval is required. Type APPROVE exactly; any other response declines.")
        manager = ApprovalManager()
        try:
            approval = manager.request_console_approval(
                request, input_fn=input_fn, output_fn=output_fn
            )
        except EOFError:
            approval = manager.create_record(
                request,
                approved=False,
                approver=getpass.getuser() or "local-operator",
                reason="Approval input ended; fail closed",
            )

        if not approval.approved:
            action_result = executor.execute(request, approval)
            if _surface_pre_execution_audit_failure(output, action_result):
                return output
            output.update(
                status="rejected",
                action=action_result.to_dict(),
                message="The operator declined the proposal. No state-changing tool was executed.",
            )
            output["problem_resolution"] = _problem_resolution(
                "rejected",
                "The user declined the proposal. No change was executed; "
                "the original problem has not been verified as resolved.",
            )
            return output

    action_result = executor.execute(request, approval)
    if _surface_pre_execution_audit_failure(output, action_result):
        return output
    output["action"] = action_result.to_dict()
    output["changes_made"] = bool(
        action_result.data.get("executed") is True
        or action_result.data.get("audit_failed_after_execution") is True
    )

    if not output["changes_made"]:
        output.update(
            status="execution_failed",
            message=action_result.error or "The action did not execute.",
        )
        output["problem_resolution"] = _problem_resolution(
            "unresolved",
            "The proposed action did not execute. The original problem "
            "has not been verified as resolved.",
        )
        return output

    verifier = RecoveryManager(max_attempts=2, interval_seconds=1.0)
    service_name = str(request.arguments["service_name"])
    verified = verifier.verify_until_healthy(
        lambda: registry.invoke(
            "verify_service_health",
            {"service_name": service_name},
        )
    )
    output["verification"] = verified.to_dict()

    endpoint_verified = None
    if verification_url:
        endpoint_verified = verifier.verify_until_healthy(
            lambda: registry.invoke(
                "verify_endpoint",
                {"url": verification_url},
            )
        )
        output["endpoint_verification"] = endpoint_verified.to_dict()

    verification_results = [("service_state", verified)]
    if endpoint_verified is not None:
        verification_results.append(("original_endpoint", endpoint_verified))

    checks = [
        {
            "target": target,
            "status": result.status,
            "healthy": result.ok and result.data.get("healthy") is True,
        }
        for target, result in verification_results
    ]

    audit_error = False
    if audit is not None:
        try:
            audit.record_event(
                event_type="action.verification_finished",
                incident_id=incident_id,
                action_id=request.action_id,
                details={
                    "verification_status": verified.status,
                    "healthy": verified.data.get("healthy") is True,
                    "attempts": verified.data.get("verification_attempts", []),
                    "endpoint_verification_status": (
                        endpoint_verified.status
                        if endpoint_verified is not None
                        else None
                    ),
                    "endpoint_healthy": (
                        endpoint_verified.data.get("healthy") is True
                        if endpoint_verified is not None
                        else None
                    ),
                    "endpoint_attempts": (
                        endpoint_verified.data.get("verification_attempts", [])
                        if endpoint_verified is not None
                        else []
                    ),
                },
            )
        except Exception:  # noqa: BLE001 - do not claim recovery if audit fails.
            audit_error = True
            output["verification_audit_error"] = True

    all_healthy = all(check["healthy"] for check in checks)

    if audit_error:
        output.update(
            status="audit_failure_after_execution",
            message=(
                "The action may have executed and health checks were collected, "
                "but verification could not be audited. Do not claim full recovery."
            ),
            problem_resolution=_problem_resolution(
                "verification_failed",
                "Post-action checks may have run, but the verification audit "
                "failed. Recovery cannot be declared complete.",
                checks,
            ),
        )
    elif (
        endpoint_verification_required
        and endpoint_verified is None
        and verified.ok
        and verified.data.get("healthy") is True
    ):
        output.update(
            status="recovery_failed",
            message=(
                "The service health check passed, but the original request "
                "included an endpoint that could not be selected unambiguously "
                "for post-action verification. The original problem is not "
                "confirmed as resolved."
            ),
            problem_resolution=_problem_resolution(
                "verification_failed",
                "Service health passed, but the requested endpoint could not "
                "be verified after the action.",
                checks,
            ),
        )
    elif all_healthy:
        if endpoint_verified is not None:
            message = (
                "The service health check and the endpoint from the original "
                "request both passed post-action verification. This confirms "
                "these checks, not every application function."
            )
        else:
            message = (
                "The service health check reports active after the action. "
                "Service state is verified; application-level correctness "
                "has not been independently tested."
            )
        output.update(
            status="verified_recovered",
            message=message,
            problem_resolution=_problem_resolution(
                "resolved",
                (
                    "The service and original endpoint both passed verification."
                    if endpoint_verified is not None
                    else "The requested service-state target passed verification; "
                    "application-level behavior was not independently tested."
                ),
                checks,
            ),
        )
    else:
        failed_results = [
            result
            for _, result in verification_results
            if not (result.ok and result.data.get("healthy") is True)
        ]

        def has_observed_unhealthy_state(result: ToolResult) -> bool:
            data = result.data
            active_state = data.get("active_state")
            if isinstance(active_state, str) and active_state != "active":
                return True
            if data.get("load_state") == "not-found":
                return True
            if isinstance(data.get("reachable"), bool):
                return data["reachable"] is False or (
                    isinstance(data.get("status_code"), int)
                    and not isinstance(data.get("status_code"), bool)
                )
            return (
                isinstance(data.get("status_code"), int)
                and not isinstance(data.get("status_code"), bool)
            )

        observed_failure = any(
            has_observed_unhealthy_state(result) for result in failed_results
        )
        some_healthy = any(check["healthy"] for check in checks)

        if len(checks) > 1 and some_healthy and observed_failure:
            resolution_status = "partially_resolved"
            resolution_message = (
                "At least one post-action health check passed, but another "
                "target remains unhealthy. The original problem is not fully resolved."
            )
        elif observed_failure:
            resolution_status = "unresolved"
            resolution_message = (
                "Post-action evidence shows that the expected healthy state "
                "was not achieved. The original problem remains unresolved."
            )
        else:
            resolution_status = "verification_failed"
            resolution_message = (
                "Post-action checks could not determine the health state "
                "reliably. Do not claim that the original problem is resolved."
            )

        failed_result = failed_results[0]
        output["recovery_disposition"] = RecoveryManager.handle_recovery_failure(
            incident_id=incident_id,
            action_name=request.action_name,
            last_result=failed_result,
        )
        output.update(
            status="recovery_failed",
            message=(
                "The action ran or may have run, but one or more health checks "
                "did not confirm recovery. No additional state-changing action "
                "was attempted."
            ),
            problem_resolution=_problem_resolution(
                resolution_status, resolution_message, checks
            ),
        )
    return output
