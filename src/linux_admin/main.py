"""CLI entry point for configuration checks and read-only investigations."""

from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any
from urllib.parse import urlsplit

from linux_admin import __version__
from linux_admin.agent import Agent
from linux_admin.audit import AuditError, AuditLogger
from linux_admin.config import ConfigurationError, load_config
from linux_admin.contracts import ActionRequest, IncidentContext
from linux_admin.control import ApprovalManager, ControlledExecutor, PolicyEngine
from linux_admin.registry import ToolRegistry
from linux_admin.remediation_workflow import (
    build_remediation_proposal,
    no_proposal_result,
    run_remediation_workflow,
)
from linux_admin.tools import register_builtin_tools
from linux_admin.verification import RecoveryManager


def build_parser() -> argparse.ArgumentParser:
    """Construct the command-line interface."""
    parser = argparse.ArgumentParser(
        prog="linux-admin",
        description="Safety-first Linux system administration agent",
    )
    parser.add_argument(
        "--version", action="version", version=f"linux-admin-agent {__version__}"
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check-config",
        action="store_true",
        help="Load and validate YAML configuration, then exit",
    )
    mode.add_argument(
        "--list-tools",
        action="store_true",
        help="List registered tools and whether they can change the system",
    )
    mode.add_argument(
        "--investigate",
        metavar="REQUEST",
        help="Run a bounded, read-only incident investigation",
    )
    mode.add_argument(
        "--restart-service",
        metavar="SERVICE",
        help=(
            "Request a controlled restart (disabled by default; "
            "requires policy and approval)"
        ),
    )
    parser.add_argument(
        "--config-dir",
        metavar="DIR",
        help=(
            "Load agent.yaml, policy.yaml, and services.yaml from DIR "
            "instead of the default project config directory."
        ),
    )
    parser.add_argument(
        "--reason",
        default="Operator-requested service restart",
        help="Reason recorded for --restart-service",
    )
    parser.add_argument(
        "request_text",
        nargs="*",
        metavar="REQUEST_TEXT",
        help=(
            "Natural-language request; when used alone, "
            "run an investigation."
        ),
    )

    return parser


_REQUEST_URL_PATTERN = re.compile(r"https?://\S+", re.IGNORECASE)


def _extract_explicit_http_urls(request: str) -> list[str]:
    """Return distinct, valid HTTP(S) URLs explicitly written by the user."""
    urls: list[str] = []
    for match in _REQUEST_URL_PATTERN.finditer(request):
        candidate = match.group(0).rstrip(".,;:!?)]}")
        try:
            parsed = urlsplit(candidate)
            hostname = parsed.hostname
        except ValueError:
            continue

        if (
            parsed.scheme.casefold() not in {"http", "https"}
            or not hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            continue
        if candidate not in urls:
            urls.append(candidate)
    return urls


def _select_verification_target(
    request: str,
) -> tuple[str | None, bool]:
    """Choose a verification URL only when the request has one unambiguous URL."""
    url_mentions = list(_REQUEST_URL_PATTERN.finditer(request))
    urls = _extract_explicit_http_urls(request)

    verification_url = (
        urls[0] if len(url_mentions) == 1 and len(urls) == 1 else None
    )
    return verification_url, bool(url_mentions)


def _investigation_exit_code(
    incident_status: str,
    remediation_status: str,
) -> int:
    """Return CLI operation status, independently of problem resolution."""
    if incident_status == "failed":
        return 1

    failed_remediation_statuses = {
        "execution_failed",
        "recovery_failed",
        "audit_failure_before_execution",
        "audit_failure_after_execution",
    }
    return int(remediation_status in failed_remediation_statuses)


def _extract_external_references(evidence: list[Any]) -> list[dict[str, Any]]:
    """Extract bounded, validated Tavily references from tool evidence."""
    from urllib.parse import urlsplit

    references: list[dict[str, Any]] = []
    seen_urls: set[str] = set()

    for result in evidence:
        if len(references) >= 5:
            break
        if getattr(result, "tool_name", None) != "tavily_web_search":
            continue
        if not getattr(result, "ok", False):
            continue

        data = getattr(result, "data", None)
        if not isinstance(data, dict):
            continue

        items = data.get("results")
        if not isinstance(items, list):
            continue

        source = data.get("source")
        if not isinstance(source, str) or not source.strip():
            source = "Tavily Search API"

        for item in items:
            if len(references) >= 5:
                break
            if not isinstance(item, dict):
                continue

            title = item.get("title")
            url = item.get("url")
            content = item.get("content", "")
            score = item.get("score")

            if (
                not isinstance(title, str)
                or not title.strip()
                or not isinstance(url, str)
                or len(url) > 2048
            ):
                continue

            try:
                parsed_url = urlsplit(url)
                valid_url = (
                    parsed_url.scheme in {"https", "http"}
                    and bool(parsed_url.hostname)
                    and parsed_url.username is None
                    and parsed_url.password is None
                )
            except ValueError:
                valid_url = False

            if not valid_url or url in seen_urls:
                continue

            if not isinstance(content, str):
                content = ""
            if (
                isinstance(score, bool)
                or not isinstance(score, (int, float))
            ):
                score = None

            seen_urls.add(url)
            references.append(
                {
                    "title": title.strip()[:200],
                    "url": url,
                    "snippet": content.strip()[:1200],
                    "score": score,
                    "source": source.strip()[:100],
                    "untrusted_external_content": True,
                }
            )

    return references


def _incident_to_dict(incident: IncidentContext) -> dict[str, Any]:
    """Convert an incident result into JSON-compatible data for the CLI."""
    return {
        "incident_id": incident.incident_id,
        "request": incident.user_request,
        "status": incident.status,
        "steps": incident.steps,
        "findings": incident.findings,
        "evidence": [result.to_dict() for result in incident.evidence],
        "external_references": _extract_external_references(incident.evidence),
        "started_at": incident.started_at.isoformat(),
    }




def _run_investigation(
    agent: Agent,
    request: str,
    config: Any,
    registry: ToolRegistry,
    audit: AuditLogger | None,
) -> dict[str, Any]:
    """Run one investigation and its existing remediation workflow."""
    incident = agent.run(request)
    output = _incident_to_dict(incident)
    proposal = build_remediation_proposal(incident, config, registry)

    verification_url, endpoint_verification_required = (
        _select_verification_target(request)
    )

    if proposal is None:
        output["remediation"] = no_proposal_result(
            request,
            incident.findings,
            investigation_status=incident.status,
        )
    else:
        output["remediation"] = run_remediation_workflow(
            proposal,
            incident_id=incident.incident_id,
            config=config,
            registry=registry,
            audit=audit,
            diagnosis_findings=incident.findings,
            verification_url=verification_url,
            endpoint_verification_required=endpoint_verification_required,
            output_fn=lambda message: print(message, file=sys.stderr),
        )

    return output


def _read_follow_up_answer(question: str) -> str | None:
    """Ask one clarification only in a fully interactive terminal."""
    try:
        interactive = sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, OSError):
        interactive = False

    if not interactive:
        return None

    print(
        f"\nCần làm rõ trước khi tiếp tục:\n{question}",
        file=sys.stderr,
    )
    print(
        "Thông tin bổ sung (nhấn Enter để bỏ qua): ",
        end="",
        file=sys.stderr,
        flush=True,
    )

    try:
        answer = sys.stdin.readline()
    except (EOFError, KeyboardInterrupt, OSError):
        return None

    answer = answer.strip()
    return answer or None



def _is_unknown_follow_up_answer(answer: str) -> bool:
    """Identify answers that provide no additional diagnostic context."""
    normalized = " ".join(answer.casefold().split()).strip(" .,!?:;")
    return normalized in {
        "không xác định",
        "chưa xác định",
        "không xác định được",
        "chưa xác định được",
        "không biết",
        "chưa biết",
        "chưa rõ",
        "không rõ",
        "unknown",
        "not sure",
        "i don't know",
        "i do not know",
        "dont know",
        "idk",
        "n/a",
    }



def _is_test_only_follow_up_answer(answer: str) -> bool:
    """Detect clarification explicitly marked as hypothetical or test-only."""
    normalized = " ".join(answer.casefold().split())
    markers = (
        "chỉ dùng để kiểm thử",
        "chỉ để kiểm thử",
        "chỉ dùng cho mục đích kiểm thử",
        "tên unit giả lập",
        "unit giả lập",
        "giả lập",
        "for testing only",
        "for test purposes only",
        "hypothetical",
        "simulated unit",
        "test-only",
        "test only",
    )
    return any(marker in normalized for marker in markers)




def _is_observation_only_request(request: str) -> bool:
    """Recognize read-only checks even when Vietnamese accents vary."""
    import unicodedata

    normalized = request.casefold().replace("đ", "d")
    normalized = "".join(
        character
        for character in unicodedata.normalize("NFKD", normalized)
        if not unicodedata.combining(character)
    )
    normalized = " ".join(normalized.split())

    # A negated action must not turn a read-only request into a repair request.
    negations = (
        "khong restart",
        "khong khoi dong lai",
        "don't restart",
        "do not restart",
        "no restart",
        "without restarting",
        "khong sua",
        "khong khac phuc",
        "do not fix",
        "don't fix",
    )
    for phrase in negations:
        normalized = normalized.replace(phrase, " ")

    action_markers = (
        "restore", "repair", "fix", "recover", "remediate",
        "resolve the issue", "resolve this",
        "khac phuc", "sua loi", "sua chua",
        "khoi phuc", "khoi dong lai", "restart",
    )
    if any(marker in normalized for marker in action_markers):
        return False

    observation_markers = (
        "kiem tra tinh trang he thong",
        "tinh trang he thong",
        "he thong dang trong tinh trang the nao",
        "he thong dang o tinh trang nao",
        "he thong hien tai the nao",
        "tinh hinh he thong",
        "kiem tra tong the",
        "kiem tra he thong",
        "system health", "health check", "overall system",
        "system status", "system overview",
        "kiem tra cpu", "kiem tra ram", "kiem tra tai nguyen",
        "kiem tra trang thai mang", "trang thai mang",
        "tinh trang mang", "kiem tra mang",
        "cpu", "ram", "memory", "tai nguyen",
        "o dia", "disk usage", "top processes", "tien trinh",
        "kiem tra cac dich vu dang loi",
        "dich vu dang loi", "kiem tra dich vu",
        "failed services", "service status",
        "doc log", "log lien quan", "read logs", "recent errors",
        "check connectivity", "check endpoint",
    )
    return any(marker in normalized for marker in observation_markers)

def main() -> int:
    """Run the selected CLI operation and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args()
    # Allow a natural-language request without --investigate.
    if args.request_text:
        explicit_mode = any((
            args.check_config,
            args.list_tools,
            args.investigate,
            args.restart_service,
        ))
        if explicit_mode:
            parser.error(
                "Use a natural-language request alone, or choose a mode flag; do not combine them."
            )
        args.investigate = " ".join(args.request_text).strip()
        if not args.investigate:
            parser.error("The request cannot be empty.")


    if not (
        args.check_config
        or args.list_tools
        or args.investigate
        or args.restart_service
    ):
        parser.print_help()
        return 0

    try:
        config = (
            load_config(config_dir=args.config_dir)
            if args.config_dir
            else load_config()
        )
    except ConfigurationError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    if args.check_config:
        print(f"Application: {config.name} {config.version}")
        print(f"Project root: {config.project_root}")
        print(f"Agent mode: {config.agent.mode}")
        print(f"Dry-run: {config.agent.dry_run}")
        print(f"Maximum steps: {config.agent.max_steps}")
        print(f"Tool timeout: {config.agent.tool_timeout_seconds:g}s")
        print(f"LLM enabled: {config.llm.enabled}")
        print(f"LLM provider: {config.llm.provider or '(not configured)'}")
        print(f"LLM model: {config.llm.model or '(not configured)'}")
        print(f"Tavily web search enabled: {config.tavily.enabled}")
        print(f"Policy actions loaded: {len(config.policy.actions)}")
        print(f"Service allowlist entries: {len(config.services.allowlist)}")
        print(f"Service restart enabled: {config.services.restart_enabled}")
        print(f"Audit enabled: {config.audit.enabled}")
        print(f"Audit database: {config.audit.database_path}")
        print("Configuration check passed.")
        return 0

    registry = register_builtin_tools(ToolRegistry(), config)

    if args.list_tools:
        for spec in registry.list_tools():
            mode_label = "STATE-CHANGING" if spec.changes_system else "read-only"
            approval = ", approval required" if spec.requires_approval else ""
            print(f"{spec.name}: {mode_label}{approval} — {spec.description}")
        return 0

    audit_logger: AuditLogger | None = None
    try:
        if config.audit.enabled:
            audit_logger = AuditLogger(config.audit.database_path)

        if args.investigate:
            agent = Agent(registry=registry, config=config, audit=audit_logger)
            output = _run_investigation(
                agent, args.investigate, config, registry, audit_logger
            )

            question = output["remediation"].get("follow_up_question")
            if question and _is_observation_only_request(args.investigate):
                output["remediation"]["follow_up_question"] = None
                question = None
            answer = _read_follow_up_answer(question) if question else None

            if answer:
                previous_incident_id = output["incident_id"]

                unknown_answer = _is_unknown_follow_up_answer(answer)
                test_only_answer = _is_test_only_follow_up_answer(answer)

                if unknown_answer or test_only_answer:
                    # Do not investigate unknown or explicitly hypothetical
                    # targets as if they were real services.
                    output["remediation"]["follow_up_question"] = None
                    output["clarification"] = {
                        "answered": True,
                        "status": (
                            "insufficient_context"
                            if unknown_answer
                            else "non_operational_example"
                        ),
                        "previous_incident_id": previous_incident_id,
                        "answer": answer,
                        "context_provided": False,
                    }
                else:
                    clarified_request = (
                        f"{args.investigate}\n\n"
                        f"Additional operator context: {answer}"
                    )
                    output = _run_investigation(
                        agent, clarified_request, config, registry, audit_logger
                    )
                    output["clarification"] = {
                        "answered": True,
                        "status": "context_added",
                        "previous_incident_id": previous_incident_id,
                        "answer": answer,
                        "context_provided": True,
                    }

            print(json.dumps(output, ensure_ascii=False, indent=2))
            return _investigation_exit_code(
                output["status"], output["remediation"]["status"]
            )

        if args.restart_service:
            request = ActionRequest(
                action_name="restart_service",
                arguments={"service_name": args.restart_service},
                reason=args.reason,
                requested_by="local-cli-operator",
            )
            policy_engine = PolicyEngine(config, registry)
            decision = policy_engine.evaluate(request)
            approval = None
            if decision.outcome == "approval_required" and not config.agent.dry_run:
                approval = ApprovalManager().request_console_approval(request)

            result = ControlledExecutor(
                config=config,
                registry=registry,
                audit=audit_logger,
                policy_engine=policy_engine,
            ).execute(request, approval)
            output: dict[str, Any] = {"action": result.to_dict(), "verification": None}
            exit_code = 0 if result.ok else 1

            # A command may time out or fail after affecting the service. If the
            # adapter reports that execution occurred, verify before any retry.
            action_may_have_executed = (
                result.data.get("executed") is True
                or result.data.get("audit_failed_after_execution") is True
            )
            if action_may_have_executed:
                verifier = RecoveryManager(max_attempts=2, interval_seconds=1.0)
                verified = verifier.verify_until_healthy(
                    lambda: registry.invoke(
                        "verify_service_health",
                        {"service_name": args.restart_service},
                    )
                )
                output["verification"] = verified.to_dict()

                if audit_logger is not None:
                    try:
                        audit_logger.record_event(
                            event_type="action.verification_finished",
                            incident_id=f"action:{request.action_id}",
                            action_id=request.action_id,
                            details={
                                "verification_status": verified.status,
                                "healthy": verified.data.get("healthy") is True,
                                "attempts": verified.data.get(
                                    "verification_attempts", []
                                ),
                            },
                        )
                    except AuditError:
                        # Do not expose database paths or internal audit details.
                        output["verification_audit_error"] = True
                        exit_code = 1

                if not verified.ok or verified.data.get("healthy") is not True:
                    output["recovery_disposition"] = (
                        RecoveryManager.handle_recovery_failure(
                            incident_id=request.action_id,
                            action_name=request.action_name,
                            last_result=verified,
                        )
                    )
                    exit_code = 1

            print(json.dumps(output, ensure_ascii=False, indent=2))
            return exit_code

        return 0
    except (AuditError, OSError, ValueError) as exc:
        # Avoid dumping database paths or secret-bearing exception text to the CLI.
        print(f"Could not start operation ({type(exc).__name__}).", file=sys.stderr)
        return 2
    finally:
        if audit_logger is not None:
            audit_logger.close()



# DUAL_TERMINAL_REPORT_PATCH
# Keep the investigation workflow intact; only reorganize its terminal output.
_original_run_investigation_for_report = _run_investigation


def _run_investigation(*args, **kwargs):
    from linux_admin.terminal_report import run_with_dual_report

    return run_with_dual_report(
        _original_run_investigation_for_report, *args, **kwargs
    )

if __name__ == "__main__":
    raise SystemExit(main())
