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
        "--reason",
        default="Operator-requested service restart",
        help="Reason recorded for --restart-service",
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


def _incident_to_dict(incident: IncidentContext) -> dict[str, Any]:
    """Convert an incident result into JSON-compatible data for the CLI."""
    return {
        "incident_id": incident.incident_id,
        "request": incident.user_request,
        "status": incident.status,
        "steps": incident.steps,
        "findings": incident.findings,
        "evidence": [result.to_dict() for result in incident.evidence],
        "started_at": incident.started_at.isoformat(),
    }


def main() -> int:
    """Run the selected CLI operation and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args()

    if not (
        args.check_config
        or args.list_tools
        or args.investigate
        or args.restart_service
    ):
        parser.print_help()
        return 0

    try:
        config = load_config()
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
            incident = agent.run(args.investigate)
            output = _incident_to_dict(incident)
            proposal = build_remediation_proposal(incident, config, registry)

            (
                verification_url,
                endpoint_verification_required,
            ) = _select_verification_target(args.investigate)

            if proposal is None:
                output["remediation"] = no_proposal_result(
                    args.investigate,
                    incident.findings,
                    investigation_status=incident.status,
                )
            else:
                output["remediation"] = run_remediation_workflow(
                    proposal,
                    incident_id=incident.incident_id,
                    config=config,
                    registry=registry,
                    audit=audit_logger,
                    diagnosis_findings=incident.findings,
                    verification_url=verification_url,
                    endpoint_verification_required=endpoint_verification_required,
                    output_fn=lambda message: print(message, file=sys.stderr),
                )

            print(json.dumps(output, ensure_ascii=False, indent=2))
            remediation_status = output["remediation"]["status"]
            return _investigation_exit_code(
                incident.status,
                remediation_status,
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


if __name__ == "__main__":
    raise SystemExit(main())
