"""Output-mode contract tests for the terminal reporting wrapper."""

from __future__ import annotations

import io
import json
from dataclasses import replace
from types import SimpleNamespace

from linux_admin import main as cli
from linux_admin import terminal_report
from linux_admin.config import load_config
from linux_admin.main import build_parser
from linux_admin.registry import ToolRegistry

PAYLOAD = {
    "incident_id": "incident-output-test",
    "request": "Check CPU and RAM",
    "status": "completed",
    "findings": ["Diagnosis: resource snapshot"],
    "evidence": [],
    "remediation": {"status": "not_proposed"},
}


class _TTY(io.StringIO):
    def isatty(self):
        return True


class _Pipe(io.StringIO):
    def isatty(self):
        return False


def _run_mode(monkeypatch, mode):
    stream = _TTY()
    monkeypatch.setattr(terminal_report.sys, "stdout", stream)

    def operation():
        print(json.dumps(PAYLOAD, ensure_ascii=False))
        return PAYLOAD

    terminal_report.run_with_dual_report(operation, output_mode=mode)
    return stream.getvalue()


def test_default_tty_shows_concise_report_without_debug_or_raw_json(monkeypatch):
    output = _run_mode(monkeypatch, "human")
    assert "incident-output-test" in output
    assert "[2] DEVELOPER DETAILS" not in output
    assert '"incident_id"' not in output
    assert '"evidence"' not in output


def test_json_mode_suppresses_human_report(monkeypatch):
    output = _run_mode(monkeypatch, "json")
    assert output == ""


def test_non_tty_default_keeps_wrapper_silent_for_single_json_document(monkeypatch):
    stream = _Pipe()
    monkeypatch.setattr(terminal_report.sys, "stdout", stream)

    def operation():
        print(json.dumps(PAYLOAD, ensure_ascii=False))
        return PAYLOAD

    result = terminal_report.run_with_dual_report(operation, output_mode="default")
    assert result == PAYLOAD
    assert stream.getvalue() == ""


def test_legacy_text_environment_keeps_two_section_report(monkeypatch):
    monkeypatch.setenv("LINUX_ADMIN_REPORT", "text")
    output = _run_mode(monkeypatch, "legacy")
    assert "[1] USER REPORT" in output
    assert "[2] DEVELOPER DETAILS" in output
    assert '"incident_id"' not in output


def test_debug_mode_includes_technical_section_but_no_implicit_second_json(monkeypatch):
    output = _run_mode(monkeypatch, "debug")
    assert "DEVELOPER DETAILS" in output
    assert "JSON chi tiet se duoc CLI in mot lan ben duoi." in output
    assert '"incident_id"' not in output


def test_cli_exposes_mutually_exclusive_json_and_debug_modes():
    assert build_parser().parse_args(["--json", "--investigate", "status"]).json
    assert build_parser().parse_args(["--debug", "--investigate", "status"]).debug


def test_restart_action_default_tty_does_not_dump_json(monkeypatch):
    stream = _TTY()
    monkeypatch.setattr(cli.sys, "stdout", stream)
    monkeypatch.setattr(cli.sys, "argv", ["linux-admin", "--restart-service", "demo.service"])
    config = load_config()
    config = replace(config, audit=replace(config.audit, enabled=False))
    monkeypatch.setattr(cli, "load_config", lambda: config)
    monkeypatch.setattr(cli, "register_builtin_tools", lambda *_: ToolRegistry())

    class Policy:
        def __init__(self, *_):
            pass

        def evaluate(self, _request):
            return SimpleNamespace(outcome="deny")

    class Executor:
        def __init__(self, **_):
            pass

        def execute(self, _request, _approval):
            return SimpleNamespace(
                ok=False,
                status="denied",
                data={"executed": False},
                to_dict=lambda: {"status": "denied", "data": {"executed": False}},
            )

    monkeypatch.setattr(cli, "PolicyEngine", Policy)
    monkeypatch.setattr(cli, "ControlledExecutor", Executor)
    assert cli.main() == 1
    output = stream.getvalue()
    assert "Action: restart_service demo.service" in output
    assert "System change executed: no" in output
    assert '{"action"' not in output


def test_investigation_tty_default_and_json_route_to_distinct_output(monkeypatch):
    config = load_config()
    config = replace(config, audit=replace(config.audit, enabled=False))
    monkeypatch.setattr(cli, "load_config", lambda: config)
    monkeypatch.setattr(cli, "register_builtin_tools", lambda *_: ToolRegistry())
    observed_modes = []

    def fake_investigation(*_args, output_mode):
        observed_modes.append(output_mode)
        if output_mode == "human":
            print("Concise incident report")
        return {
            **PAYLOAD,
            "status": "completed",
            "remediation": {"status": "not_proposed"},
        }

    monkeypatch.setattr(cli, "_run_investigation", fake_investigation)
    outputs = []
    for argv in (
        ["linux-admin", "--investigate", "status"],
        ["linux-admin", "--json", "--investigate", "status"],
    ):
        stream = _TTY()
        monkeypatch.setattr(cli.sys, "stdout", stream)
        monkeypatch.setattr(cli.sys, "argv", argv)
        assert cli.main() == 0
        outputs.append(stream.getvalue())

    assert observed_modes == ["human", "json"]
    assert "Concise incident report" in outputs[0]
    assert '"incident_id"' not in outputs[0]
    assert json.loads(outputs[1])["incident_id"] == "incident-output-test"
