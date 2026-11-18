"""Focused tests for bounded conversational session state."""

from __future__ import annotations

import json
from types import SimpleNamespace

from linux_admin.chat import ChatSession


def _payload(incident_id: str) -> dict:
    return {
        "incident_id": incident_id,
        "request": "sample",
        "status": "completed",
        "findings": ["Diagnosis: sample"],
        "evidence": [
            {
                "tool_name": "inspect_listening_port",
                "status": "success",
                "evidence": ["Observed local port evidence"],
            }
        ],
        "remediation": {"status": "not_proposed"},
    }


def test_greeting_and_commands_do_not_run_diagnostics():
    calls = []

    def runner(*args, **kwargs):
        calls.append(args)

    session = ChatSession("linux-admin", "/config", runner=runner)
    assert "Xin chào" in session.handle("hello")
    assert "help" in session.handle("help")
    assert "chưa có" in session.handle("history").casefold()
    assert "Chưa có" in session.handle("details")
    assert "Đã xóa" in session.handle("clear")
    assert session.handle("exit") == "__EXIT__"
    assert calls == []


def test_follow_up_preserves_incident_context_and_details_are_cached():
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        incident_id = f"incident-{len(calls)}"
        return SimpleNamespace(
            stdout=json.dumps(_payload(incident_id), ensure_ascii=False),
            stderr="",
            returncode=0,
        )

    session = ChatSession("linux-admin", "/config", runner=runner)
    session.handle("check port 5432")
    details = session.handle("details")
    assert json.loads(details)["incident_id"] == "incident-1"

    session.handle("what about it")
    assert len(calls) == 2
    follow_up = calls[1][-1]
    assert "port 5432" in follow_up
    assert "incident-1" in follow_up
    assert "Observed local port evidence" in follow_up

    history = session.handle("history")
    assert "check port 5432" in history
    assert "incident-1" in history


def test_ambiguous_follow_up_asks_without_running_another_probe():
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(stdout=json.dumps(_payload("i-1")), stderr="", returncode=0)

    session = ChatSession("linux-admin", "/config", runner=runner)
    session.handle("Check port 5432 and port 8080")
    before = len(calls)
    response = session.handle("what about it")
    assert "mục tiêu nào" in response
    assert len(calls) == before


def test_session_history_is_bounded_to_eight_results():
    counter = 0

    def runner(command, **kwargs):
        nonlocal counter
        counter += 1
        return SimpleNamespace(stdout=json.dumps(_payload(f"i-{counter}")), stderr="", returncode=0)

    session = ChatSession("linux-admin", "/config", runner=runner)
    for number in range(10):
        session.handle(f"request {number}")
    history = session.handle("history")
    assert "request 0" not in history
    assert "request 1" not in history
    assert "request 2" in history
