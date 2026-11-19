"""Focused tests for bounded conversational session state."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

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


def test_greetings_and_commands_do_not_run_diagnostics():
    calls = []

    def runner(*args, **kwargs):
        calls.append(args)

    session = ChatSession("linux-admin", "/config", runner=runner)
    assert "Xin chào" in session.handle("hello")
    assert "Xin chào" in session.handle("Chào buổi sáng")
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
    assert len(calls) == 1

    session.handle("what about it")
    assert len(calls) == 2
    follow_up = calls[1][-1]
    assert "port 5432" in follow_up
    assert "incident-1" in follow_up
    assert "Observed local port evidence" in follow_up

    history = session.handle("history")
    assert "check port 5432" in history
    assert "incident-1" in history


def test_vietnamese_port_follow_up_and_cached_explanation_use_four_turn_contract():
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
    session.handle("Kiểm tra CPU và RAM")
    session.handle("Kiểm tra port 5432")
    before_follow_up = len(calls)
    session.handle("Cổng đó có đang được mở không?")

    assert len(calls) == before_follow_up + 1
    assert "port 5432" in calls[-1][-1]
    assert "incident-2" in calls[-1][-1]
    assert "Observed local port evidence" in calls[-1][-1]
    assert "--json" in calls[-1]

    before_explanation = len(calls)
    explanation = session.handle("Giải thích rõ hơn kết quả vừa rồi.")
    assert len(calls) == before_explanation
    assert "incident-3" in explanation
    assert "Diagnosis: sample" in explanation
    assert "Observed local port evidence" in explanation


def test_explicit_matching_cached_target_is_explained_without_new_child():
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(
            stdout=json.dumps(_payload("incident-5432")),
            stderr="",
            returncode=0,
        )

    session = ChatSession("linux-admin", "/config", runner=runner)
    session.handle("Kiểm tra cổng 5432")
    count = len(calls)
    explanation = session.handle("Giải thích kết quả của cổng 5432")

    assert len(calls) == count
    assert "incident-5432" in explanation
    assert "Observed local port evidence" in explanation


def test_explicit_mismatched_cached_target_is_clarified_without_reusing_evidence():
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(
            stdout=json.dumps(_payload("incident-5432")),
            stderr="",
            returncode=0,
        )

    session = ChatSession("linux-admin", "/config", runner=runner)
    session.handle("Kiểm tra cổng 5432")
    count = len(calls)
    response = session.handle("Giải thích kết quả của cổng 8080")

    assert len(calls) == count
    assert "port 5432" in response
    assert "port 8080" in response
    assert "Observed local port evidence" not in response


@pytest.mark.parametrize("target", ["port 5432", "port 8080"])
def test_explicit_subset_of_multi_target_incident_is_clarified(target):
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(
            stdout=json.dumps(_payload("incident-multi")),
            stderr="",
            returncode=0,
        )

    session = ChatSession("linux-admin", "/config", runner=runner)
    session.handle("Check port 5432 and port 8080")
    count = len(calls)
    response = session.handle(f"Giải thích kết quả của {target}")

    assert len(calls) == count
    assert "port 5432" in response and "port 8080" in response
    assert "không gắn riêng từng mục tiêu" in response
    assert "Observed local port evidence" not in response


def test_explicit_complete_multi_target_explanation_discloses_incident_scope():
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(
            stdout=json.dumps(_payload("incident-multi")),
            stderr="",
            returncode=0,
        )

    session = ChatSession("linux-admin", "/config", runner=runner)
    session.handle("Check port 5432 and port 8080")
    count = len(calls)
    response = session.handle(
        "Giải thích kết quả của port 8080 và port 5432"
    )

    assert len(calls) == count
    assert "Phạm vi toàn sự cố: port 5432, port 8080." in response
    assert "không được gắn riêng cho từng mục tiêu" in response
    assert "Observed local port evidence" in response


def test_unqualified_multi_target_explanation_discloses_whole_incident_scope():
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(
            stdout=json.dumps(_payload("incident-multi")),
            stderr="",
            returncode=0,
        )

    session = ChatSession("linux-admin", "/config", runner=runner)
    session.handle("Check port 5432 and port 8080")
    count = len(calls)
    response = session.handle("Giải thích rõ hơn kết quả vừa rồi")

    assert len(calls) == count
    assert "Phạm vi toàn sự cố: port 5432, port 8080." in response
    assert "không được gắn riêng cho từng mục tiêu" in response


def test_cached_explanation_without_prior_result_clarifies_without_child():
    calls = []
    session = ChatSession("linux-admin", "/config", runner=lambda *a, **k: calls.append(a))

    response = session.handle("Giải thích kết quả của port 5432")

    assert "Chưa có kết quả" in response
    assert calls == []


@pytest.mark.parametrize("non_object_json", ["[]", "null", '"not a result"'])
def test_non_object_json_does_not_create_turn_or_break_later_commands(non_object_json):
    calls = []
    outputs = iter(
        [
            json.dumps(_payload("incident-before")),
            non_object_json,
            json.dumps(_payload("incident-after")),
        ]
    )

    def runner(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(stdout=next(outputs), stderr="", returncode=0)

    session = ChatSession("linux-admin", "/config", runner=runner)
    session.handle("check port 5432")
    response = session.handle("check port 8080")

    assert "không phải đối tượng JSON" in response
    assert len(calls) == 2
    assert len(session.turns) == 1
    assert session.turns[-1].incident_id == "incident-before"
    assert "incident-before" in session.handle("details")
    assert "incident-after" in session.handle("check port 443")
    assert len(calls) == 3
    history = session.handle("history")
    assert "incident-before" in history
    assert "incident-after" in history
    assert "incident-8080" not in history


def test_repeated_follow_ups_keep_the_resolved_target_and_provenance():
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(
            stdout=json.dumps(_payload(f"incident-{len(calls)}")),
            stderr="",
            returncode=0,
        )

    session = ChatSession("linux-admin", "/config", runner=runner)
    session.handle("Kiểm tra port 5432")
    session.handle("Cổng đó đang mở không?")
    before_repeat = len(calls)
    session.handle("Nó có dịch vụ nào dùng không?")

    assert len(calls) == before_repeat + 1
    assert "port 5432" in calls[-1][-1]
    assert "incident-2" in calls[-1][-1]


def test_zero_and_multiple_referents_are_clarified_without_subprocess():
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(
            stdout=json.dumps(_payload(f"incident-{len(calls)}")),
            stderr="",
            returncode=0,
        )

    session = ChatSession("linux-admin", "/config", runner=runner)
    session.handle("Kiểm tra CPU và RAM")
    count = len(calls)
    zero = session.handle("Cổng đó có đang mở không?")
    assert "Không tìm thấy mục tiêu cụ thể" in zero
    assert len(calls) == count

    session.handle("Kiểm tra port 5432 và port 8080")
    count = len(calls)
    multiple = session.handle("Cổng đó có đang mở không?")
    assert "port 5432" in multiple and "port 8080" in multiple
    assert len(calls) == count


def test_chat_always_requests_json_even_with_inherited_legacy_environment(monkeypatch):
    monkeypatch.setenv("LINUX_ADMIN_REPORT", "text")
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(
            stdout=json.dumps(_payload("incident-chat-json")),
            stderr="",
            returncode=0,
        )

    session = ChatSession(
        "/path with spaces/linux-admin", "/config with spaces", runner=runner
    )
    request = "check port 5432; $(touch /tmp/not-run)"
    session.handle(request)

    command, kwargs = calls[0]
    assert command == [
        "/path with spaces/linux-admin",
        "--config-dir",
        "/config with spaces",
        "--json",
        "--investigate",
        request,
    ]
    assert kwargs == {"text": True, "capture_output": True, "check": False}


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
