"""Stateful, bounded conversational shell for the existing investigation CLI."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import deque
from dataclasses import dataclass
from typing import Any

from linux_admin.terminal_report import _render_user_report

_GREETING = re.compile(
    r"^(?:hi|hello|hey|xin chào|chào(?: bạn)?|chào buổi sáng|"
    r"chao(?: ban)?|chao buoi sang|good morning|good evening)[!. ]*$",
    re.IGNORECASE,
)
_FOLLOW_UP = re.compile(
    r"\b(?:it|that|this|those|they|its|their|them|ở đó|cái đó|đó|nó|chúng|vậy còn)\b",
    re.IGNORECASE,
)
_PORT = re.compile(r"\b(?:port|cổng)\s*[:#-]?\s*(\d{1,5})\b", re.IGNORECASE)
_SERVICE = re.compile(r"\b[a-zA-Z0-9_.@-]+\.service\b")
_URL = re.compile(r"https?://[^\s,;]+", re.IGNORECASE)
_CACHED_EXPLANATION = re.compile(
    r"(?:giải thích|giai thich).*(?:kết quả|ket qua)|"
    r"(?:explain|clarify).*(?:result|that|it)",
    re.IGNORECASE,
)
_HISTORY_LIMIT = 8
_CONTEXT_LIMIT = 3


@dataclass
class Turn:
    request: str
    incident_id: str | None
    findings: list[str]
    evidence: list[str]
    details: str
    targets: list[str]


def _targets(request: str) -> list[str]:
    found: list[str] = []
    for matches, prefix in ((_PORT.finditer(request), "port "),
                            (_SERVICE.finditer(request), "service "),
                            (_URL.finditer(request), "URL ")):
        for match in matches:
            value = match.group(1) if prefix == "port " else match.group(0)
            target = prefix + value.rstrip(".,!?)]")
            if target not in found:
                found.append(target)
    return found


def _result_context(payload: dict[str, Any]) -> tuple[list[str], list[str]]:
    raw_findings = payload.get("findings", [])
    findings = [item[:240] for item in raw_findings if isinstance(item, str)][:5] \
        if isinstance(raw_findings, list) else []
    evidence = []
    raw_evidence = payload.get("evidence", [])
    if isinstance(raw_evidence, list):
        for item in raw_evidence[:8]:
            if not isinstance(item, dict):
                continue
            name = item.get("tool_name", "unknown tool")
            status = item.get("status", "unknown")
            notes = item.get("evidence", [])
            note = next((text for text in notes if isinstance(text, str)), "") \
                if isinstance(notes, list) else ""
            evidence.append(f"{name}: {status}" + (f" — {note[:160]}" if note else ""))
    return findings, evidence


class ChatSession:
    """Run CLI investigations while retaining a bounded context window."""

    def __init__(self, cli: str, config_dir: str, *, runner=subprocess.run) -> None:
        self.cli = cli
        self.config_dir = config_dir
        self.runner = runner
        self.turns: deque[Turn] = deque(maxlen=_HISTORY_LIMIT)

    def handle(self, request: str) -> str:
        """Handle a user line and return a response without doing I/O itself."""
        value = request.strip()
        command = value.casefold()
        if command in {"exit", "quit", "thoát", "thoat"}:
            return "__EXIT__"
        if command == "help":
            return (
                "Gửi yêu cầu kiểm tra hệ thống. Lệnh: help, history, details, "
                "clear, exit."
            )
        if command == "history":
            if not self.turns:
                return "Chưa có lượt điều tra nào trong phiên này."
            return "\n".join(
                f"{i}. {turn.request} [{turn.incident_id or 'không có incident ID'}]"
                for i, turn in enumerate(self.turns, 1)
            )
        if command == "details":
            return self.turns[-1].details if self.turns else "Chưa có kết quả để xem."
        if command == "clear":
            self.turns.clear()
            return "Đã xóa lịch sử và ngữ cảnh của phiên chat."
        if not value:
            return ""
        if _GREETING.fullmatch(value):
            return "Xin chào. Tôi có thể giúp kiểm tra CPU, RAM, dịch vụ, cổng hoặc URL."

        if _CACHED_EXPLANATION.search(value):
            if not self.turns:
                return "Chưa có kết quả điều tra trong phiên để giải thích."
            return self._explain_cached(self.turns[-1])

        targets = _targets(value)
        if _FOLLOW_UP.search(value) and not targets:
            if not self.turns:
                return (
                    "Chưa có mục tiêu trước đó. Vui lòng nêu cổng, dịch vụ "
                    "hoặc URL bạn muốn hỏi."
                )
            prior_targets = self.turns[-1].targets
            if not prior_targets:
                return (
                    "Không tìm thấy mục tiêu cụ thể trong kết quả trước. "
                    "Vui lòng nêu cổng, dịch vụ hoặc URL."
                )
            if len(prior_targets) > 1:
                choices = ", ".join(prior_targets)
                return (
                    f"Có nhiều mục tiêu trong ngữ cảnh trước ({choices}). "
                    "Bạn muốn nói đến mục tiêu nào?"
                )
            targets = prior_targets.copy()
            value = (
                f"{value}\n\nNgữ cảnh phiên: mục tiêu được nêu rõ trước đó là "
                f"{targets[0]}. Không suy diễn dịch vụ từ cổng."
            )

        context = list(self.turns)[-_CONTEXT_LIMIT:]
        if context and _FOLLOW_UP.search(value):
            parts = []
            for turn in context:
                if turn.incident_id:
                    parts.append(f"Incident {turn.incident_id}; yêu cầu: {turn.request[:200]}")
                parts.extend(f"Finding: {item}" for item in turn.findings[:3])
                parts.extend(f"Evidence: {item}" for item in turn.evidence[:4])
            value += "\n\nBằng chứng sự cố trước trong phiên:\n" + "\n".join(parts)

        try:
            result = self.runner(
                [
                    self.cli,
                    "--config-dir",
                    self.config_dir,
                    "--json",
                    "--investigate",
                    value,
                ],
                text=True,
                capture_output=True,
                check=False,
            )
        except OSError as exc:
            return f"Không thể chạy linux-admin ({type(exc).__name__})."
        output = result.stdout.strip()
        try:
            payload = json.loads(output)
        except (json.JSONDecodeError, TypeError):
            error = result.stderr.strip() or output or "CLI không trả về kết quả."
            return error

        findings, evidence = _result_context(payload)
        self.turns.append(
            Turn(
                request=request.strip(),
                incident_id=payload.get("incident_id"),
                findings=findings,
                evidence=evidence,
                details=json.dumps(payload, ensure_ascii=False, indent=2),
                targets=targets,
            )
        )
        return _render_user_report(payload, result.returncode)

    @staticmethod
    def _explain_cached(turn: Turn) -> str:
        """Explain the most recent cached result without launching the CLI."""
        lines = [f"Kết quả điều tra {turn.incident_id or 'không có incident ID'}:"]
        lines.extend(f"- {finding}" for finding in turn.findings)
        lines.extend(f"- Bằng chứng: {item}" for item in turn.evidence)
        if not turn.findings and not turn.evidence:
            lines.append("Kết quả chưa có finding hoặc evidence tóm tắt.")
        lines.append("Đây là dữ liệu đã lưu từ lượt trước; không chạy kiểm tra mới.")
        return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(prog="linux-admin-chat")
    parser.add_argument("--cli", required=True)
    parser.add_argument("--config-dir", required=True)
    args = parser.parse_args()
    session = ChatSession(args.cli, args.config_dir)
    print("Linux AI Administrator — nhập help để xem lệnh.")
    while True:
        try:
            line = input("Bạn > ")
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        response = session.handle(line)
        if response == "__EXIT__":
            print("Đã thoát Linux AI Administrator.")
            return 0
        if response:
            print(f"\nAgent > {response}\n")


if __name__ == "__main__":
    raise SystemExit(main())
