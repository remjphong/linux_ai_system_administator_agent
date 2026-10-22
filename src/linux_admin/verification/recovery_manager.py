"""Recovery manager — retry có giới hạn, dừng an toàn khi thất bại.

Nguyên tắc:
- Retry tối đa max_retries lần.
- Không tự chuyển sang action nguy hiểm khác.
- Mọi bước ghi audit.
- Nếu hết retry → trả final_status="failed" và đề xuất can thiệp thủ công.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass

from linux_admin.control.audit import AuditLogger

logger = logging.getLogger(__name__)

MAX_RETRIES = 2


@dataclass
class RecoveryOutcome:
    recovered: bool
    attempts: int
    final_status: str  # success | failed
    message: str


def handle_recovery(
    action_type: str,
    target: str,
    attempt_action: Callable[[], bool],
    verify: Callable[[], bool],
    audit: AuditLogger | None = None,
    max_retries: int = MAX_RETRIES,
) -> RecoveryOutcome:
    """Thử action + verify tối đa max_retries lần.

    Tham số:
        attempt_action: gọi action, trả True nếu action không raise/lỗi.
        verify:         kiểm tra hậu điều kiện, trả True nếu đạt.
        audit:          AuditLogger; mặc định tạo mới (audit.db).
        max_retries:    số lần thử tối đa, mặc định 2.

    Trả về RecoveryOutcome với:
        recovered=True   nếu verify đạt trong vòng max_retries.
        recovered=False  nếu hết retry → cần can thiệp thủ công.
    """
    audit = audit or AuditLogger()

    max_retries = max(max_retries, 1)

    attempts = 0

    for _ in range(max_retries):
        attempts += 1

        # 1. Gọi action — nếu False, thử lại
        ok_action = attempt_action()
        if not ok_action:
            audit.log_event(
                event_type="recovery_attempt",
                action_type=action_type,
                target=target,
                decision="action_failed",
                details=f"attempt={attempts}",
            )
            continue

        # 2. Verify sau action
        if verify():
            audit.log_event(
                event_type="recovery_success",
                action_type=action_type,
                target=target,
                decision="success",
                details=f"attempt={attempts}",
            )
            return RecoveryOutcome(
                recovered=True,
                attempts=attempts,
                final_status="success",
                message="Đã phục hồi và xác minh thành công",
            )

        audit.log_event(
            event_type="recovery_attempt",
            action_type=action_type,
            target=target,
            decision="verify_failed",
            details=f"attempt={attempts}",
        )

    # Hết retry
    audit.log_event(
        event_type="recovery_exhausted",
        action_type=action_type,
        target=target,
        decision="failed",
        details=f"attempts={attempts}",
    )
    return RecoveryOutcome(
        recovered=False,
        attempts=attempts,
        final_status="failed",
        message="Đã hết retry, cần can thiệp thủ công",
    )
