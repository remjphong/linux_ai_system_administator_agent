"""Approval — quản lý phê duyệt gắn đúng action + target + tham số + TTL."""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_TTL_SECONDS = 300


def _fingerprint(action_type: str, target: str, parameters: dict[str, Any]) -> str:
    payload = json.dumps(
        {"action": action_type, "target": target, "params": parameters},
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class ApprovalRecord:
    fingerprint: str
    action_type: str
    target: str
    parameters: dict[str, Any]
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: datetime = field(
        default_factory=lambda: datetime.now() + timedelta(seconds=DEFAULT_TTL_SECONDS)
    )
    granted: bool = False

    def is_valid(self) -> bool:
        return self.granted and datetime.now() < self.expires_at


class ApprovalManager:
    def __init__(self, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        self.ttl_seconds = ttl_seconds
        self._store: dict[str, ApprovalRecord] = {}

    def request(
        self,
        action_type: str,
        target: str,
        parameters: dict[str, Any] | None = None,
    ) -> ApprovalRecord:
        parameters = parameters or {}
        fp = _fingerprint(action_type, target, parameters)
        record = ApprovalRecord(
            fingerprint=fp,
            action_type=action_type,
            target=target,
            parameters=parameters,
            expires_at=datetime.now() + timedelta(seconds=self.ttl_seconds),
        )
        self._store[fp] = record
        logger.info("Đã tạo approval request: %s", fp[:12])
        return record

    def grant(
        self,
        action_type: str,
        target: str,
        parameters: dict[str, Any] | None = None,
    ) -> bool:
        fp = _fingerprint(action_type, target, parameters or {})
        record = self._store.get(fp)
        if not record:
            return False
        record.granted = True
        return True

    def check(
        self,
        action_type: str,
        target: str,
        parameters: dict[str, Any] | None = None,
    ) -> bool:
        fp = _fingerprint(action_type, target, parameters or {})
        record = self._store.get(fp)
        return bool(record and record.is_valid())

