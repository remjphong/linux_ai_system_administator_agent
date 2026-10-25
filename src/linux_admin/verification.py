"""Xác minh hậu điều kiện sau action (Health checks và Recovery)."""
from __future__ import annotations

import logging
import socket
import subprocess

logger = logging.getLogger(__name__)

def verify_service_active(service_name: str) -> bool:
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", service_name],
            capture_output=True, text=True, timeout=10, check=False
        )
        return proc.stdout.strip() == "active"
    except (OSError, subprocess.SubprocessError):
        return False

def verify_tcp_endpoint(host: str, port: int, timeout: int = 5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False

def handle_recovery_retry(action_fn, verify_fn, max_retries: int = 2) -> dict:
    for attempt in range(1, max_retries + 1):
        action_ok = action_fn()
        if action_ok and verify_fn():
            return {"status": "success", "attempts": attempt}
    return {"status": "failed", "message": "Đã hết retry, cần can thiệp thủ công"}
