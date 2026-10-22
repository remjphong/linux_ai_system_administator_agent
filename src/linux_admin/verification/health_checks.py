"""Health checks — xác minh hậu điều kiện sau action.

Nguyên tắc:
- KHÔNG tin exit code của restart.
- Phải kiểm tra trạng thái thật sau thực thi.
- Mọi lỗi môi trường đều trả False (fail-closed) và ghi log.
"""
from __future__ import annotations

import http.client
import logging
import socket
import subprocess
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 10


def check_service_health(service_name: str, timeout: int = DEFAULT_TIMEOUT) -> bool:
    """True nếu systemctl is-active trả 'active'."""
    if not service_name:
        return False

    try:
        proc = subprocess.run(
            ["systemctl", "is-active", service_name],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.stdout.strip() == "active"
    except subprocess.TimeoutExpired:
        logger.error("check_service_health timeout cho %s", service_name)
        return False
    except (OSError, subprocess.SubprocessError) as exc:
        logger.error("check_service_health lỗi: %s", exc)
        return False


def check_tcp_endpoint(host: str, port: int, timeout: int = DEFAULT_TIMEOUT) -> bool:
    """True nếu mở được TCP tới host:port trong timeout."""
    if not host or not isinstance(port, int) or not (1 <= port <= 65535):
        return False

    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError as exc:
        logger.error("check_tcp_endpoint lỗi %s:%s — %s", host, port, exc)
        return False


def check_http_endpoint(url: str, timeout: int = DEFAULT_TIMEOUT) -> bool:
    """True nếu HTTP/HTTPS trả status 2xx/3xx."""
    if not url:
        return False

    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        if not parsed.netloc:
            return False

        if parsed.scheme == "https":
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                parsed.netloc, timeout=timeout
            )
        else:
            conn = http.client.HTTPConnection(parsed.netloc, timeout=timeout)

        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            return 200 <= resp.status < 400
        finally:
            conn.close()

    except (OSError, http.client.HTTPException) as exc:
        logger.error("check_http_endpoint lỗi: %s", exc)
        return False
    except ValueError as exc:
        logger.error("check_http_endpoint URL không hợp lệ: %s", exc)
        return False
