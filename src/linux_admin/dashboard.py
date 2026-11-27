"""Serve a read-only Linux dashboard on the SSH host's loopback interface."""

import argparse
import json
import sqlite3
import subprocess
from contextlib import closing
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Event, Lock, Thread

from linux_admin.audit import AuditError, AuditLogger
from linux_admin.config import ConfigurationError, load_config
from linux_admin.dashboard_demo import IncidentDemo
from linux_admin.monitor import DEFAULT_DB, Monitor, verify_ssh
from linux_admin.registry import ToolRegistry
from linux_admin.tools.logs import AuthLogTool, FailedServicesTool
from linux_admin.tools.network import NetworkStateTool
from linux_admin.tools.security_updates import (
    SecurityUpdatesTool,
    package_details,
    verify_security_update,
)
from linux_admin.tools.system import DiskUsageTool, SystemOverviewTool, TopProcessesTool
from linux_admin.web_chat import configure_chat, investigate

INTERVAL = 3
TOOLS = (
    ("system", SystemOverviewTool, {}),
    ("disk", DiskUsageTool, {"path": "/"}),
    ("processes", TopProcessesTool, {"limit": 10, "sort_by": "memory"}),
)


def sample(stop: Event, latest: dict, monitor=None, watch_interfaces=(), ssh=None) -> None:
    registry = ToolRegistry()
    tools = TOOLS
    if monitor is not None:
        tools += (("services", FailedServicesTool, {}), ("network", NetworkStateTool, {}))
    for _, tool, _ in tools:
        registry.register(tool())

    while not stop.is_set():
        snapshot = {"timestamp": datetime.now(timezone.utc).isoformat()}
        for key, tool, args in tools:
            snapshot[key] = registry.invoke(tool.spec.name, args).to_dict()
        if monitor is not None:
            snapshot["watch_interfaces"] = watch_interfaces
            try:
                monitor.observe(snapshot)
                snapshot["incidents"] = monitor.recent()
                snapshot["active_incidents"], snapshot["resolved_count"] = monitor.incident_status()
                snapshot["monitor_errors"] = [
                    key for key in ("system", "disk", "services", "network")
                    if snapshot[key]["status"] != "success"
                ]
            except sqlite3.Error:
                snapshot["monitor_errors"] = ["Không thể lưu hoặc đọc lịch sử."]
        if ssh is not None:
            snapshot["ssh_monitor"] = ssh.get("sample")
        latest["body"] = json.dumps(snapshot, ensure_ascii=False).encode("utf-8")
        stop.wait(INTERVAL)


def sample_ssh(stop, monitor, settings, latest) -> None:
    tool = AuthLogTool()
    while not stop.is_set():
        result = tool.execute(
            since_minutes=settings.window_minutes,
            brute_force_threshold=settings.failure_threshold,
        )
        now = datetime.now(timezone.utc).isoformat()
        try:
            monitor.observe_ssh(now, result, settings.interval_seconds)
        except sqlite3.Error:
            monitor.ssh_coverage_since = None
            latest["sample"] = {"timestamp": now, "status": "unavailable",
                                "detail": "Không lưu được cảnh báo SSH."}
        else:
            latest["sample"] = {
                "timestamp": now,
                "status": "ok" if result.ok and result.data["coverage_complete"] else "unavailable",
                "detail": ("Cửa sổ log vượt giới hạn đọc." if result.ok else result.error)
                if not result.data.get("coverage_complete") else None,
            }
        stop.wait(settings.interval_seconds)


def security_history(config) -> list[dict]:
    path = config.audit.database_path.resolve()
    if not config.audit.enabled or not path.is_file():
        return []
    with closing(sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True, timeout=2)) as db:
        rows = db.execute(
            "SELECT timestamp_utc, event_type, details_json FROM audit_events "
            "WHERE event_type IN (?, ?) ORDER BY event_id DESC LIMIT 20",
            ("security.patch_checked", "security.ssh_rechecked"),
        ).fetchall()
    events = []
    for timestamp, event_type, payload in rows:
        details = json.loads(payload)
        events.append({
            "timestamp": timestamp,
            "target": (details.get("package") if event_type == "security.patch_checked"
                       else details.get("subject")),
            "usn": details.get("usn"),
            "status": details.get("assessment") or details.get("status"),
        })
    return events


def security_action(path, payload, config, monitor):
    if path == "/api/security/package-details":
        return package_details(payload.get("package"), payload.get("architecture"))
    if path == "/api/security/scan":
        if payload:
            raise ValueError("Yêu cầu quét cần một đối tượng trống.")
        return SecurityUpdatesTool(config.project_root).execute(include_inventory=True).to_dict()
    if path == "/api/security/verify-patch":
        package, usn = payload.get("package"), payload.get("usn")
        if not all(isinstance(value, str) and 0 < len(value) <= 128
                   for value in (package, usn)):
            raise ValueError("Nhập tên gói và mã USN.")
        if not config.audit.enabled:
            raise ValueError("Cần bật audit để hậu kiểm bản vá.")
        with AuditLogger(config.audit.database_path) as audit:
            return verify_security_update(
                SecurityUpdatesTool(config.project_root), package, usn, audit
            ).to_dict()

    incident_id, reviewed = payload.get("incident_id"), payload.get("reviewed", False)
    if type(incident_id) is not int or not 0 < incident_id < 2**63 or type(reviewed) is not bool:
        raise ValueError("ID hoặc trạng thái rà soát SSH không hợp lệ.")
    if monitor is None or not config.audit.enabled:
        raise ValueError("Cần bật giám sát và audit để hậu kiểm SSH.")
    with closing(monitor.connect()) as db:
        incident = db.execute(
            "SELECT * FROM incidents WHERE id = ? AND cleared_at IS NULL "
            "AND subject LIKE 'security:ssh:%'", (incident_id,),
        ).fetchone()
    if incident is None:
        raise ValueError("Cảnh báo SSH đã đóng hoặc không tồn tại.")
    return verify_ssh(monitor, incident, config, reviewed)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--chat", action="store_true", help="Enable live web chat")
    parser.add_argument("--config-dir")
    parser.add_argument("--monitor", action="store_true", help="Enable incident monitoring")
    parser.add_argument("--monitor-db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--watch-interface", action="append", default=[])
    args = parser.parse_args()
    monitor = Monitor(args.monitor_db) if args.monitor else None
    try:
        chat_config = configure_chat(args.config_dir) if args.chat else None
        config = chat_config or load_config(config_dir=args.config_dir)
    except ConfigurationError as exc:
        parser.error(str(exc))
    ssh = {} if monitor and config.security.monitor_ssh else None
    security_lock = Lock()
    chat_lock = Lock()
    demo = IncidentDemo(monitor)
    page = Path(__file__).with_name("dashboard.html").read_bytes()
    latest = {"body": None}
    stop = Event()

    class Handler(BaseHTTPRequestHandler):
        def send_json(self, value, status=200):
            body = json.dumps(value, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def post_security(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 1024 or self.headers.get_content_type() != "application/json":
                    raise ValueError
                self.connection.settimeout(5)
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise TypeError
            except (OSError, TypeError, ValueError):
                self.send_json({"error": "Dữ liệu yêu cầu bảo mật không hợp lệ."}, 400)
                return
            if not security_lock.acquire(blocking=False):
                self.send_json({"error": "Đang có lượt kiểm tra bảo mật. Hãy đợi lượt đó kết thúc."}, 429)
                return
            try:
                result = security_action(self.path, payload, config, monitor)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400)
            except (AuditError, OSError, sqlite3.Error, subprocess.SubprocessError):
                self.send_json({"error": "Không hoàn tất kiểm tra hoặc không ghi được audit."}, 502)
            else:
                self.send_json(result)
            finally:
                security_lock.release()

        def do_POST(self):
            host = self.headers.get("Host")
            if host not in hosts or self.headers.get("Origin") != f"http://{host}":
                self.send_json({"error": "Origin không hợp lệ."}, 403)
                return
            if self.path in {"/api/security/scan", "/api/security/verify-patch",
                             "/api/security/verify-ssh", "/api/security/package-details"}:
                self.post_security()
                return
            if self.path in {"/api/demo/trigger", "/api/demo/recover"}:
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= 512 or self.headers.get_content_type() != "application/json":
                        raise ValueError("Yêu cầu demo không hợp lệ.")
                    self.connection.settimeout(5)
                    payload = json.loads(self.rfile.read(length))
                    if not isinstance(payload, dict):
                        raise TypeError("Yêu cầu demo không hợp lệ.")
                    result = (
                        demo.trigger(payload.get("scenario"))
                        if self.path.endswith("/trigger")
                        else demo.recover()
                    )
                except (TypeError, ValueError) as exc:
                    self.send_json({"error": str(exc)}, 400)
                except (OSError, sqlite3.Error, subprocess.TimeoutExpired):
                    self.send_json({"error": "Không chạy được phép kiểm tra demo."}, 502)
                else:
                    self.send_json(result)
                return
            if self.path != "/api/chat" or chat_config is None:
                self.send_json({"error": "Chat chưa được bật."}, 404)
                return
            if self.headers.get_content_type() != "application/json":
                self.send_json({"error": "Yêu cầu phải là JSON."}, 415)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 8192:
                    raise ValueError
                self.connection.settimeout(5)
                payload = json.loads(self.rfile.read(length))
                message = payload["message"]
                if not isinstance(message, str) or not 0 < len(message.strip()) <= 1500:
                    raise ValueError
            except (ValueError, KeyError, TypeError, OSError):
                self.send_json({"error": "Nhập câu hỏi từ 1 đến 1500 ký tự."}, 400)
                return
            if not chat_lock.acquire(blocking=False):
                self.send_json({"error": "Agent đang xử lý một yêu cầu khác."}, 429)
                return
            try:
                result = investigate(chat_config, message.strip())
            except Exception:  # noqa: BLE001
                self.log_error("Web investigation failed")
                self.send_json({"error": "Điều tra thất bại. Kiểm tra terminal."}, 502)
            else:
                self.send_json(result)
            finally:
                chat_lock.release()

        def do_GET(self):
            if self.headers.get("Host") not in hosts:
                self.send_error(400, "Invalid Host")
                return
            if self.path == "/api/incidents/resolved":
                try:
                    if monitor is None:
                        self.send_json({"error": "Giám sát sự cố chưa bật."}, 404)
                    else:
                        self.send_json({"incidents": monitor.resolved()})
                except sqlite3.Error:
                    self.send_json({"error": "Không đọc được lịch sử sự cố."}, 502)
                return
            if self.path == "/api/security/history":
                try:
                    history = security_history(config)
                except (ValueError, sqlite3.Error):
                    self.send_json({"error": "Không đọc được lịch sử audit bảo mật."}, 502)
                else:
                    self.send_json({"events": history, "audit_enabled": config.audit.enabled})
                return
            if self.path == "/api/demo":
                self.send_json({"incident": demo.snapshot()})
                return
            if self.path == "/api/chat-status":
                self.send_json({"enabled": chat_config is not None})
                return
            if self.path == "/":
                body, content_type = page, "text/html; charset=utf-8"
            elif self.path == "/api/snapshot":
                body, content_type = latest["body"], "application/json"
                if body is None:
                    self.send_error(503, "Initial sample pending")
                    return
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    with ThreadingHTTPServer(("127.0.0.1", args.port), Handler) as server:
        port = server.server_port
        hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        worker = Thread(
            target=sample, args=(stop, latest, monitor, args.watch_interface, ssh), daemon=True
        )
        worker.start()
        ssh_worker = None
        if ssh is not None:
            ssh_worker = Thread(
                target=sample_ssh, args=(stop, monitor, config.security, ssh), daemon=True
            )
            ssh_worker.start()
        print(f"Dashboard: http://127.0.0.1:{port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            stop.set()
            worker.join()
            if ssh_worker is not None:
                ssh_worker.join()
            demo.close()


if __name__ == "__main__":
    main()
