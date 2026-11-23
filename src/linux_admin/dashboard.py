"""Serve a read-only Linux dashboard on the SSH host's loopback interface."""

import argparse
import json
import sqlite3
import subprocess
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Event, Lock, Thread

from linux_admin.config import ConfigurationError
from linux_admin.dashboard_demo import IncidentDemo
from linux_admin.monitor import DEFAULT_DB, Monitor
from linux_admin.registry import ToolRegistry
from linux_admin.tools.logs import FailedServicesTool
from linux_admin.tools.network import NetworkStateTool
from linux_admin.tools.system import DiskUsageTool, SystemOverviewTool, TopProcessesTool
from linux_admin.web_chat import configure_chat, investigate

INTERVAL = 3
TOOLS = (
    ("system", SystemOverviewTool, {}),
    ("disk", DiskUsageTool, {"path": "/"}),
    ("processes", TopProcessesTool, {"limit": 10, "sort_by": "memory"}),
)


def sample(stop: Event, latest: dict, monitor=None, watch_interfaces=()) -> None:
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
                snapshot["monitor_errors"] = [
                    key for key in ("system", "disk", "services", "network")
                    if snapshot[key]["status"] != "success"
                ]
            except sqlite3.Error:
                snapshot["monitor_errors"] = ["Không thể lưu hoặc đọc lịch sử."]
        latest["body"] = json.dumps(snapshot, ensure_ascii=False).encode("utf-8")
        stop.wait(INTERVAL)


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
    chat_config = None
    if args.chat:
        try:
            chat_config = configure_chat(args.config_dir)
        except ConfigurationError as exc:
            parser.error(str(exc))
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

        def do_POST(self):
            host = self.headers.get("Host")
            if host not in hosts or self.headers.get("Origin") != f"http://{host}":
                self.send_json({"error": "Origin không hợp lệ."}, 403)
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
            target=sample, args=(stop, latest, monitor, args.watch_interface), daemon=True
        )
        worker.start()
        print(f"Dashboard: http://127.0.0.1:{port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            stop.set()
            worker.join()
            demo.close()


if __name__ == "__main__":
    main()
