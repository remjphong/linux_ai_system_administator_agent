"""Serve a read-only Linux dashboard on the SSH host's loopback interface."""

import argparse
import json
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Event, Thread

from linux_admin.registry import ToolRegistry
from linux_admin.tools.system import DiskUsageTool, SystemOverviewTool, TopProcessesTool

INTERVAL = 3
TOOLS = (
    ("system", SystemOverviewTool, {}),
    ("disk", DiskUsageTool, {"path": "/"}),
    ("processes", TopProcessesTool, {"limit": 10, "sort_by": "memory"}),
)


def sample(stop: Event, latest: dict) -> None:
    registry = ToolRegistry()
    for _, tool, _ in TOOLS:
        registry.register(tool())

    while not stop.is_set():
        snapshot = {"timestamp": datetime.now(timezone.utc).isoformat()}
        for key, tool, args in TOOLS:
            snapshot[key] = registry.invoke(tool.spec.name, args).to_dict()
        latest["body"] = json.dumps(snapshot, ensure_ascii=False).encode("utf-8")
        stop.wait(INTERVAL)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    page = Path(__file__).with_name("dashboard.html").read_bytes()
    latest = {"body": None}
    stop = Event()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.headers.get("Host") not in hosts:
                self.send_error(400, "Invalid Host")
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
        worker = Thread(target=sample, args=(stop, latest), daemon=True)
        worker.start()
        print(f"Dashboard: http://127.0.0.1:{port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            stop.set()
            worker.join()


if __name__ == "__main__":
    main()
