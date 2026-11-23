"""Control a dedicated loopback HTTP service and verify it through real probes."""

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock, Thread

from linux_admin.tools.network import HttpEndpointTool
from linux_admin.verification import VerifyEndpointTool

SCENARIOS = {
    "service_exit": "Dịch vụ thử nghiệm ngừng lắng nghe",
    "service_unready": "Dịch vụ thử nghiệm trả HTTP 503",
}


class IncidentDemo:
    def __init__(self, monitor):
        self.monitor = monitor
        self.lock = Lock()
        self.incident = None
        self.server = None
        self.port = 0
        self.status = 200
        if monitor is not None:
            self.start_server()

    def start_server(self):
        demo = self

        class HealthHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(demo.status if self.path == "/health" else 404)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *_args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", self.port), HealthHandler)
        self.port = self.server.server_port
        Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        with self.lock:
            self.stop_server()

    def stop_server(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

    @property
    def endpoint(self):
        return f"http://127.0.0.1:{self.port}/health"

    def snapshot(self):
        with self.lock:
            return self.incident

    def record_probe(self, result, subject):
        evidence = (
            f"HTTP {result.data['status_code']}"
            if result.data.get("status_code") is not None
            else result.error or "Không kết nối được tới endpoint."
        )
        self.monitor.observe_endpoint(
            subject, datetime.now(timezone.utc).isoformat(),
            result, f"{self.endpoint} · {evidence}",
        )
        return evidence

    def trigger(self, scenario):
        if self.monitor is None:
            raise ValueError("Khởi động dashboard với --monitor để bật dịch vụ thử.")
        if not isinstance(scenario, str) or scenario not in SCENARIOS:
            raise ValueError("Loại sự cố demo không hợp lệ.")
        with self.lock:
            if self.incident and self.incident["state"] == "detected":
                raise ValueError("Hãy xử lý sự cố demo đang mở trước.")
            if scenario == "service_exit":
                self.stop_server()
            else:
                self.status = 503
            result = HttpEndpointTool().execute(url=self.endpoint, timeout_seconds=1)
            if result.ok and result.data.get("healthy") is True:
                raise ValueError("Endpoint vẫn phản hồi khỏe.")
            listener = scenario == "service_exit"
            category = "network" if listener else "system"
            subject = f"demo:http:{'listener' if listener else 'readiness'}:{self.port}"
            evidence = self.record_probe(result, subject)
            self.incident = {
                "subject": subject,
                "category": category,
                "steps": [
                    {
                        "kind": "Thao tác nội bộ",
                        "name": (
                            "Khởi động lại listener thử nghiệm"
                            if listener else "Khôi phục phản hồi health thành HTTP 200"
                        ),
                    },
                    {
                        "kind": "Tool hậu kiểm",
                        "name": "verify_endpoint",
                        "target": self.endpoint,
                    },
                ],
                "state": "detected",
                "title": SCENARIOS[scenario],
                "evidence": evidence,
                "proposal": (
                    "Khởi động lại listener HTTP thử nghiệm rồi gọi verify_endpoint."
                    if scenario == "service_exit"
                    else "Khôi phục phản hồi health thành HTTP 200 rồi gọi verify_endpoint."
                ),
            }
            return self.incident

    def recover(self):
        with self.lock:
            if not self.incident or self.incident["state"] != "detected":
                raise ValueError("Hiện không có sự cố demo đang mở.")
            self.status = 200
            if self.server is None:
                self.start_server()
            result = VerifyEndpointTool().execute(url=self.endpoint, timeout_seconds=1)
            if not result.ok or result.data.get("healthy") is not True:
                raise ValueError("Hậu kiểm HTTP chưa đạt.")
            evidence = self.record_probe(result, self.incident["subject"])
            self.incident = {**self.incident, "state": "verified", "evidence": evidence}
            return self.incident
