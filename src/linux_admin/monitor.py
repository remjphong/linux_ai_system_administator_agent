"""Store sustained monitoring events separately from remediation audit records."""

import argparse
import json
import sqlite3
from contextlib import closing
from pathlib import Path

from linux_admin.audit import AuditLogger
from linux_admin.config import load_config
from linux_admin.contracts import IncidentContext
from linux_admin.registry import ToolRegistry
from linux_admin.remediation_workflow import (
    build_remediation_proposal,
    run_remediation_workflow,
)
from linux_admin.tools import register_builtin_tools

DEFAULT_DB = Path("data/monitor.db")


def incident_category(subject: str) -> str:
    if subject.startswith(("network:", "demo:http:listener:")):
        return "network"
    if subject.startswith("security:"):
        return "security"
    if subject in {"cpu", "ram", "disk"} or subject.startswith(("service:", "demo:http:")):
        return "system"
    return "unknown"


class Monitor:
    def __init__(self, path: Path):
        self.path = path
        self.pending: dict[str, int] = {}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self.connect()) as db, db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY,
                    subject TEXT NOT NULL,
                    opened_at TEXT NOT NULL,
                    cleared_at TEXT,
                    evidence TEXT NOT NULL
                )
            """)
            db.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS one_open_incident
                ON incidents(subject) WHERE cleared_at IS NULL
            """)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=2)
        db.row_factory = sqlite3.Row
        return db

    def recent(self):
        with closing(self.connect()) as db:
            return [dict(row, category=incident_category(row["subject"])) for row in db.execute("""
                SELECT * FROM incidents ORDER BY (cleared_at IS NULL) DESC, id DESC
                LIMIT 30
            """)]

    def observe(self, snapshot: dict) -> None:
        timestamp = snapshot["timestamp"]
        metrics = (
            ("cpu", "system", "cpu_percent", 90, 80),
            ("ram", "system", "memory_percent", 90, 85),
            ("disk", "disk", "used_percent", 90, 85),
        )
        with closing(self.connect()) as db, db:
            for subject, tool, field, high, low in metrics:
                result = snapshot.get(tool, {})
                value = (result.get("data") or {}).get(field)
                if result.get("status") != "success" or type(value) not in (int, float):
                    self.pending.pop(subject, None)
                    continue
                if value >= high:
                    count = self.pending[subject] = self.pending.get(subject, 0) + 1
                    if count >= 3:
                        self._open(db, subject, timestamp, f"{value:g}% · ngưỡng {high}%")
                else:
                    self.pending.pop(subject, None)
                    if value < low:
                        self._clear(db, subject, timestamp)

            services = snapshot.get("services", {})
            names = (services.get("data") or {}).get("failed_services")
            if services.get("status") == "success" and isinstance(names, list):
                failed = {f"service:{name}" for name in names}
                for subject in sorted(failed):
                    self._open(db, subject, timestamp, "systemd báo failed")
                active = db.execute("""
                    SELECT subject FROM incidents
                    WHERE subject LIKE 'service:%' AND cleared_at IS NULL
                """).fetchall()
                for row in active:
                    if row["subject"] not in failed:
                        self._clear(db, row["subject"], timestamp)

            network = snapshot.get("network", {})
            interfaces = (network.get("data") or {}).get("interfaces")
            if network.get("status") == "success" and isinstance(interfaces, list):
                for link in interfaces:
                    if link["name"] == "lo":
                        continue
                    subject = "network:" + link["name"]
                    if link["is_up"]:
                        self._clear(db, subject, timestamp)
                    else:
                        # Only alert for interfaces explicitly selected by the operator.
                        if link["name"] in snapshot.get("watch_interfaces", []):
                            self._open(db, subject, timestamp, "Card mạng đang tắt")

    def observe_endpoint(self, subject, timestamp, result, evidence):
        """Record a failed endpoint probe or clear it after verified recovery."""
        with closing(self.connect()) as db, db:
            if result.ok and result.data.get("healthy") is True:
                self._clear(db, subject, timestamp)
            else:
                self._open(db, subject, timestamp, evidence)

    @staticmethod
    def _open(db, subject, timestamp, evidence):
        db.execute("""
            INSERT INTO incidents (subject, opened_at, evidence) VALUES (?, ?, ?)
            ON CONFLICT(subject) WHERE cleared_at IS NULL
            DO UPDATE SET evidence = excluded.evidence
        """, (subject, timestamp, evidence))

    @staticmethod
    def _clear(db, subject, timestamp):
        db.execute("""
            UPDATE incidents SET cleared_at = ?
            WHERE subject = ? AND cleared_at IS NULL
        """, (timestamp, subject))


def main() -> None:
    parser = argparse.ArgumentParser(description="Khắc phục sự cố service đã giám sát")
    parser.add_argument("incident_id", type=int)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--config-dir", default="config")
    parser.add_argument("--endpoint", help="URL dịch vụ cần hậu kiểm, do người vận hành nhập")
    args = parser.parse_args()
    monitor = Monitor(args.db)
    with closing(monitor.connect()) as db:
        incident = db.execute(
            "SELECT * FROM incidents WHERE id = ? AND cleared_at IS NULL",
            (args.incident_id,),
        ).fetchone()
    if incident is None or not incident["subject"].startswith("service:"):
        parser.error("Cần ID của một sự cố systemd đang mở.")
    name = incident["subject"].removeprefix("service:")
    config = load_config(config_dir=args.config_dir)
    registry = register_builtin_tools(ToolRegistry(), config)
    current = registry.invoke("get_service_status", {"service_name": name})
    context = IncidentContext(user_request=f"Khắc phục sự cố {name}")
    context.evidence.append(current)
    proposal = build_remediation_proposal(context, config, registry)
    if proposal is None:
        parser.error("Lần kiểm tra mới chưa xác nhận service đang failed.")
    if not config.audit.enabled:
        parser.error("Cần bật audit để chạy luồng khắc phục.")
    with AuditLogger(config.audit.database_path) as audit:
        audit.record_event(
            event_type="monitor.remediation_requested",
            incident_id=context.incident_id,
            details={"monitor_incident_id": args.incident_id, "service": name},
        )
        result = run_remediation_workflow(
            proposal,
            incident_id=context.incident_id,
            config=config,
            registry=registry,
            audit=audit,
            diagnosis_findings=[f"Monitoring incident #{args.incident_id}: {name}"],
            verification_url=args.endpoint,
            endpoint_verification_required=bool(args.endpoint),
        )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if result["status"] != "verified_recovered":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
