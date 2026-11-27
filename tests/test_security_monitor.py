from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from linux_admin import monitor as monitoring
from linux_admin.contracts import ToolResult
from linux_admin.monitor import SSH_REVIEW, Monitor, verify_ssh
from linux_admin.tools import security_updates as updates

IP = "2001:db8::1"
TS = datetime(2026, 11, 27, tzinfo=timezone.utc)
DEFINITION = "oval:com.ubuntu.jammy:def:1"


def observation(*, failures=0, accepted=False, complete=True):
    return ToolResult("check_auth_log", "success", data={
        "coverage_complete": complete,
        "window_minutes": 1,
        "suspicious_ips": [{"ip": IP, "failure_count": failures,
                            "accepted_after_failures": accepted}] if failures >= 3 else [],
        "failed_source_ips": [IP] if failures else [],
    })


def test_ssh_incident_deduplicates_and_requires_complete_cooldown(tmp_path):
    monitor = Monitor(tmp_path / "incidents.db")
    def observe(seconds, result):
        monitor.observe_ssh((TS + timedelta(seconds=seconds)).isoformat(), result, 30)

    observe(0, observation(failures=3))
    observe(30, observation(failures=5))
    incident = monitor.recent()[0]
    assert incident["subject"] == f"security:ssh:{IP}"
    assert incident["category"] == "security"
    assert len(monitor.recent()) == 1
    observe(60, observation(complete=False))
    observe(90, observation())
    observe(120, observation())
    assert monitor.recent()[0]["cleared_at"] is None
    observe(150, observation())
    resolved = monitor.recent()[0]
    assert resolved["id"] == incident["id"]
    assert resolved["cleared_at"] is not None


def test_ssh_success_after_failures_requires_operator_review(tmp_path, monkeypatch, app_config):
    monitor = Monitor(tmp_path / "incidents.db")
    monitor.observe_ssh(TS.isoformat(), observation(failures=3, accepted=True), 30)
    monitor.observe_ssh((TS + timedelta(seconds=30)).isoformat(), observation(failures=3), 30)
    monitor.observe_ssh((TS + timedelta(seconds=60)).isoformat(), observation(), 30)
    incident = monitor.recent()[0]
    assert incident["evidence"].startswith(SSH_REVIEW)
    assert incident["cleared_at"] is None
    config = replace(app_config, audit=replace(app_config.audit, database_path=tmp_path / "audit.db"))
    monkeypatch.setattr(monitoring.AuthLogTool, "execute", lambda *a, **kw: observation())
    assert verify_ssh(monitor, incident, config, False)["status"] == "review_required"
    assert verify_ssh(monitor, incident, config, True)["closed"] is True
    assert monitor.recent()[0]["cleared_at"] is not None


@pytest.fixture
def oval_fixture(tmp_path, monkeypatch):
    monkeypatch.setattr(updates.platform, "freedesktop_os_release",
                        lambda: {"ID": "ubuntu", "VERSION_CODENAME": "jammy"})
    monkeypatch.setattr(updates, "_FOLDER", tmp_path)
    lsb = tmp_path / "lsb-release"
    lsb.write_text("DISTRIB_CODENAME=jammy\n")
    monkeypatch.setattr(updates, "_LSB_RELEASE", lsb)
    data = tmp_path / "data"
    data.mkdir()
    feed = data / "com.ubuntu.jammy.usn.oval.xml"
    timestamp = datetime.now(timezone.utc).isoformat()
    feed.write_text(f"""<oval_definitions xmlns="urn:oval">
      <generator><timestamp>{timestamp}</timestamp></generator>
      <definitions><definition id="{DEFINITION}" class="patch"><metadata>
        <title>USN-1234-1 -- Editor security fix</title>
        <description>Fix incorrect permissions.</description>
        <reference source="USN" ref_id="USN-1234-1"/>
        <reference source="CVE" ref_id="CVE-2026-1234"/>
      </metadata><criteria><criterion test_ref="t1"/></criteria></definition></definitions>
      <tests><dpkginfo_test id="t1"><object object_ref="o1"/>
        <state state_ref="s1"/></dpkginfo_test></tests>
      <objects><dpkginfo_object id="o1"><name var_ref="v1"/></dpkginfo_object></objects>
      <states><dpkginfo_state id="s1"><evr operation="less than">1:2.0-0ubuntu1</evr>
        </dpkginfo_state></states>
      <variables><constant_variable id="v1"><value>demo-package</value>
        <value>another-package</value></constant_variable></variables>
    </oval_definitions>""", encoding="utf-8")
    state = SimpleNamespace(version="1:1.9-0ubuntu1", result="true")
    run = updates.subprocess.run

    def run_fixture(command, **kwargs):
        if command[0] == "oscap":
            Path(command[command.index("--results") + 1]).write_text(f"""
              <oval_results xmlns="urn:results"><results><system><definitions>
              <definition definition_id="oval:com.ubuntu.jammy:def:100" result="true"/>
              <definition definition_id="{DEFINITION}" result="{state.result}">
              <criteria result="{state.result}">
              <criterion test_ref="t1" result="{state.result}"/>
              </criteria></definition></definitions></system></results></oval_results>
            """, encoding="utf-8")
            return SimpleNamespace(returncode=0)
        if command[0] == "dpkg-query":
            return SimpleNamespace(stdout=(
                f"installed\tdemo-package\tamd64\t{state.version}\teditors\tSample editor\n"
                "installed\tanother-package\tall\t1:2.5-0ubuntu1\tlibs\tSample library\n"
            ))
        return run(command, **kwargs)

    monkeypatch.setattr(updates.subprocess, "run", run_fixture)
    return updates.SecurityUpdatesTool(tmp_path), state, feed


def test_scan_and_verify_same_package_using_debian_version_order(oval_fixture):
    tool, state, _ = oval_fixture
    scan = tool.execute()
    assert scan.data["assessment"] == "missing"
    assert scan.data["missing"][0]["fixed_version"] == "1:2.0-0ubuntu1"
    assert scan.data["missing"][0]["cves"] == ["CVE-2026-1234"]
    assert tool.execute(package="demo-package", usn="USN-1234-1").data["assessment"] == "still_missing"
    state.version, state.result = "1:2.0-0ubuntu2", "false"
    assert tool.execute().data["assessment"] == "clear"
    assert tool.execute(package="demo-package:amd64", usn="USN-1234-1").data["assessment"] == "patched"
    assert tool.execute(package="demo-package:arm64", usn="USN-1234-1").data["assessment"] == "inconclusive"
    (tool.project_root / "reboot-required.pkgs").write_text("demo-package\n")
    assert tool.execute(package="demo-package", usn="USN-1234-1").data["assessment"] == "restart_required"


def test_unknown_evaluation_and_stale_oval_cannot_pass(oval_fixture):
    tool, state, feed = oval_fixture
    state.result = "unknown"
    assert tool.execute().data["assessment"] == "inconclusive"
    xml = feed.read_text()
    old = datetime.now(timezone.utc) - timedelta(days=8)
    start = xml.index("<timestamp>") + len("<timestamp>")
    feed.write_text(xml[:start] + old.isoformat() + xml[xml.index("</timestamp>"):])
    assert tool.execute().status == "failed"


def test_inventory_groups_separate_missing_patched_and_unknown(oval_fixture):
    tool, state, _ = oval_fixture
    grouped = tool.execute(include_inventory=True).data["package_groups"]
    assert [(item["package"], item["architecture"]) for item in grouped["missing"]] == [
        ("demo-package", "amd64")
    ]
    assert [(item["package"], item["architecture"]) for item in grouped["patched"]] == [
        ("another-package", "all")
    ]
    entry = grouped["missing"][0]
    assert entry["package_category"] == "Trình soạn thảo"
    assert entry["package_summary"] == "Sample editor"
    assert entry["patch_label"] == "Editor security fix"
    assert entry["patch_topics"] == ["Quyền truy cập"]
    state.result = "unknown"
    grouped = tool.execute(include_inventory=True).data["package_groups"]
    assert not grouped["patched"] and not grouped["missing"]
    assert len(grouped["inconclusive"]) == 2


def test_inventory_prefers_missing_then_highest_debian_version():
    groups = {}
    key = ("demo-package", "amd64")
    for status, version in (
        ("patched", "2.0"), ("missing", "2.1~esm2"), ("inconclusive", "2.3"),
        ("missing", "2.1~esm10"),
    ):
        updates._record_package(groups, key, {"fixed_version": version},
                                status, updates._version_is_older)
    assert groups[key] == {"fixed_version": "2.1~esm10", "assessment": "missing"}
