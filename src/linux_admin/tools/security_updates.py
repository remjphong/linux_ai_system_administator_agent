"""Evaluate local Ubuntu packages against a Canonical USN OVAL feed."""
from __future__ import annotations

import gzip
import platform
import re
import subprocess
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from linux_admin.audit import AuditLogger
from linux_admin.contracts import ToolResult, ToolSpec

_PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]+(?::[a-z0-9-]+)?")
_USN = re.compile(r"USN-\d+-\d+")
_FOLDER = Path("/run")
_LSB_RELEASE = Path("/etc/lsb-release")
_KNOWN_RESULTS = {"true", "false", "not applicable"}


def _indexed(root, section):
    return {item.get("id"): item for item in root.findall(f"{{*}}{section}/*")}


def _catalog(root, release):
    """Read the package thresholds and advisory references from the OVAL feed."""
    generated = datetime.fromisoformat(root.findtext("{*}generator/{*}timestamp") or "")
    if generated.tzinfo is None:
        generated = generated.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    if not now - timedelta(days=7) <= generated <= now + timedelta(minutes=10):
        raise ValueError("Dữ liệu USN OVAL đã cũ hoặc có thời điểm bất hợp lệ.")

    definitions = _indexed(root, "definitions")
    if not definitions or not all(
        definition.startswith(f"oval:com.ubuntu.{release}:def:") for definition in definitions
    ):
        raise ValueError("USN OVAL không khớp bản Ubuntu đang chạy.")

    objects, states, variables = (_indexed(root, section) for section in
                                  ("objects", "states", "variables"))
    package_tests = {}
    for test_id, test in _indexed(root, "tests").items():
        if not test.tag.endswith("}dpkginfo_test"):
            continue
        obj = objects[test.find("{*}object").get("object_ref")]
        state_ref = test.find("{*}state")
        if state_ref is None:
            continue
        name = obj.find("{*}name")
        evr = states[state_ref.get("state_ref")].find("{*}evr")
        if evr is None or evr.get("operation") != "less than" or not evr.text:
            continue
        variable = variables.get(name.get("var_ref"))
        names = ([v.text for v in variable.findall("{*}value")]
                 if variable is not None else [name.text])
        package_tests[test_id] = (set(filter(None, names)), evr.text)

    notices = {}
    for definition_id, definition in definitions.items():
        if definition.get("class") != "patch":
            continue
        references = definition.findall("{*}metadata/{*}reference")
        usn = next((ref.get("ref_id", "") for ref in references
                    if ref.get("source") == "USN"), "")
        if _USN.fullmatch(usn):
            notices[definition_id] = (
                usn,
                sorted({ref.get("ref_id") for ref in references
                        if ref.get("source") == "CVE" and ref.get("ref_id")}),
                definition,
            )
    if not notices:
        raise ValueError("File OVAL không có thông báo USN.")
    return generated, notices, package_tests


def _installed_packages():
    proc = subprocess.run(
        ["dpkg-query", "-W", ("-f=${db:Status-Status}\\t${Package}\\t"
         "${Architecture}\\t${Version}\\t${Section}\\t${binary:Synopsis}\\n")],
        capture_output=True, text=True, check=True, timeout=15,
    )
    packages = defaultdict(list)
    metadata = {}
    for line in proc.stdout.splitlines():
        status, name, arch, version, *details = line.split("\t", maxsplit=5)
        if status != "installed":
            continue
        packages[name].append((arch, version))
        section, summary = details if len(details) == 2 else ("", "")
        metadata[name, arch] = (section.rsplit("/", 1)[-1], summary)
    return packages, metadata


def _version_is_older(installed: str, fixed: str) -> bool:
    proc = subprocess.run(["dpkg", "--compare-versions", installed, "lt", fixed],
                          capture_output=True, check=False, timeout=5)
    if proc.returncode not in {0, 1}:
        raise ValueError("Không so sánh được phiên bản Debian của gói.")
    return proc.returncode == 0


_PACKAGE_SECTIONS = {
    "admin": "Quản trị hệ thống", "devel": "Công cụ phát triển", "doc": "Tài liệu",
    "editors": "Trình soạn thảo", "fonts": "Phông chữ", "graphics": "Đồ họa",
    "kernel": "Nhân hệ điều hành", "libdevel": "Thư viện phát triển",
    "libs": "Thư viện", "oldlibs": "Thư viện tương thích", "net": "Mạng",
    "mail": "Thư điện tử", "database": "Cơ sở dữ liệu", "python": "Hệ sinh thái Python",
    "ruby": "Hệ sinh thái Ruby", "perl": "Hệ sinh thái Perl", "shells": "Shell",
    "sound": "Âm thanh", "video": "Đa phương tiện", "utils": "Tiện ích",
    "web": "Phần mềm web", "x11": "Giao diện X11", "gnome": "Giao diện GNOME",
    "kde": "Giao diện KDE", "security": "Công cụ bảo mật",
}
_PATCH_TOPICS = (
    ((r"memory operations?|memory safety|memory corruption|buffer overflow|out[- ]of[- ]bounds|"
     r"use[- ]after[- ]free|double free|heap corruption"), "An toàn bộ nhớ"),
    ((r"incorrect permissions|wrong permissions|file permissions|directory permissions|"
     r"permission checks?|improper permissions"), "Quyền truy cập"),
    ((r"authentication bypass|improper authentication|incorrectly authenticat|"
     r"authentication mechanism"), "Xác thực"),
    ((r"certificate validation|verif\w+ certificates?|signature verification|"
     r"incorrectly verif\w+ signatures?"), "Xác minh chứng chỉ hoặc chữ ký"),
    (r"cross[- ]site scripting|cross[- ]site request forgery", "Bảo mật ứng dụng web"),
)
_PATCH_PRECEDENCE = {"patched": 0, "inconclusive": 1, "missing": 2}


def _record_package(groups, key, entry, status, is_older):
    current = groups.get(key)
    if current is not None:
        old_rank = _PATCH_PRECEDENCE[current["assessment"]]
        new_rank = _PATCH_PRECEDENCE[status]
        if new_rank < old_rank:
            return
        if new_rank == old_rank and not is_older(
            current["fixed_version"], entry["fixed_version"]
        ):
            return
    groups[key] = {**entry, "assessment": status}


def _matching_tests(node):
    """Return tests on branches that OpenSCAP confirmed true."""
    if node.get("result") != "true":
        return
    if node.tag.endswith("}criterion") and node.get("negate") != "true":
        yield node.get("test_ref")
    for child in node:
        yield from _matching_tests(child)


class SecurityUpdatesTool:
    spec = ToolSpec(
        name="check_security_updates",
        description="Check official Ubuntu packages against locally prepared Canonical USN OVAL data.",
    )

    def __init__(self, project_root: Path):
        self.project_root = project_root

    def execute(
        self, *, package: str | None = None, usn: str | None = None,
        include_inventory: bool = False,
    ) -> ToolResult:
        if (package is not None or usn is not None) and (
            not _PACKAGE.fullmatch(package or "") or not _USN.fullmatch(usn or "")
        ):
            return ToolResult(self.spec.name, "invalid_input",
                              error="Nhập tên gói hợp lệ và mã USN, ví dụ USN-1234-1.")
        try:
            data = self._scan(package, usn, include_inventory)
        except subprocess.TimeoutExpired:
            return ToolResult(self.spec.name, "timeout", data={"assessment": "inconclusive"},
                              error="Quét USN OVAL vượt quá thời gian cho phép.")
        except (OSError, ET.ParseError, AttributeError, KeyError, TypeError,
                ValueError, subprocess.CalledProcessError) as exc:
            message = str(exc) if isinstance(exc, ValueError) else (
                "Không đọc được dữ liệu USN OVAL hoặc không chạy được OpenSCAP/dpkg."
            )
            return ToolResult(self.spec.name, "failed", data={"assessment": "inconclusive"},
                              error=message)
        return ToolResult(self.spec.name, "success", data=data)

    def _scan(self, package, usn, include_inventory):
        distro = platform.freedesktop_os_release()
        release = distro.get("VERSION_CODENAME")
        if distro.get("ID") != "ubuntu" or release != "jammy":
            raise ValueError("Quét bản vá hiện hỗ trợ Ubuntu 22.04 (jammy).")
        # The Canonical Jammy inventory rule checks this marker, too. A missing
        # marker must not turn every advisory false on a minimal installation.
        if not _LSB_RELEASE.is_file() or "DISTRIB_CODENAME=jammy" not in (
            _LSB_RELEASE.read_text(encoding="utf-8").splitlines()
        ):
            raise ValueError("Thiếu dấu nhận diện jammy trong /etc/lsb-release.")
        feed = self.project_root / "data" / f"com.ubuntu.{release}.usn.oval.xml"
        if not feed.is_file():
            raise ValueError(f"Thiếu dữ liệu {feed.name}. Xem cách chuẩn bị trong README.")
        generated, notices, package_tests = _catalog(ET.parse(feed).getroot(), release)
        if usn:
            notices = {key: value for key, value in notices.items() if value[0] == usn}
            if not notices:
                raise ValueError("USN này không nằm trong dữ liệu Ubuntu đang dùng.")

        with TemporaryDirectory(prefix="linux-admin-oval-") as directory:
            output = Path(directory) / "results.xml"
            command = ["oscap", "oval", "eval", "--results", str(output)]
            if usn and len(notices) == 1:
                command.extend(("--id", next(iter(notices))))
            subprocess.run([*command, str(feed)], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=True, timeout=90)
            root = ET.parse(output).getroot()
        evaluations = {
            item.get("definition_id"): item for item in
            root.findall("{*}results/{*}system/{*}definitions/{*}definition")
        }
        if not usn:
            inventory = evaluations.get(f"oval:com.ubuntu.{release}:def:100")
            if inventory is None or inventory.get("result") != "true":
                raise ValueError("OpenSCAP chưa xác nhận được môi trường Ubuntu 22.04.")
        installed, metadata = _installed_packages()
        name, _, arch = (package or "").partition(":")
        findings = []
        version_cache: dict[tuple[str, str], bool] = {}
        versions = []
        unknown = 0
        groups = {}

        def is_older(left, right):
            if left == right:
                return False
            pair = (left, right)
            if pair not in version_cache:
                version_cache[pair] = _version_is_older(left, right)
            return version_cache[pair]

        for definition_id, (notice, cves, definition) in notices.items():
            prior_findings = len(findings)
            evaluation = evaluations.get(definition_id)
            outcome = evaluation.get("result") if evaluation is not None else None
            known = outcome in _KNOWN_RESULTS
            if not known:
                unknown += 1
                if not include_inventory or name:
                    continue
            if not name and outcome == "not applicable":
                continue
            positive = set(_matching_tests(evaluation)) if known else set()
            references = {item.get("test_ref") for item in definition.findall(".//{*}criterion")}
            title = (definition.findtext("{*}metadata/{*}title") or "").strip() or notice
            title = re.sub(r"^USN-\d+-\d+\s*--\s*", "", title)
            description = definition.findtext("{*}metadata/{*}description") or ""
            topics = [label for pattern, label in _PATCH_TOPICS
                      if re.search(pattern, description, re.IGNORECASE)]
            for test_id in sorted(references & package_tests.keys()):
                names, fixed = package_tests[test_id]
                if name and name not in names:
                    continue
                if not include_inventory and not name and test_id not in positive:
                    continue
                for binary in sorted(names & installed.keys()):
                    if name and binary != name:
                        continue
                    for architecture, version in installed[binary]:
                        if arch and arch != architecture:
                            continue
                        section, summary = metadata[binary, architecture]
                        entry = {
                            "package": binary, "architecture": architecture,
                            "installed_version": version, "fixed_version": fixed,
                            "usn": notice, "cves": cves, "patch_label": title, "patch_topics": topics,
                            "package_section": section, "package_summary": summary,
                            "package_category": _PACKAGE_SECTIONS.get(section, section or "Chưa phân loại"),
                            "advisory": f"https://ubuntu.com/security/notices/{notice}",
                        }
                        older = known and is_older(version, fixed)
                        confirmed_missing = test_id in positive and older
                        if confirmed_missing and entry not in findings:
                            findings.append(entry)
                        if name:
                            versions.append((entry, older, outcome != "not applicable"))
                        elif include_inventory:
                            status = ("missing" if confirmed_missing else
                                      "inconclusive" if older or not known else "patched")
                            _record_package(groups, (binary, architecture), entry, status, is_older)
            if not name and outcome == "true" and len(findings) == prior_findings:
                unknown += 1

        data = {
            "release": release, "scope": "Ubuntu USN OVAL / installed .deb names covered by Canonical",
            "feed_generated_at": generated.isoformat(),
            "missing_count": len(findings), "missing": findings[:100],
            "inconclusive_definitions": unknown,
        }
        if name:
            # Exact validation requires an installed Ubuntu package. All relevant
            # fixed thresholds must be satisfied, including across architectures.
            candidates = [entry for entry, _, _ in versions]
            data.update(package=package, usn=usn, compared_packages=candidates[:100])
            if findings:
                data["assessment"] = "still_missing"
            elif unknown or not versions or any(
                older or not applicable for _, older, applicable in versions
            ):
                data["assessment"] = "inconclusive"
            else:
                reboot_packages = _FOLDER / "reboot-required.pkgs"
                names = (reboot_packages.read_text(encoding="utf-8").splitlines()
                         if reboot_packages.is_file() else [])
                data["assessment"] = (
                    "restart_required" if name in names else "patched"
                )
        else:
            package_groups = {"missing": [], "patched": [], "inconclusive": []}
            for _, entry in sorted(groups.items()):
                package_groups[entry["assessment"]].append(entry)
            if include_inventory:
                data["package_groups"] = package_groups
            data["assessment"] = (
                "missing" if findings else
                "inconclusive" if unknown or package_groups["inconclusive"] else "clear"
            )
        return data


def _manual_summary(path: Path) -> str | None:
    """Read the NAME section from a local, packaged man page."""
    try:
        resolved = path.resolve()
        if not resolved.is_relative_to("/usr/share/man") or not resolved.is_file():
            return None
        read = gzip.open if resolved.suffix == ".gz" else Path.open
        with read(resolved, "rt", encoding="utf-8", errors="replace") as manual:
            text = manual.read(16_384)
    except (OSError, RuntimeError, EOFError):
        return None
    section = re.search(
        r'^\.SH +"?NAME"?[ \t]*\n(.*?)(?=^\.S[HS] |\Z)',
        text, re.MULTILINE | re.DOTALL | re.IGNORECASE,
    )
    if section is None:
        return None
    body = " ".join(line.strip() for line in section[1].splitlines()
                    if not line.startswith("."))
    body = re.sub(r"\\f(?:\[[^\]]*\]|[BIRP01234])", "", body)
    parts = re.split(r" +(?:\\-|-) +", body, maxsplit=1)
    return parts[1][:320].strip() if len(parts) == 2 else None


def package_details(package: str, architecture: str) -> dict:
    """Inspect local package metadata and its declared files without running them."""
    if (not isinstance(package, str) or len(package) > 96 or ":" in package
            or not _PACKAGE.fullmatch(package)):
        raise ValueError("Tên gói không hợp lệ.")
    if not isinstance(architecture, str) or not re.fullmatch(r"[a-z0-9-]{1,32}", architecture):
        raise ValueError("Kiến trúc gói không hợp lệ.")
    target = f"{package}:{architecture}"
    metadata = subprocess.run(
        ["dpkg-query", "-W", "-f=" + (
            "${db:Status-Status}\n${Package}\n${Architecture}\n"
            "${Version}\n${Description}"
        ), "--", target],
        capture_output=True, text=True, check=False, timeout=5,
    )
    fields = metadata.stdout.split("\n", maxsplit=4)
    if metadata.returncode or len(fields) != 5 or fields[:3] != ["installed", package, architecture]:
        raise ValueError("Không tìm thấy gói đã cài với kiến trúc này.")
    listing = subprocess.run(
        ["dpkg-query", "-L", "--", target], capture_output=True, text=True, check=True, timeout=5,
    )
    paths = [Path(line) for line in listing.stdout.splitlines() if line.startswith("/")]
    manuals = {}
    for path in paths:
        if path.is_relative_to("/usr/share/man") and re.search(r"\.[1-8](?:\.gz)?$", path.name):
            name = path.name.removesuffix(".gz").rsplit(".", maxsplit=1)[0]
            manuals.setdefault(name, path)

    description = fields[4].strip()
    summary = description.partition("\n")[0]
    body = description.partition("\n")[2]
    body = "\n".join("" if line.strip() == "." else line.strip() for line in body.splitlines())
    directories = {"/bin", "/sbin", "/usr/bin", "/usr/sbin"}
    commands = sorted({path.name for path in paths
                       if str(path.parent) in directories and path.is_file()})
    libraries = sorted({
        path.name for path in paths
        if (path.is_relative_to("/usr/lib") or path.is_relative_to("/lib"))
        and re.search(r"\.so(?:\.[0-9.]+)?$", path.name) and path.is_file()
    })
    tools = [{
        "name": name,
        "description": (_manual_summary(manuals[name]) if name in manuals else None)
        or (summary if name == package else None),
    } for name in commands[:40]]
    return {
        "package": package, "architecture": architecture, "version": fields[3],
        "summary": summary, "description": body[:3000], "tools": tools,
        "tool_count": len(commands), "libraries": libraries[:30], "library_count": len(libraries),
    }


def verify_security_update(tool, package: str, usn: str, audit: AuditLogger) -> ToolResult:
    """Check and audit a package using the same policy in the CLI and dashboard."""
    result = tool.execute(package=package, usn=usn)
    if result.status != "invalid_input":
        audit.record_event(
            event_type="security.patch_checked",
            incident_id=f"security:patch:{package}:{usn}",
            details={"package": package, "usn": usn, **result.data,
                     "tool_status": result.status},
        )
    return result
