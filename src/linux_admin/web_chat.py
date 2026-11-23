"""Read-only web investigations with live LLM and Tavily integrations."""

import re
from dataclasses import replace
from time import perf_counter

from linux_admin.agent import Agent, RuleBasedPlanner
from linux_admin.audit import AuditLogger
from linux_admin.config import ConfigurationError, load_config
from linux_admin.main import _extract_external_references
from linux_admin.registry import ToolRegistry
from linux_admin.tools import register_builtin_tools

WEB_TOOLS = {
    "get_system_overview", "get_disk_usage", "list_top_processes",
    "list_all_mounts", "get_io_stats", "get_failed_services", "get_service_status",
    "get_network_state", "list_listening_ports", "inspect_listening_port",
    "inspect_security_posture", "tavily_web_search",
}


def configure_chat(config_dir: str | None):
    config = load_config(config_dir=config_dir)
    if not config.llm.enabled or not config.tavily.enabled:
        raise ConfigurationError(
            "Web chat cần LLM_ENABLED=true và TAVILY_ENABLED=true trong .env."
        )
    return replace(
        config,
        agent=replace(config.agent, mode="observe", dry_run=True),
        llm=replace(
            config.llm,
            planning_mode="llm",
            summary_enabled=True,
            timeout_seconds=min(config.llm.timeout_seconds, 8),
        ),
    )


class WebRegistry(ToolRegistry):
    def register(self, tool):
        if tool.spec.name in WEB_TOOLS and not tool.spec.changes_system:
            super().register(tool)


def describe_health(evidence, threshold: float) -> str:
    data = {item.tool_name: item.data for item in evidence if item.ok}
    system = data.get("get_system_overview", {})
    disk = data.get("get_disk_usage", {})
    values = [
        (label, value)
        for label, value in (
            ("CPU", system.get("cpu_percent")), ("RAM", system.get("memory_percent")),
            ("swap", system.get("swap_percent")), ("đĩa /", disk.get("used_percent")),
        )
        if type(value) in (int, float)
    ]
    failed = data.get("get_failed_services", {}).get("failed_services")
    if not values and failed is None:
        return "Mình chưa thu được đủ dữ liệu để đánh giá tình trạng máy."

    alerts = [label for label, value in values if value >= threshold]
    sentences = []
    if alerts:
        sentences.append(f"Mình thấy {', '.join(alerts)} đang ở ngưỡng cảnh báo.")
    elif len(values) == 4 and failed == []:
        sentences.append("Máy có vẻ ổn tại thời điểm kiểm tra.")
    if values:
        metrics = ", ".join(f"{label} {value:g}%" for label, value in values)
        sentences.append(f"Mức sử dụng hiện tại: {metrics}.")
    if failed:
        sentences.append(f"systemd báo {len(failed)} dịch vụ đang lỗi.")
    elif failed == []:
        sentences.append("systemd không báo dịch vụ nào bị lỗi.")
    if len(values) < 4 or failed is None:
        sentences.append("Một số chỉ số chưa đọc được.")
    return " ".join(sentences)


def investigate(config, message: str) -> dict:
    start = perf_counter()
    registry = register_builtin_tools(WebRegistry(), config)
    audit = AuditLogger(config.audit.database_path) if config.audit.enabled else None
    try:
        normalized = " ".join(
            RuleBasedPlanner._normalize_request(message).strip(" ?.!").split()
        )
        intent = normalized.removesuffix(" cho toi").removesuffix(" cho minh")
        quick_network = intent in {
            "kiem tra mang", "kiem tra tinh trang mang", "tinh trang mang",
            "trang thai mang", "kiem tra trang thai mang", "mang hien tai the nao",
        }
        quick = intent in {
            "kiem tra he thong", "tong quan he thong", "tinh trang he thong",
            "he thong hien tai the nao", "kiem tra tong the",
            "kiem tra tinh trang he thong", "kiem tra tinh trang he thong hien tai",
            "tinh trang he thong hien tai", "he thong dang chay the nao",
            "he thong co on khong", "he thong hien tai chay nhu the nao",
            "cho minh biet tinh trang he thong hien tai",
        }
        planner = RuleBasedPlanner(config) if quick or quick_network else None
        agent = Agent(registry, config, audit, planner=planner)
        incident = agent.run(message)
        references = _extract_external_references(incident.evidence)
        prefix = "LLM analysis: "
        summary = next(
            (line[len(prefix):] for line in incident.findings if line.startswith(prefix)),
            None,
        )
        rejected_summary = bool(summary and re.search(r"[㐀-鿿]", summary))
        if rejected_summary:
            summary = None
        has_overview = any(
            item.ok and item.tool_name == "get_system_overview"
            for item in incident.evidence
        )
        network = next(
            (item.data for item in incident.evidence
             if item.ok and item.tool_name == "get_network_state"),
            None,
        )
        if summary:
            answer = summary
        elif quick_network or (network is not None and not has_overview):
            if network is None:
                answer = "Mình chưa đọc được trạng thái card mạng."
            else:
                links = [link for link in network["interfaces"] if link["name"] != "lo"]
                states = ", ".join(
                    f'{link["name"]} đang ' + ("bật" if link["is_up"] else "tắt")
                    for link in links
                )
                answer = (
                    f"{states}. " if states
                    else "Chưa thấy card mạng ngoài loopback. "
                ) + "Chưa kiểm tra gateway, DNS hay kết nối Internet."
        elif quick or has_overview:
            answer = describe_health(
                incident.evidence, config.policy.resource_threshold_percent
            )
        else:
            answer = "Mình chưa có bản tổng hợp. Xem các kết quả đã thu được bên dưới."
        findings = [line for line in incident.findings if not line.startswith(prefix)]
        if rejected_summary:
            findings.append("Bản tổng hợp LLM có chữ Hán và đã được ẩn khỏi câu trả lời.")
        return {
            "incident_id": incident.incident_id,
            "status": incident.status,
            "summary": summary,
            "model": agent.summary_model if summary else None,
            "answer": answer,
            "findings": findings,
            "tools": [
                {
                    "name": tool.tool_name, "status": tool.status,
                    "ms": tool.duration_ms, "result": tool.data, "error": tool.error,
                }
                for tool in incident.evidence
            ],
            "references": references,
            "elapsed_ms": round((perf_counter() - start) * 1000),
        }
    finally:
        if audit is not None:
            audit.close()
