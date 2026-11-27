"""Load and validate shared YAML configuration.

Secrets are read from environment variables (normally from a local .env file) and
are excluded from dataclass representations and routine configuration summaries.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml
from dotenv import load_dotenv


class ConfigurationError(ValueError):
    """Raised when configuration is missing, malformed, or inconsistent."""


@dataclass(frozen=True)
class AgentSettings:
    mode: str
    dry_run: bool
    max_steps: int
    tool_timeout_seconds: float
    connectivity_check_url: str | None = None


@dataclass(frozen=True)
class LLMSettings:
    enabled: bool
    provider: str | None
    model: str | None
    api_key_env: str
    api_key: str | None = field(default=None, repr=False)
    base_url: str = "http://127.0.0.1:11434/v1"
    timeout_seconds: float = 20.0
    max_output_tokens: int = 1200
    fallback_to_rules: bool = True
    planning_mode: str = "rules"
    summary_enabled: bool = False
    groq_model: str | None = None
    groq_api_key: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class TavilySettings:
    enabled: bool
    api_key_env: str
    api_key: str | None = field(default=None, repr=False)
    timeout_seconds: float = 8.0
    max_results: int = 3
    search_depth: str = "basic"


@dataclass(frozen=True)
class AuditSettings:
    enabled: bool
    database_path: Path


@dataclass(frozen=True)
class ActionPolicy:
    allowed: bool
    requires_approval: bool


@dataclass(frozen=True)
class PolicySettings:
    default_decision: str
    require_approval_for_disruptive_actions: bool
    allow_privilege_escalation: bool
    actions: dict[str, ActionPolicy]
    resource_threshold_percent: float = 80.0


@dataclass(frozen=True)
class ServiceSettings:
    allowlist: tuple[str, ...]
    restart_enabled: bool


@dataclass(frozen=True)
class SecuritySettings:
    monitor_ssh: bool = False
    interval_seconds: int = 30
    window_minutes: int = 5
    failure_threshold: int = 10


@dataclass(frozen=True)
class AppConfig:
    name: str
    version: str
    agent: AgentSettings
    llm: LLMSettings
    tavily: TavilySettings
    audit: AuditSettings
    policy: PolicySettings
    services: ServiceSettings
    project_root: Path
    config_dir: Path
    security: SecuritySettings = field(default_factory=SecuritySettings)


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ConfigurationError(f"Required configuration file not found: {path}")
    try:
        with path.open("r", encoding="utf-8") as file:
            value = yaml.safe_load(file)
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError(
            f"Could not read configuration file: {path.name}"
        ) from exc
    if not isinstance(value, dict):
        raise ConfigurationError(f"Root of {path.name} must be a YAML mapping")
    return value


def _mapping(parent: dict[str, Any], key: str, file_name: str) -> dict[str, Any]:
    value = parent.get(key)
    if not isinstance(value, dict):
        raise ConfigurationError(f"'{key}' in {file_name} must be a mapping")
    return value


def _required(mapping: dict[str, Any], key: str, file_name: str) -> Any:
    if key not in mapping:
        raise ConfigurationError(f"Missing '{key}' in {file_name}")
    return mapping[key]


def _string(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise ConfigurationError(f"{label} must be a non-empty string")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigurationError(f"{label} must be true or false")
    return value


def _env_boolean(name: str, fallback: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return fallback
    normalized = raw.strip().casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"Environment variable {name} must be true or false")


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigurationError(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{label} must be between {minimum} and {maximum}")
    return value


def _number(value: Any, label: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigurationError(f"{label} must be a number")
    numeric = float(value)
    if not minimum <= numeric <= maximum:
        raise ConfigurationError(f"{label} must be between {minimum:g} and {maximum:g}")
    return numeric


def _is_loopback_url(base_url: str) -> bool:
    host = (urlsplit(base_url).hostname or "").casefold()
    return host in {"localhost", "127.0.0.1", "::1"}


def load_config(
    config_dir: str | Path | None = None,
    *,
    project_root: str | Path | None = None,
    dotenv_path: str | Path | None = None,
) -> AppConfig:
    """Load YAML, then apply supported environment overrides.

    ``LLM_API_KEY`` belongs to the selected model provider. ``TAVILY_API_KEY`` is
    separate and is used only for Tavily web search; Tavily is not a chat LLM API.
    """
    default_root = Path(__file__).resolve().parents[2]
    if project_root is not None:
        root = Path(project_root).expanduser().resolve()
    elif config_dir is not None:
        root = Path(config_dir).expanduser().resolve().parent
    else:
        root = default_root

    cfg_dir = (
        Path(config_dir).expanduser().resolve()
        if config_dir is not None
        else (root / "config").resolve()
    )
    env_file = (
        Path(dotenv_path).expanduser().resolve()
        if dotenv_path is not None
        else root / ".env"
    )
    if env_file.is_file():
        load_dotenv(dotenv_path=env_file, override=False)

    agent_file = _read_yaml(cfg_dir / "agent.yaml")
    policy_file = _read_yaml(cfg_dir / "policy.yaml")
    services_file = _read_yaml(cfg_dir / "services.yaml")

    app_section = _mapping(agent_file, "app", "agent.yaml")
    runtime_section = _mapping(agent_file, "agent", "agent.yaml")
    network_section = agent_file.get("network", {})
    if not isinstance(network_section, dict):
        raise ConfigurationError("'network' in agent.yaml must be a mapping")
    llm_section = _mapping(agent_file, "llm", "agent.yaml")
    tavily_section = agent_file.get("tavily", {})
    if not isinstance(tavily_section, dict):
        raise ConfigurationError("'tavily' in agent.yaml must be a mapping")
    audit_section = _mapping(agent_file, "audit", "agent.yaml")

    app_name = _string(_required(app_section, "name", "agent.yaml"), "app.name")
    app_version = _string(
        _required(app_section, "version", "agent.yaml"), "app.version"
    )

    mode = _string(_required(runtime_section, "mode", "agent.yaml"), "agent.mode")
    if mode not in {"observe", "assisted"}:
        raise ConfigurationError("agent.mode must be 'observe' or 'assisted'")
    dry_run = _boolean(
        _required(runtime_section, "dry_run", "agent.yaml"), "agent.dry_run"
    )
    max_steps = _integer(
        _required(runtime_section, "max_steps", "agent.yaml"),
        "agent.max_steps",
        1,
        50,
    )
    timeout = _number(
        _required(runtime_section, "tool_timeout_seconds", "agent.yaml"),
        "agent.tool_timeout_seconds",
        0.1,
        120,
    )

    # Optional HTTPS probe used for generic Internet-connectivity requests.
    probe_value = (
        os.getenv("NETWORK_CONNECTIVITY_CHECK_URL")
        or network_section.get("connectivity_check_url")
    )
    connectivity_check_url = None
    if probe_value is not None:
        connectivity_check_url = _string(
            probe_value, "network.connectivity_check_url"
        )
        parsed_probe = urlsplit(connectivity_check_url)
        if (
            parsed_probe.scheme != "https"
            or not parsed_probe.hostname
            or parsed_probe.username
            or parsed_probe.password
            or parsed_probe.fragment
        ):
            raise ConfigurationError(
                "network.connectivity_check_url must be a clean HTTPS URL "
                "without credentials or a fragment"
            )
        try:
            _ = parsed_probe.port
        except ValueError as exc:
            raise ConfigurationError(
                "network.connectivity_check_url contains an invalid port"
            ) from exc

    # LLM: use an OpenAI-compatible chat completions endpoint. The API key is never
    # read from YAML; it is read from the configured environment variable.
    llm_enabled_yaml = _boolean(
        _required(llm_section, "enabled", "agent.yaml"), "llm.enabled"
    )
    llm_enabled = _env_boolean("LLM_ENABLED", llm_enabled_yaml)
    provider_value = os.getenv("LLM_PROVIDER") or llm_section.get("provider")
    model_value = os.getenv("LLM_MODEL") or llm_section.get("model")
    provider = (
        None
        if provider_value is None
        else _string(provider_value, "llm.provider")
    )
    model = None if model_value is None else _string(model_value, "llm.model")
    if provider is not None:
        provider = provider.casefold().replace("-", "_")
        if provider == "openai":
            provider = "openai_compatible"
    api_key_env = _string(
        llm_section.get("api_key_env", "LLM_API_KEY"), "llm.api_key_env"
    )
    api_key = os.getenv(api_key_env)
    base_url_value = (
        os.getenv("LLM_BASE_URL")
        or llm_section.get("base_url", "https://api.openai.com/v1")
    )
    base_url = _string(base_url_value, "llm.base_url").rstrip("/")
    parsed_base_url = urlsplit(base_url)
    if (
        parsed_base_url.scheme not in {"https", "http"}
        or not parsed_base_url.netloc
        or parsed_base_url.username
        or parsed_base_url.password
        or parsed_base_url.query
        or parsed_base_url.fragment
    ):
        raise ConfigurationError("llm.base_url must be a clean HTTP(S) API root URL")
    if parsed_base_url.scheme != "https" and not _is_loopback_url(base_url):
        raise ConfigurationError(
            "Remote LLM endpoints must use HTTPS; HTTP is allowed only on loopback"
        )
    llm_timeout = _number(
        llm_section.get("timeout_seconds", 20), "llm.timeout_seconds", 1, 60
    )
    max_output_tokens = _integer(
        llm_section.get("max_output_tokens", 1200),
        "llm.max_output_tokens",
        128,
        8192,
    )
    fallback_to_rules = _boolean(
        llm_section.get("fallback_to_rules", True), "llm.fallback_to_rules"
    )
    planning_mode_value = (
        os.getenv("LLM_PLANNING_MODE")
        or llm_section.get("planning_mode", "rules")
    )
    planning_mode = _string(
        planning_mode_value, "llm.planning_mode"
    ).casefold()
    if planning_mode not in {"rules", "llm"}:
        raise ConfigurationError("llm.planning_mode must be 'rules' or 'llm'")
    summary_enabled = _boolean(
        llm_section.get("summary_enabled", False), "llm.summary_enabled"
    )
    groq_api_key = os.getenv("GROQ_API_KEY", "").strip() or None
    groq_model = os.getenv("GROQ_MODEL", "").strip() or None
    if llm_enabled:
        if groq_api_key and not groq_model:
            raise ConfigurationError("Set GROQ_MODEL when GROQ_API_KEY is configured")
        if provider != "openai_compatible":
            raise ConfigurationError(
                "LLM is enabled but llm.provider is unsupported; "
                "use 'openai_compatible'"
            )
        if not model:
            raise ConfigurationError(
                "LLM is enabled but no model is configured; set LLM_MODEL"
            )
        if not api_key and not _is_loopback_url(base_url):
            raise ConfigurationError(
                f"LLM is enabled but {api_key_env} is missing; "
                "configure the model provider key"
            )

    # Tavily is a separate web-search service. It enriches the agent with sources,
    # but it does not replace the LLM planning and synthesis endpoint.
    tavily_enabled_default = _boolean(
        tavily_section.get("enabled", False), "tavily.enabled"
    )
    tavily_enabled = _env_boolean("TAVILY_ENABLED", tavily_enabled_default)
    tavily_api_key_env = _string(
        tavily_section.get("api_key_env", "TAVILY_API_KEY"),
        "tavily.api_key_env",
    )
    tavily_api_key = os.getenv(tavily_api_key_env)
    tavily_timeout = _number(
        tavily_section.get("timeout_seconds", 8),
        "tavily.timeout_seconds",
        1,
        30,
    )
    tavily_max_results = _integer(
        tavily_section.get("max_results", 3), "tavily.max_results", 1, 5
    )
    tavily_search_depth = _string(
        tavily_section.get("search_depth", "basic"), "tavily.search_depth"
    )
    if tavily_search_depth not in {"basic", "advanced"}:
        raise ConfigurationError("tavily.search_depth must be 'basic' or 'advanced'")
    if tavily_enabled and not tavily_api_key:
        raise ConfigurationError(
            f"Tavily search is enabled but {tavily_api_key_env} is missing; "
            "put the key in .env"
        )

    audit_enabled = _boolean(
        _required(audit_section, "enabled", "agent.yaml"), "audit.enabled"
    )
    db_value = _string(
        _required(audit_section, "database_path", "agent.yaml"),
        "audit.database_path",
    )
    database_path = Path(db_value).expanduser()
    if not database_path.is_absolute():
        database_path = root / database_path
    database_path = database_path.resolve()

    policy_root = _mapping(policy_file, "policy", "policy.yaml")
    resource_threshold_percent = _number(
        policy_root.get("resource_threshold_percent", 80),
        "policy.resource_threshold_percent",
        1.0,
        100.0,
    )
    default_decision = _string(
        _required(policy_root, "default_decision", "policy.yaml"),
        "policy.default_decision",
    )
    if default_decision != "deny":
        raise ConfigurationError(
            "policy.default_decision must be 'deny' (fail-closed default)"
        )
    require_approval = _boolean(
        _required(
            policy_root, "require_approval_for_disruptive_actions", "policy.yaml"
        ),
        "policy.require_approval_for_disruptive_actions",
    )
    allow_privilege_escalation = _boolean(
        _required(policy_root, "allow_privilege_escalation", "policy.yaml"),
        "policy.allow_privilege_escalation",
    )
    action_rules = _mapping(policy_file, "actions", "policy.yaml")
    parsed_actions: dict[str, ActionPolicy] = {}
    for action_name, raw_rule in action_rules.items():
        if not isinstance(action_name, str) or not action_name.strip():
            raise ConfigurationError("Policy action names must be non-empty strings")
        if not isinstance(raw_rule, dict):
            raise ConfigurationError(
                f"Policy action '{action_name}' must be a mapping"
            )
        parsed_actions[action_name] = ActionPolicy(
            allowed=_boolean(
                _required(raw_rule, "allowed", "policy.yaml"),
                f"actions.{action_name}.allowed",
            ),
            requires_approval=_boolean(
                _required(raw_rule, "requires_approval", "policy.yaml"),
                f"actions.{action_name}.requires_approval",
            ),
        )

    services_root = _mapping(services_file, "services", "services.yaml")
    raw_allowlist = _required(services_root, "allowlist", "services.yaml")
    if not isinstance(raw_allowlist, list) or not all(
        isinstance(item, str) and item.strip() for item in raw_allowlist
    ):
        raise ConfigurationError(
            "services.allowlist must be a list of non-empty strings"
        )
    if len(raw_allowlist) != len(set(raw_allowlist)):
        raise ConfigurationError("services.allowlist must not contain duplicates")
    restart_enabled = _boolean(
        _required(services_root, "restart_enabled", "services.yaml"),
        "services.restart_enabled",
    )
    if restart_enabled:
        restart_rule = parsed_actions.get("restart_service")
        if not raw_allowlist:
            raise ConfigurationError(
                "Restart cannot be enabled with an empty allowlist"
            )
        if restart_rule is None or not restart_rule.allowed:
            raise ConfigurationError(
                "services.restart_enabled is true, but policy does not allow "
                "restart_service"
            )
        if not restart_rule.requires_approval:
            raise ConfigurationError(
                "restart_service must require approval while restart is enabled"
            )

    security = agent_file.get("security", {})
    if not isinstance(security, dict):
        raise ConfigurationError("'security' in agent.yaml must be a mapping")
    security_settings = SecuritySettings(
        monitor_ssh=_boolean(security.get("monitor_ssh", False), "security.monitor_ssh"),
        interval_seconds=_integer(
            security.get("interval_seconds", 30), "security.interval_seconds", 10, 300
        ),
        window_minutes=_integer(
            security.get("window_minutes", 5), "security.window_minutes", 1, 60
        ),
        failure_threshold=_integer(
            security.get("failure_threshold", 10), "security.failure_threshold", 3, 100
        ),
    )

    return AppConfig(
        name=app_name,
        version=app_version,
        agent=AgentSettings(
            mode=mode,
            dry_run=dry_run,
            max_steps=max_steps,
            tool_timeout_seconds=timeout,
            connectivity_check_url=connectivity_check_url,
        ),
        llm=LLMSettings(
            enabled=llm_enabled,
            provider=provider,
            model=model,
            api_key_env=api_key_env,
            api_key=api_key,
            base_url=base_url,
            timeout_seconds=llm_timeout,
            max_output_tokens=max_output_tokens,
            fallback_to_rules=fallback_to_rules,
            planning_mode=planning_mode,
            summary_enabled=summary_enabled,
            groq_model=groq_model,
            groq_api_key=groq_api_key,
        ),
        tavily=TavilySettings(
            enabled=tavily_enabled,
            api_key_env=tavily_api_key_env,
            api_key=tavily_api_key,
            timeout_seconds=tavily_timeout,
            max_results=tavily_max_results,
            search_depth=tavily_search_depth,
        ),
        audit=AuditSettings(enabled=audit_enabled, database_path=database_path),
        policy=PolicySettings(
            default_decision=default_decision,
            require_approval_for_disruptive_actions=require_approval,
            allow_privilege_escalation=allow_privilege_escalation,
            actions=parsed_actions,
            resource_threshold_percent=resource_threshold_percent,
        ),
        services=ServiceSettings(
            allowlist=tuple(raw_allowlist),
            restart_enabled=restart_enabled,
        ),
        project_root=root,
        config_dir=cfg_dir,
        security=security_settings,
    )
