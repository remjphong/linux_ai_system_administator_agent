"""Load and validate shared YAML configuration.

Configuration errors fail startup. Secrets are read from environment variables
and are deliberately excluded from normal summaries and dataclass repr output.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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


@dataclass(frozen=True)
class LLMSettings:
    enabled: bool
    provider: str | None
    model: str | None
    api_key_env: str
    api_key: str | None = field(default=None, repr=False)


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


@dataclass(frozen=True)
class ServiceSettings:
    allowlist: tuple[str, ...]
    restart_enabled: bool


@dataclass(frozen=True)
class AppConfig:
    name: str
    version: str
    agent: AgentSettings
    llm: LLMSettings
    audit: AuditSettings
    policy: PolicySettings
    services: ServiceSettings
    project_root: Path
    config_dir: Path


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


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigurationError(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{label} must be between {minimum} and {maximum}")
    return value


def load_config(
    config_dir: str | Path | None = None,
    *,
    project_root: str | Path | None = None,
    dotenv_path: str | Path | None = None,
) -> AppConfig:
    """Load the three shared YAML files and validate cross-file assumptions.

    Args:
        config_dir: Directory containing agent.yaml, policy.yaml, services.yaml.
            Defaults to `<project-root>/config`.
        project_root: Root used to resolve relative runtime paths. If omitted,
            the root is inferred from this source file or from config_dir.
        dotenv_path: Optional explicit .env file. Defaults to `<project-root>/.env`.
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
    llm_section = _mapping(agent_file, "llm", "agent.yaml")
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
    timeout_value = _required(runtime_section, "tool_timeout_seconds", "agent.yaml")
    if isinstance(timeout_value, bool) or not isinstance(timeout_value, (int, float)):
        raise ConfigurationError("agent.tool_timeout_seconds must be a number")
    timeout = float(timeout_value)
    if not 0 < timeout <= 120:
        raise ConfigurationError("agent.tool_timeout_seconds must be > 0 and <= 120")

    llm_enabled = _boolean(
        _required(llm_section, "enabled", "agent.yaml"), "llm.enabled"
    )
    provider_value = llm_section.get("provider")
    model_value = llm_section.get("model")
    provider = (
        None
        if provider_value is None
        else _string(provider_value, "llm.provider")
    )
    model = None if model_value is None else _string(model_value, "llm.model")
    api_key_env = _string(
        llm_section.get("api_key_env", "LLM_API_KEY"), "llm.api_key_env"
    )
    api_key = os.getenv(api_key_env)
    if llm_enabled and (not provider or not model or not api_key):
        raise ConfigurationError(
            "llm.enabled is true but provider, model, or API key is missing; "
            "configure agent.yaml and the named environment variable"
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
            raise ConfigurationError(f"Policy action '{action_name}' must be a mapping")
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

    return AppConfig(
        name=app_name,
        version=app_version,
        agent=AgentSettings(
            mode=mode,
            dry_run=dry_run,
            max_steps=max_steps,
            tool_timeout_seconds=timeout,
        ),
        llm=LLMSettings(
            enabled=llm_enabled,
            provider=provider,
            model=model,
            api_key_env=api_key_env,
            api_key=api_key,
        ),
        audit=AuditSettings(enabled=audit_enabled, database_path=database_path),
        policy=PolicySettings(
            default_decision=default_decision,
            require_approval_for_disruptive_actions=require_approval,
            allow_privilege_escalation=allow_privilege_escalation,
            actions=parsed_actions,
        ),
        services=ServiceSettings(
            allowlist=tuple(raw_allowlist),
            restart_enabled=restart_enabled,
        ),
        project_root=root,
        config_dir=cfg_dir,
    )
