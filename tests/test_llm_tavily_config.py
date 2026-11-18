"""Configuration tests for LLM and Tavily credentials/toggles."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from linux_admin.config import ConfigurationError, load_config


def _copy_config_tree(tmp_path: Path) -> Path:
    source = Path(__file__).resolve().parents[1] / "config"
    target = tmp_path / "config"
    shutil.copytree(source, target)
    return target


def _clear_api_environment(monkeypatch) -> None:
    for name in (
        "LLM_ENABLED",
        "LLM_PROVIDER",
        "LLM_MODEL",
        "LLM_BASE_URL",
        "LLM_PLANNING_MODE",
        "LLM_API_KEY",
        "TAVILY_ENABLED",
        "TAVILY_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)


def test_llm_planning_mode_environment_override(tmp_path, monkeypatch):
    _clear_api_environment(monkeypatch)
    monkeypatch.setenv("LLM_PLANNING_MODE", "llm")
    config_dir = _copy_config_tree(tmp_path)

    config = load_config(
        config_dir=config_dir,
        project_root=tmp_path,
        dotenv_path=tmp_path / "no-such-dotenv-file",
    )

    assert config.llm.planning_mode == "llm"
    assert config.llm.enabled is False


def test_blank_env_toggles_keep_safe_yaml_defaults(tmp_path, monkeypatch) -> None:
    _clear_api_environment(monkeypatch)
    for name in ("LLM_ENABLED", "LLM_MODEL", "TAVILY_ENABLED", "TAVILY_API_KEY"):
        monkeypatch.setenv(name, "")
    config_dir = _copy_config_tree(tmp_path)

    config = load_config(
        config_dir=config_dir,
        project_root=tmp_path,
        dotenv_path=tmp_path / "no-such-dotenv-file",
    )

    assert config.llm.enabled is False
    assert config.tavily.enabled is False


def test_enabling_llm_without_provider_key_fails_closed(tmp_path, monkeypatch) -> None:
    _clear_api_environment(monkeypatch)
    monkeypatch.setenv("LLM_ENABLED", "true")
    monkeypatch.setenv("LLM_PROVIDER", "openai_compatible")
    monkeypatch.setenv("LLM_MODEL", "test-model")
    monkeypatch.setenv("LLM_BASE_URL", "https://llm.example/v1")
    config_dir = _copy_config_tree(tmp_path)

    with pytest.raises(ConfigurationError, match="LLM_API_KEY is missing"):
        load_config(
            config_dir=config_dir,
            project_root=tmp_path,
            dotenv_path=tmp_path / "no-such-dotenv-file",
        )


def test_enabling_tavily_without_key_fails_closed(tmp_path, monkeypatch) -> None:
    _clear_api_environment(monkeypatch)
    monkeypatch.setenv("TAVILY_ENABLED", "true")
    config_dir = _copy_config_tree(tmp_path)

    with pytest.raises(ConfigurationError, match="TAVILY_API_KEY is missing"):
        load_config(
            config_dir=config_dir,
            project_root=tmp_path,
            dotenv_path=tmp_path / "no-such-dotenv-file",
        )
