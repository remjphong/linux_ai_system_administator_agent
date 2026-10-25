"""Command-line entry point for the Linux Admin Agent."""

from __future__ import annotations

import argparse
import sys

from linux_admin import __version__
from linux_admin.config import ConfigurationError, load_config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="linux-admin",
        description="Safety-first Linux system administration agent",
    )
    parser.add_argument(
        "--version", action="version", version=f"linux-admin-agent {__version__}"
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="Load and validate YAML configuration, then exit",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.check_config:
        parser.print_help()
        return 0

    try:
        config = load_config()
    except ConfigurationError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    print(f"Application: {config.name} {config.version}")
    print(f"Project root: {config.project_root}")
    print(f"Agent mode: {config.agent.mode}")
    print(f"Dry-run: {config.agent.dry_run}")
    print(f"Maximum steps: {config.agent.max_steps}")
    print(f"Tool timeout: {config.agent.tool_timeout_seconds:g}s")
    print(f"LLM enabled: {config.llm.enabled}")
    print(f"Policy actions loaded: {len(config.policy.actions)}")
    print(f"Service allowlist entries: {len(config.services.allowlist)}")
    print(f"Service restart enabled: {config.services.restart_enabled}")
    print(f"Audit enabled: {config.audit.enabled}")
    print(f"Audit database: {config.audit.database_path}")
    print("Configuration check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
