# Linux AI System Administrator Agent

A safety-first Linux diagnostic agent that investigates system issues, collects evidence, and suggests actionable next steps.

**Status:** Research prototype — not production-ready.

## Overview

Linux Admin Agent accepts natural-language investigation requests, selects diagnostic tools, and reports observed facts, possible causes, and recommended next steps. It uses **observe mode** by default and does not restart services during ordinary investigations.

## Features

- **System monitoring:** CPU, RAM, swap, disk usage, processes, and mount points.
- **I/O diagnostics:** Disk activity, CPU iowait, and bounded per-process I/O observations.
- **Logs and services:** Kernel errors, possible OOM evidence, authentication events, and systemd status.
- **Network diagnostics:** Listening ports, TCP connectivity, HTTP endpoints, and visible process ownership.
- **Investigation planning:** Rule-based diagnostics and evidence-driven follow-ups; optional LLM and Tavily integration.
- **Safety and auditing:** Policy restrictions, dry-run defaults, controlled approvals, and SQLite audit logs.

## Quick Start

**Requirements:** Ubuntu/Linux, Python 3.10+, Git, `venv`, and `pip`. Run as a normal user; do not use `sudo pip install`.

```bash
git clone https://github.com/remjphong/linux_ai_system_administator_agent.git
cd linux_ai_system_administator_agent
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

The default clone uses the `main` branch. Verify the installation and run a read-only investigation:

```bash
linux-admin --check-config
linux-admin --list-tools
linux-admin --investigate "Inspect CPU and RAM usage. Read only."
```

No LLM or Tavily API key is required. An investigation normally creates a local SQLite audit database at `data/audit.db` (the checkout must be writable). If Python `venv` is unavailable, ask the environment administrator to provide the appropriate Python venv package before proceeding.

## Configuration and safety

Configuration lives in `config/agent.yaml`, `config/policy.yaml`, and `config/services.yaml`. The defaults are observe mode, `dry_run: true`, at most five investigation steps, disabled service restart, enabled SQLite audit, rule-based planning, and disabled LLM/Tavily.

Controlled service remediation is a separate restricted workflow, **not** part of normal read-only investigations. Do not enable it on production systems without further security review.

## Documentation

| Document | What it covers |
| --- | --- |
| [Architecture](docs/architecture.md) | Components, architecture, and data flow |
| [Tool Catalog](docs/tool-catalog.md) | Registered diagnostics, parameters, and limitations |
| [Safety & Operations](docs/safety-and-operations.md) | Authorization, audit, and operational controls |
| [Threat Model](docs/threat-model.md) | Trust boundaries, threats, and residual risk |
| [LLM & Tavily Setup](docs/llm-and-tavily-setup.md) | Optional AI planning and external search configuration |

## Development and testing

With the virtual environment active:

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
python -m ruff check .
python -m compileall -q src tests
```

## Known limitations

This prototype has been independently tested for installation and read-only investigations on Ubuntu 22.04.5 under WSL2, but full bare-metal compatibility has not been established. Process-I/O and resource measurements are bounded observations, not definitive causal proof. Root-cause identification, full firewall diagnosis, live LLM/Tavily availability, privileged service remediation, and production security readiness are not guaranteed.

For details, see [Safety & Operations](docs/safety-and-operations.md) and [Tool Catalog](docs/tool-catalog.md).

---

**Project status:** Completed research prototype, accepted with documented limitations.
