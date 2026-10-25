# Linux AI Agent System Administrator

A safety-first Python application for Linux system observation, incident diagnosis,
and controlled service administration. The team can develop and run unit tests on
Windows 10/11, while systemd/journald integration must be verified in Ubuntu.

## Implemented in this branch

- Shared contracts and validated YAML configuration.
- Registry with explicit tool registration, argument validation, and a guard that
  blocks ordinary invocation of state-changing tools.
- Real read-only system tools using `psutil` for CPU, memory, disk, process, and
  network-interface data.
- Linux adapters for `systemctl` and `journalctl` with fixed argument arrays,
  input validation, bounded output, and finite timeouts.
- TCP/HTTP endpoint checks with bounded timeouts; HTTP redirects are not followed.
- Read-only security posture checks.
- Deterministic policy engine, console approval records, controlled executor, and
  SQLite audit persistence.
- Post-action verification and a bounded recovery manager that retries health checks,
  not state-changing commands.
- Rule-based investigation Agent that can use real registered read-only tools.

The LLM is disabled by default. The current incident planner is rule-based; no model
is allowed to authorize actions. Service restart remains disabled by default and is
never performed by the investigation Agent. The explicit `--restart-service` command
uses `PolicyEngine`, asks for console approval only when enabled policy requires it,
then performs bounded post-action health verification. It will not restart with the
default observe/dry-run configuration.

## Supported environments

- Windows 10/11: package setup, code development, unit tests, `psutil` observations,
  network diagnostics, and tool-level tests. Windows does not provide `systemctl` or
  `journalctl`; Linux-specific tools return explicit unsupported/failure results.
- Ubuntu 22.04+ or compatible Ubuntu VM: intended environment for systemd/journald
  integration tests and controlled service-restart tests.
- Python 3.10 or newer.

## Setup on Windows 10/11 (PowerShell)

Open PowerShell in the repository root:

```powershell
py -3.10 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
linux-admin --check-config
pytest -q
ruff check .
```

If `py -3.10` is unavailable but `python` is Python 3.10+, replace the first command
with `python -m venv .venv`. If PowerShell blocks activation, use
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that same shell, then
activate again. For Command Prompt, activate with `.venv\Scripts\activate.bat`.

## Setup on Ubuntu

```bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
linux-admin --check-config
pytest -q
ruff check .
```

If `venv` is missing on Ubuntu, install the matching `python3-venv` package. Never
replace Ubuntu's system Python to satisfy this project.

## CLI

```bash
linux-admin --help
linux-admin --version
linux-admin --check-config
linux-admin --list-tools
linux-admin --investigate "Investigate disk pressure on filesystem /"
linux-admin --investigate "Investigate service failure for demo-web.service"
linux-admin --investigate "Investigate why http://127.0.0.1:8080/health is unreachable"
# Explicit action entry point; safe defaults will deny/skip it unless configured
linux-admin --restart-service demo-web.service --reason "Test controlled restart"
```

`--investigate` runs a bounded read-only investigation and prints structured JSON.
A status of `completed` means evidence collection completed; it does not mean the
incident was repaired. Service diagnostics require Ubuntu with systemd and permissions
to read the relevant service/journal.

The editable install exposes `linux-admin` from `linux_admin.main:main`. If the command
is not found, check the virtual environment is active and run `python -m pip install -e
".[dev]"` again.

## Configuration

- `config/agent.yaml`: observe/assisted mode, dry-run, step limit, tool timeout, LLM
  toggle, and SQLite audit path.
- `config/policy.yaml`: explicit action rules; missing rules are denied.
- `config/services.yaml`: service allowlist and restart kill switch.
- `.env.example`: environment variable names; copy to `.env` to configure an LLM
  provider and/or the separate Tavily search tool. Never commit `.env` or real keys.

Default operation is `mode: observe`, `dry_run: true`, LLM disabled, and service
restart disabled. To test actual restart, use an isolated Ubuntu VM snapshot, configure
one test service, deliberately review policy and permissions, and use
`ControlledExecutor` plus an approval record. Never enable restart on an important
host just to test the application.

## Shared safety rules

1. Every registered tool exposes `.spec: ToolSpec` and implements
   `execute(**kwargs) -> ToolResult`.
2. `ActionRequest` is a proposal, not authorization.
3. Policy decisions and approvals are bound to the exact action ID and argument
   fingerprint; approval cannot transfer to changed arguments.
4. State-changing tools cannot be called through the ordinary Registry invocation.
5. Do not execute arbitrary shell commands from users or LLM output; do not use
   `shell=True`, automatic `sudo`, or privilege escalation.
6. Verify postconditions instead of trusting only a command exit code.
7. If required audit persistence fails before execution, fail closed. If it fails after
   an action, report uncertainty and verify system state before retrying.
8. Unit tests use fixtures/mocks for OS commands and networking. Run real service tests
   only in a disposable Ubuntu VM.

Changes to `contracts.py`, `config/*.yaml`, or tool specs affect every team member.
Notify A/B/C, update tests and docs, and review the change before merging.


## Real LLM and Tavily web search

The project supports an OpenAI-compatible chat-completions API for LLM planning and
evidence synthesis. Tavily is integrated separately as an optional read-only web
search tool; a Tavily key alone does not enable LLM reasoning. See
[`docs/llm-and-tavily-setup.md`](docs/llm-and-tavily-setup.md) for the exact `.env`
variables, configuration switches, validation commands, and end-to-end workflow.
