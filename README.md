# Linux AI Agent System Administrator

A Python project for Linux system observation, incident diagnosis, and controlled
administration. This repository is designed for a three-person team that may
write code on Windows 10/11 but validates Linux administration behavior on an
Ubuntu VM.

## Project status

The starter foundation currently provides:

- A `linux-admin` command-line entry point.
- Loading and validation of the shared YAML configuration.
- Shared contracts: `ToolResult`, `ToolSpec`, `ActionRequest`, `PolicyDecision`,
  `ApprovalRecord`, and `IncidentContext`.
- A registry with explicit tool registration, argument validation, and guards
  against normal invocation of system-changing tools.
- Unit tests for contracts, registry, and configuration.

The full incident agent, real Linux tool adapters, production policy workflow,
approval interaction, system-changing executor, post-action verification, SQLite
audit persistence, and LLM adapter are not yet implemented. Placeholder files are
not evidence that these features work.

## Supported development environments

- Windows 10/11: code editing and unit tests. Linux-only integration behavior
  must be mocked or tested on the Ubuntu VM.
- Ubuntu 22.04 or a compatible Ubuntu VM: development and Linux integration tests.
- Python 3.10 or newer.

The application administers Linux systems; native Windows is not the target for
`systemctl` or `journalctl` operations. Do not run Linux integration commands
from PowerShell and expect them to behave like Ubuntu.

## Setup on Windows 10/11 (PowerShell)

Install Python 3.10+ and ensure the Python Launcher (`py`) or `python` is on PATH.
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

If the PowerShell execution policy prevents virtual-environment activation, run
the following only in the current PowerShell process, then activate again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

If `py -3.10` is unavailable but `python` points to Python 3.10 or newer, use:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

For Command Prompt (`cmd.exe`), activation is:

```bat
.venv\Scripts\activate.bat
```

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

If `venv` is not installed on Ubuntu, install the matching package, for example:

```bash
sudo apt update
sudo apt install python3-venv
```

## Common commands (Windows and Ubuntu)

Once the virtual environment is activated:

```text
linux-admin --help
linux-admin --version
linux-admin --check-config
pytest -q
ruff check .
```

The `linux-admin` command is installed by the editable package. If it is not
found, check that the virtual environment is activated and rerun
`python -m pip install -e ".[dev]"`.

## Configuration

- `config/agent.yaml`: application metadata, operation mode, dry-run, step/time
  limits, LLM toggle, and audit database path.
- `config/policy.yaml`: explicit action rules and fail-closed default policy.
- `config/services.yaml`: service allowlist and restart kill switch.
- `.env.example`: names of environment variables that may be used for an LLM.

The LLM is disabled by default and service restart is disabled by default. Copy
`.env.example` to `.env` only when necessary, and never commit the real `.env` or
an API key. Relative paths such as `data/audit.db` are resolved from the project
root rather than the process's current working directory.

## Shared interface and safety rules

1. Every registered tool exposes `.spec: ToolSpec` and implements
   `execute(**kwargs) -> ToolResult`.
2. `ActionRequest` is a proposal, not authorization to execute.
3. Policy decisions and approvals must bind to the exact action ID and action
   arguments; approval must not transfer to a different action.
4. Policy defaults to deny. System-changing operations must be explicitly
   enabled, allowlisted, and require approval where configured.
5. Do not expose an arbitrary shell-command tool to the LLM.
6. Verify actual post-action state instead of trusting only an exit code.
7. A configuration value does not enforce itself; the application code and tests
   must load and enforce the value before the feature can be considered implemented.

Changes to `contracts.py`, `config/*.yaml`, or tool interfaces affect all three
team members. Notify A/B/C, update tests, and review the change before merging.
