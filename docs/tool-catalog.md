# Tool catalog

All tools expose a `spec: ToolSpec` and `execute(**kwargs) -> ToolResult`. The
Registry validates the declared parameter schema and normalizes execution errors.
This catalog documents the implementation in the current source tree.

## System Observer (`tools/system.py`)

| Tool | Inputs | Output | Side effect |
|---|---|---|---|
| `get_system_overview` | None | Platform, CPU, memory, swap, uptime, process count | Read-only |
| `get_disk_usage` | `path` | Total/used/free bytes and percent used | Read-only |
| `list_top_processes` | Optional `limit` (default 5, range 1–50) | Process metadata sorted by RSS | Read-only |

## Logs & Diagnosis (`tools/logs.py`)

| Tool | Inputs | Output | Constraints |
|---|---|---|---|
| `get_failed_services` | None | Failed systemd service names | Linux/systemd only |
| `get_service_logs` | `service_name`; optional `lines` (1–200), `since_minutes` (1–1440) | Bounded journal lines | Unit name validation; finite timeout |
| `get_recent_errors` | Optional `lines` (1–200), `since_minutes` (1–1440) | Recent error-priority journal entries | Linux/journald only |

These tools do not elevate privileges. Permission and systemd availability errors are
returned as `ToolResult` failures rather than being hidden.

## Service Manager (`tools/services.py`)

| Tool | Inputs | Output | Side effect |
|---|---|---|---|
| `get_service_status` | `service_name` | Load/active/substate/unit-file state | Read-only |
| `restart_service` | `service_name` | Whether systemctl accepted the restart request | **State-changing**; explicit policy, allowlist, approval and `dry_run=false` required |

The Registry blocks ordinary invocation of `restart_service`. It must be reached only
through `ControlledExecutor`/the authorized Registry path. The tool itself also checks
`services.restart_enabled`, policy configuration, allowlist, platform, and dry-run.
No `sudo`, `shell=True`, arbitrary command strings, or automatic privilege escalation
are used. A successful restart command still requires health verification.

## Network Diagnostics (`tools/network.py`)

| Tool | Inputs | Output | Constraints |
|---|---|---|---|
| `get_network_state` | None | Interface up/down, speed, MTU and IP addresses | Read-only |
| `check_tcp_connectivity` | `host`, `port`; optional `timeout_seconds` (0.1–5.0) | Connection reachable/timeout state | Host/port validated; metadata targets blocked |
| `check_http_endpoint` | `url`; optional `timeout_seconds` (0.1–5.0) | HTTP status, reachable, healthy | HTTP/HTTPS only; credentials/fragments rejected; redirects not followed; bounded body read |

## Security & Policy (`tools/security.py`, `control.py`)

`inspect_security_posture` reports read-only runtime and configuration checks. The
`PolicyEngine` independently evaluates actions. LLM output never grants authorization.

## Verification & Recovery (`verification.py`)

| Tool/class | Inputs | Behavior |
|---|---|---|
| `verify_service_health` | `service_name` | Reads active state and reports whether the service is active |
| `verify_endpoint` | `url`; optional bounded timeout | Checks HTTP endpoint health without following redirects |
| `RecoveryManager` | A health-check callback, at most 3 attempts | Retries verification only; never retries the state-changing action |

## Registration

`register_builtin_tools(registry, config)` in `linux_admin.tools` registers the above
implementation classes. Creating/registering a tool does not execute it. The default
Agent planner only invokes read-only tools.
