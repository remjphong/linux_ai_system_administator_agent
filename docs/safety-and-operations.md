# Safety and operations

## Runtime posture

- The default configuration is `mode: observe`, `dry_run: true`, LLM disabled, and
  service restart disabled.
- Run as an ordinary user. No tool automatically invokes `sudo` or requests elevation.
- Tools use `ToolSpec` and `ToolResult`; only explicitly registered names can be invoked.
- The investigation Agent filters state-changing tools and cannot directly execute them.
- The policy engine is deterministic and uses `default_decision: deny`.
- A disruptive action requires explicit policy permission and an approval record bound to
  both the exact action ID and fingerprint of its arguments.
- `ControlledExecutor` writes an audit intent before invoking an action. If the audit
  write fails, the action is not started. If the post-action audit fails, the result
  warns that the action may already have occurred and that state must be verified.
- Service commands use fixed executable/argument lists, `shell=False`, finite timeout,
  service-unit validation, and an allowlist. They never execute an LLM-generated shell.
- HTTP checks do not follow redirects, accept only HTTP/HTTPS URLs, reject URL
  credentials and known cloud metadata endpoints, and read only a small response body.
- Recovery retries health checks only, with a finite retry count; it does not repeat a
  restart automatically.

## Before enabling restart on an Ubuntu test VM

1. Use an isolated, disposable VM snapshot and an explicitly named test service.
2. Verify the service unit is in `services.allowlist`.
3. Set the `restart_service` rule to `allowed: true` and keep
   `requires_approval: true` in `config/policy.yaml`.
4. Set `services.restart_enabled: true` only after confirming the policy rule is enabled.
5. Set `agent.mode: assisted` and `agent.dry_run: false` only for that controlled test.
6. Confirm the current OS user has only the exact systemd permissions needed; the app
   does not use sudoers or elevate itself.
7. Use `ControlledExecutor` and a matching `ApprovalRecord`. Never invoke
   `restart_service` through the normal Registry path.
8. Verify service health and, where applicable, the associated HTTP endpoint.
9. Inspect audit records and return configuration to safe defaults after testing.

## Platform support

The package and unit tests are intended to run on Windows 10/11 and Ubuntu. CPU, memory,
disk, process, and network-state reads use `psutil` and are cross-platform. `systemctl`
and `journalctl` adapters only work on a Linux environment with those tools; on Windows
or WSL without systemd they return an explicit error. Run integration tests involving
service units on an Ubuntu VM.

## Known limitations

- Console approval identifies the local OS account but is not a strong identity provider.
- Audit redacts secret-like field names; do not put secrets in arbitrary free-text fields.
- DNS is resolved by the operating-system networking stack; the endpoint checker is not
  a general-purpose SSRF defense. Use it only for operator-requested diagnostic targets.
- This is a local beta, not a multi-user production control plane. Before production use,
  add authenticated approvals, stricter network target policy, deployment hardening, and
  security review.

## Read-only tool risk table (6 new System Intelligence tools)

Six read-only diagnostic tools were added to expand system-intelligence coverage. All
are registered with `changes_system=False`, bypass `ControlledExecutor`, and are
declared in `config/policy.yaml` with `allowed: true` and `requires_approval: false`.
Because they never modify system state, they do not require approval or dry-run gating;
the policy entry exists so that the default `deny` rule does not accidentally block
them and so that operators can audit which tools are explicitly permitted.

| Tool | Action name | Risk | Rationale |
|------|-------------|------|-----------|
| ListAllMountsTool | `list_all_mounts` | Low | Reads mount table only (`/proc/mounts`); no writes. |
| GetIoStatsTool | `get_io_stats` | Low | Reads disk I/O counters (`/proc/diskstats`); no writes. |
| ListListeningPortsTool | `list_listening_ports` | Low | Reads LISTEN sockets; does not open or close ports. |
| GetKernelLogTool | `get_kernel_log` | Low | Reads kernel ring buffer / journal; no modification. |
| CheckAuthLogTool | `check_auth_log` | Low | Reads authentication log; no modification. |
| list_top_processes | `list_top_processes` | Low | Reads process list sorted by CPU; does not signal processes. |

**Threshold note (Question 1.1):** `config/policy.yaml` declares
`resource_threshold_percent: 80`. The diagnostics layer (owned by the Agent
integration track) is responsible for consuming this value; `control.py` does not
read it because it is not a state-changing action.

## Out-of-scope questions (Group C)

Four questions — **3.1, 3.3, 4.2, 4.3** — were deliberately dropped from the project
scope. They are documented here and in `docs/threat-model.md` so the decision is
traceable. Reasons:

- No read-only tool in the current registry can answer them safely.
- Answering them would require privileged operations (write, restart, firewall
  changes) that fall outside the read-only design and the approval workflow.
- The project follows a fail-closed principle: it is safer to exclude a question than
  to ship a tool whose blast radius cannot be bounded.

See `docs/threat-model.md` for the threat-model view of the same decision.
