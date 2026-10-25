# Architecture and shared interfaces

## Intended runtime flow

1. `main.py` starts the CLI and loads `config.py`.
2. `agent.py` will create an `IncidentContext` and control the bounded workflow.
3. The planner (initially rule-based, later optionally LLM-backed) chooses a registered tool.
4. `registry.py` validates arguments and calls only explicitly registered tools.
5. A tool returns `ToolResult` as defined in `contracts.py`.
6. A proposed state-changing operation is represented as `ActionRequest`; it is not authorization.
7. `control.py` will consult policy and approval rules before calling a controlled adapter.
8. `verification.py` will inspect the actual post-action state.
9. `audit.py` will persist important events after its SQLite implementation is added.

The full workflow above is the target design. In this starter package, configuration,
contracts, registry, and the configuration-check CLI are implemented; later stages remain TODO.

## Shared contract ownership

`contracts.py` is shared by A, B, and C. Do not change field names or statuses without
coordinating the change and updating tests. Each tool exposes `.spec: ToolSpec` and
`execute(**kwargs) -> ToolResult`.

## Safety boundary

The LLM must not execute shell commands or grant itself permissions. Any system-changing
action must pass deterministic policy checks, approval when required, a controlled executor,
and a postcondition verification. Configuration currently keeps service restart disabled.
