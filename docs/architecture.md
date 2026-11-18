# Architecture

## Runtime flow

```text
CLI (main.py)
  -> load_config (config.py)
  -> register_builtin_tools (tools/__init__.py)
  -> Agent / RuleBasedPlanner (agent.py)
  -> ToolRegistry (registry.py)
  -> real read-only tool adapters (tools/*.py)
  -> ToolResult / IncidentContext (contracts.py)
  -> structured JSON report
  -> SQLite audit events (audit.py)
```

The CLI `--investigate` runs read-only diagnosis. It selects a bounded plan, invokes
only registered non-mutating tools, stores summarized evidence, and returns a structured
report. The explicit `--restart-service` CLI route creates an `ActionRequest`, evaluates
policy, requests local console approval where required and configured, and delegates to
`ControlledExecutor`; it then runs bounded read-only verification if an action may have
executed. This action route remains inert under the default observe/dry-run configuration.
LLM integration is optional and disabled by default; the rule-based planner works without
an API or network connection.

## Control boundary for state-changing actions

```text
ActionRequest
  -> PolicyEngine (control.py)
  -> exact service allowlist / configured action rule
  -> explicit ApprovalRecord bound to action ID + argument fingerprint
  -> dry-run gate
  -> ToolRegistry.invoke_authorized_action
  -> RestartServiceTool (fixed systemctl argv; no shell or sudo)
  -> verify_service_health / verify_endpoint (verification.py)
  -> AuditLogger (audit.py)
```

The investigation Agent cannot invoke a state-changing tool directly. `restart_service`
is disabled by default in YAML and the adapter checks configuration again. A successful
`systemctl restart` only indicates that the command was accepted; it is not proof that
the service or its HTTP endpoint is healthy. Verification must determine that outcome.

## Module ownership

- A: `contracts.py`, `config.py`, `agent.py`, `llm_client.py`, `registry.py`,
  `audit.py`, CLI integration, end-to-end tests, packaging and README.
- B: `tools/system.py`, `tools/logs.py`, `tools/network.py`, `tools/security.py`,
  tool tests and the tool catalog.
- C: `control.py`, `tools/services.py`, `verification.py`, policy/service configuration,
  control tests, and safety/operations documentation.

## Platform boundary

`psutil`-based system and network-interface metrics are cross-platform. The service and
journal adapters require Linux with systemd/journald and run fixed commands with bounded
timeouts. Windows unit tests mock these commands; Ubuntu VM tests verify the real
systemd behavior. HTTP diagnostic checks do not follow redirects and restrict inputs,
but are not a general-purpose SSRF defense.

## LLM planning and Tavily web search

When `llm.enabled` (or `LLM_ENABLED=true`) is enabled, `Agent` uses the
OpenAI-compatible chat completions adapter in `llm_client.py` to propose a
structured read-only plan. The registered tool catalog and argument schemas are
sent to the model; the response is parsed and checked against that catalog before
the Agent invokes tools through `ToolRegistry`. System-changing tools remain
blocked from the investigation workflow.

After successful evidence collection, the same model receives bounded, redacted
tool results and produces a report. If planning fails and `llm.fallback_to_rules`
is true, the Agent records the fallback and uses `RuleBasedPlanner`. A synthesis
failure is reported explicitly; local tool findings remain available.

Tavily is an optional read-only web-search tool, registered only when
`tavily.enabled` (or `TAVILY_ENABLED=true`) and `TAVILY_API_KEY` are configured.
Tavily search can provide external documentation; it does not replace the chat
LLM provider. Web results are untrusted content and are never proof of the local
host's state.
