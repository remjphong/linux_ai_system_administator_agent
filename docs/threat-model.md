# Threat model

This document captures the security assumptions, trust boundaries, and explicitly
excluded threats for the Linux AI System Administrator Agent. It complements
`docs/safety-and-operations.md`.

## Assets

- The host operating system and its services.
- Configuration files (`config/policy.yaml`, `config/services.yaml`, `config/agent.yaml`).
- Audit logs produced by `AuditLogger`.
- The LLM API key and any credentials in `.env`.

## Trust boundaries

1. **Operator ↔ CLI**: the operator is trusted to type `APPROVE` for disruptive actions,
   but the console approval is not a strong identity provider. It is acceptable only
   for a single-user local beta.
2. **Agent ↔ Tools**: the Agent may *propose* state-changing actions but cannot execute
   them. Execution is routed exclusively through `ControlledExecutor`, which enforces
   policy, approval, and audit.
3. **Tools ↔ Host**: tools run as an unprivileged user. No tool invokes `sudo`, opens
   a shell (`shell=False` everywhere), or executes LLM-generated command strings.
4. **App ↔ LLM provider**: prompts may contain diagnostic evidence. Secrets are
   redacted from audit fields; operators must not paste secrets into free-text prompts.

## Threats considered and mitigated

| Threat | Mitigation |
|--------|-----------|
| Prompt injection causing destructive shell | Fixed executable/argument lists, `shell=False`, allowlist, `ControlledExecutor` gating |
| Model hallucinating a service name | `services.allowlist` validation in `PolicyEngine` |
| Approval replay against a different action | Approval bound to `action_id` + `action_fingerprint` |
| Audit bypass | Fail-closed: no audit ⇒ no execution; denial also audited |
| SSRF via endpoint checker | Only HTTP/HTTPS, no redirects, reject URL credentials and metadata IPs |
| Privilege escalation | `allow_privilege_escalation: false`; app never calls `sudo` |

## Out of scope — dropped questions (Group C)

The following questions were removed from the project scope. They are listed here so
the decision is auditable and so future contributors do not silently reintroduce them
without an accompanying threat-model update.

| Question | Topic (per assignment) | Why it is out of scope |
|----------|------------------------|------------------------|
| 3.1 | System configuration change / privileged remediation | Requires write access and privileged operations; no read-only tool can answer it; blast radius cannot be bounded by the current approval workflow. |
| 3.3 | Destructive file or package operation | High risk of data loss; outside the read-only design; would require a new approval class and rollback strategy not present in this beta. |
| 4.2 | Firewall / network policy change | Modifies host network posture; a mistake can lock out the operator; requires privileged tooling not implemented here. |
| 4.3 | Service/daemon lifecycle change beyond the single allowlisted restart | Broader than the single `restart_service` action that is gated by `ControlledExecutor`; expanding scope would multiply the attack surface without proportional benefit for the assignment. |

**Decision principle:** fail-closed. If a question cannot be answered with a read-only
tool under the existing policy/approval/audit stack, it is excluded rather than
implemented with a weaker control.

## Residual risks

- Console approval is not strong authentication.
- The endpoint checker is not a general SSRF defense.
- Audit redaction is name-based; operators must still avoid putting secrets in free text.
- The project is a local beta; production deployment requires authenticated approvals,
  network egress policy, and a security review.
