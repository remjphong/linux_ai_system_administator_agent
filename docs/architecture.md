# Architecture

## Initial design

The system uses a single-agent architecture with a deterministic
control plane.

1. CLI receives a user request.
2. Agent orchestrates observation and diagnosis.
3. Tools collect system data or propose controlled operations.
4. Policy evaluates whether an operation is permitted.
5. Executor performs approved operations.
6. Verification checks the result.
7. Audit records relevant decisions and outcomes.

## Safety boundary

The LLM must not directly execute arbitrary shell commands.
All system-changing operations must pass through policy enforcement
and a controlled executor.

## Initial scenarios

- A service is failing.
- Disk space is running low.
- An application endpoint is unreachable.

## Current implementation status

The initial skeleton implements shared tool contracts, a tool registry,
a basic system check, and smoke tests.

Policy enforcement, execution, verification, audit persistence, and
LLM integration are future implementation tasks.
