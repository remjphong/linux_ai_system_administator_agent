# AGENTIC-UX-01 bounded baseline

Captured in the isolated sandbox before implementation, at base commit
`27492215c9d8dbf7d2dc87d30e84019b9f7a6d47`.

| Check | Result |
| --- | --- |
| `python -m pytest -q` | 294 passed, 1 failed. `test_network_state_reads_interfaces` fails because the sandbox denies reading network interfaces (`PermissionError`). |
| `python -m ruff check .` | PASS |
| `python -m compileall -q src tests` | PASS |
| Original developer host runtime | NOT_VERIFIED |

The failed baseline test directly inspects sandbox host network state; it is
outside the terminal UX change. No host diagnostic was used to create this
baseline.
