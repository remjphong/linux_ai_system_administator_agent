# Tool Catalog

All tools should follow the shared Tool interface and return ToolResult.

## Planned observation tools

- get_system_overview
- get_cpu_metrics
- get_memory_metrics
- get_disk_usage
- list_processes
- get_failed_services
- get_service_logs
- get_recent_errors
- list_large_files
- check_tcp_connectivity

## Planned controlled actions

- restart_service
- clean_package_cache
- vacuum_journal

## Requirements

- Use fixed executables and argument lists for system commands.
- Validate inputs before execution.
- Apply policy checks before changing system state.
- Use timeouts and handle command failures.
- Verify outcomes after actions.
- Record audit events.
