"""Built-in Linux administration tools and their Registry wiring.

Importing this package has no operating-system side effects. The factory only
creates tool objects; it does not invoke system commands or perform actions.
"""

from __future__ import annotations

from linux_admin.config import AppConfig
from linux_admin.registry import ToolRegistry


def register_builtin_tools(registry: ToolRegistry, config: AppConfig) -> ToolRegistry:
    """Register the real built-in tools and return the same Registry instance."""
    # Local imports keep tool modules independently importable and avoid circular
    # import problems between the package, Registry, and service/log adapters.
    from linux_admin.tools.logs import build_tools as build_log_tools
    from linux_admin.tools.network import build_tools as build_network_tools
    from linux_admin.tools.security import build_tools as build_security_tools
    from linux_admin.tools.services import build_tools as build_service_tools
    from linux_admin.tools.system import build_tools as build_system_tools
    from linux_admin.tools.tavily_search import build_tools as build_tavily_tools
    from linux_admin.verification import build_tools as build_verification_tools

    tool_groups = (
        build_system_tools(),
        build_log_tools(),
        build_network_tools(),
        build_service_tools(config),
        build_security_tools(config),
        build_verification_tools(config),
        build_tavily_tools(config.tavily),
    )
    for group in tool_groups:
        for tool in group:
            registry.register(tool)
    return registry


__all__ = ["register_builtin_tools"]
