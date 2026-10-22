
import argparse
import platform

import psutil

from linux_admin.tools.registry import ToolRegistry


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Linux AI Agent System Administrator"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check basic system metrics and registered tools",
    )
    args = parser.parse_args()

    registry = ToolRegistry()

    print("Linux Admin Agent")
    print(f"Operating system: {platform.system()}")
    print(f"Python: {platform.python_version()}")
    print(f"CPU usage: {psutil.cpu_percent(interval=0.2)}%")
    print(f"Memory usage: {psutil.virtual_memory().percent}%")
    print(f"Registered tools: {registry.list_tools()}")

    if args.check:
        print("Basic system check completed.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

