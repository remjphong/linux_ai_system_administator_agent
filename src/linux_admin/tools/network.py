"""Read-only network diagnostics with explicit timeout and input limits."""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from typing import Any
from urllib.parse import urlsplit

import psutil

from linux_admin.contracts import ToolResult, ToolSpec

_DEFAULT_TIMEOUT = 2.5
_MAX_TIMEOUT = 5.0
_MAX_URL_LENGTH = 2048
_BLOCKED_HOSTS = {"metadata.google.internal", "metadata.azure.internal"}
_BLOCKED_IPS = {"169.254.169.254", "169.254.170.2", "100.100.100.200"}


def validate_host_port(host: Any, port: Any) -> str | None:
    if not isinstance(host, str) or not host.strip() or len(host) > 253:
        return "host must be a hostname or IP address of at most 253 characters."
    if any(ch.isspace() for ch in host) or "/" in host or "\\" in host or "@" in host:
        return "host contains invalid characters."
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        return "port must be an integer between 1 and 65535."
    normalized = host.rstrip(".").casefold()
    if normalized in _BLOCKED_HOSTS or normalized in _BLOCKED_IPS:
        return "Requests to known cloud metadata endpoints are blocked."
    try:
        address = ipaddress.ip_address(normalized.strip("[]"))
    except ValueError:
        return None
    if address in {ipaddress.ip_address(value) for value in _BLOCKED_IPS}:
        return "Requests to known cloud metadata endpoints are blocked."
    return None


def _validate_timeout(timeout: Any) -> str | None:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        return "timeout_seconds must be a number."
    if not 0.1 <= float(timeout) <= _MAX_TIMEOUT:
        return f"timeout_seconds must be between 0.1 and {_MAX_TIMEOUT:g}."
    return None


def perform_http_check(url: str, timeout_seconds: float = _DEFAULT_TIMEOUT) -> ToolResult:
    """Perform one HTTP(S) request without following redirects or reading large bodies."""
    tool_name = "check_http_endpoint"
    if not isinstance(url, str) or not url.strip() or len(url) > _MAX_URL_LENGTH:
        return ToolResult(tool_name=tool_name, status="invalid_input", error="url must be a non-empty URL no longer than 2048 characters.")
    timeout_error = _validate_timeout(timeout_seconds)
    if timeout_error:
        return ToolResult(tool_name=tool_name, status="invalid_input", error=timeout_error)
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        host = parsed.hostname
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError:
        return ToolResult(tool_name=tool_name, status="invalid_input", error="URL is malformed.")
    if scheme not in {"http", "https"} or not host or parsed.username is not None or parsed.password is not None:
        return ToolResult(tool_name=tool_name, status="invalid_input", error="URL must use HTTP/HTTPS and must not include credentials.")
    host_error = validate_host_port(host, port)
    if host_error:
        return ToolResult(tool_name=tool_name, status="invalid_input", error=host_error)
    if parsed.fragment:
        return ToolResult(tool_name=tool_name, status="invalid_input", error="URL fragments are not sent to an HTTP endpoint and are not accepted.")

    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    connection: http.client.HTTPConnection | http.client.HTTPSConnection | None = None
    try:
        if scheme == "https":
            context = ssl.create_default_context()
            connection = http.client.HTTPSConnection(host, port, timeout=float(timeout_seconds), context=context)
        else:
            connection = http.client.HTTPConnection(host, port, timeout=float(timeout_seconds))
        connection.request("GET", path, headers={"User-Agent": "linux-admin-agent/0.1", "Connection": "close"})
        response = connection.getresponse()
        status = int(response.status)
        # Drain only a small amount so the server connection can be closed without
        # loading arbitrary response bodies into agent memory.
        response.read(4096)
        data = {
            "url": url,
            "host": host,
            "port": port,
            "reachable": True,
            "healthy": 200 <= status < 400,
            "status_code": status,
            "reason": str(response.reason)[:120],
            "redirect_followed": False,
        }
        return ToolResult(
            tool_name=tool_name,
            status="success",
            data=data,
            evidence=[f"The endpoint returned HTTP status {status}; redirects were not followed."],
        )
    except TimeoutError:
        return ToolResult(tool_name=tool_name, status="timeout", error="HTTP endpoint check timed out.", data={"url": url, "reachable": False})
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        return ToolResult(tool_name=tool_name, status="success", data={"url": url, "host": host, "port": port, "reachable": False, "healthy": False, "status_code": None, "error_type": type(exc).__name__}, evidence=[f"HTTP connection failed with {type(exc).__name__}."])
    finally:
        if connection is not None:
            connection.close()


class NetworkStateTool:
    spec = ToolSpec(
        name="get_network_state",
        description="Read network interface status and assigned IP addresses.",
    )

    def execute(self, **kwargs: Any) -> ToolResult:
        del kwargs
        try:
            addresses = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
        except (OSError, psutil.Error) as exc:
            return ToolResult(tool_name=self.spec.name, status="failed", error=f"Could not read network interfaces ({type(exc).__name__}).")

        interfaces: list[dict[str, Any]] = []
        for name in sorted(set(addresses) | set(stats)):
            stat = stats.get(name)
            ip_addresses = []
            for address in addresses.get(name, []):
                family = getattr(address.family, "name", str(address.family))
                if family in {"AF_INET", "AF_INET6"}:
                    ip_addresses.append({"family": family, "address": address.address.split("%", 1)[0]})
            interfaces.append({
                "name": name,
                "is_up": bool(stat.isup) if stat else None,
                "speed_mbps": int(stat.speed) if stat and stat.speed else None,
                "mtu": int(stat.mtu) if stat else None,
                "addresses": ip_addresses,
            })
        return ToolResult(tool_name=self.spec.name, status="success", data={"interfaces": interfaces, "count": len(interfaces)}, evidence=["Read network interface data via psutil; no network settings were changed."])


class TcpConnectivityTool:
    spec = ToolSpec(
        name="check_tcp_connectivity",
        description="Attempt a bounded TCP connection to a specific host and port.",
        parameters={
            "type": "object",
            "properties": {
                "host": {"type": "string", "minLength": 1, "maxLength": 253},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "timeout_seconds": {"type": "number", "minimum": 0.1, "maximum": _MAX_TIMEOUT},
            },
            "required": ["host", "port"],
            "additionalProperties": False,
        },
    )

    def execute(self, host: str, port: int, timeout_seconds: float = _DEFAULT_TIMEOUT, **kwargs: Any) -> ToolResult:
        del kwargs
        host_error = validate_host_port(host, port)
        if host_error:
            return ToolResult(tool_name=self.spec.name, status="invalid_input", error=host_error)
        timeout_error = _validate_timeout(timeout_seconds)
        if timeout_error:
            return ToolResult(tool_name=self.spec.name, status="invalid_input", error=timeout_error)
        try:
            with socket.create_connection((host, port), timeout=float(timeout_seconds)):
                pass
        except TimeoutError:
            return ToolResult(tool_name=self.spec.name, status="timeout", data={"host": host, "port": port, "reachable": False}, error="TCP connection timed out.")
        except OSError as exc:
            return ToolResult(tool_name=self.spec.name, status="success", data={"host": host, "port": port, "reachable": False, "error_type": type(exc).__name__}, evidence=[f"TCP connection failed with {type(exc).__name__}."])
        return ToolResult(tool_name=self.spec.name, status="success", data={"host": host, "port": port, "reachable": True}, evidence=["TCP handshake completed successfully."])


class HttpEndpointTool:
    spec = ToolSpec(
        name="check_http_endpoint",
        description="Check an HTTP(S) endpoint without following redirects.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "minLength": 8, "maxLength": _MAX_URL_LENGTH},
                "timeout_seconds": {"type": "number", "minimum": 0.1, "maximum": _MAX_TIMEOUT},
            },
            "required": ["url"],
            "additionalProperties": False,
        },
    )

    def execute(self, url: str, timeout_seconds: float = _DEFAULT_TIMEOUT, **kwargs: Any) -> ToolResult:
        del kwargs
        result = perform_http_check(url, timeout_seconds)
        if result.tool_name != self.spec.name:
            return ToolResult(tool_name=self.spec.name, status="failed", error="HTTP probe returned an unexpected tool name.")
        return result


class ListeningPortTool:
    """Inspect local listening sockets for one TCP/UDP port."""

    spec = ToolSpec(
        name="inspect_listening_port",
        description=(
            "Inspect local listening sockets on a specific port and report "
            "visible process ownership when available."
        ),
        parameters={
            "type": "object",
            "properties": {
                "port": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 65535,
                },
            },
            "required": ["port"],
            "additionalProperties": False,
        },
    )

    def execute(self, port: int, **kwargs: Any) -> ToolResult:
        del kwargs
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            return ToolResult(
                tool_name=self.spec.name,
                status="invalid_input",
                error="port must be an integer between 1 and 65535.",
            )

        try:
            connections = psutil.net_connections(kind="inet")
        except (OSError, psutil.Error) as exc:
            return ToolResult(
                tool_name=self.spec.name,
                status="failed",
                error=(
                    "Could not inspect local listening sockets "
                    f"({type(exc).__name__})."
                ),
                data={"port": port, "supported": False},
            )

        listeners: list[dict[str, Any]] = []
        for connection in connections:
            if connection.status != psutil.CONN_LISTEN:
                continue

            local_address = connection.laddr
            if not local_address:
                continue

            local_port = getattr(local_address, "port", None)
            if (
                local_port is None
                and isinstance(local_address, tuple)
                and len(local_address) > 1
            ):
                local_port = local_address[1]
            if local_port != port:
                continue

            address = getattr(local_address, "ip", None)
            if address is None:
                address = (
                    local_address[0]
                    if isinstance(local_address, tuple) and local_address
                    else str(local_address)
                )

            pid = connection.pid
            process_name = None
            if isinstance(pid, int) and pid > 0:
                try:
                    process_name = psutil.Process(pid).name()
                except (OSError, psutil.Error):
                    # Socket visibility does not guarantee process-name access.
                    pass

            listeners.append(
                {
                    "local_address": str(address),
                    "port": port,
                    "pid": pid,
                    "process_name": process_name,
                }
            )

        return ToolResult(
            tool_name=self.spec.name,
            status="success",
            data={
                "port": port,
                "listeners": listeners,
                "count": len(listeners),
                "supported": True,
            },
            evidence=[
                (
                    f"Inspected local listening sockets for port {port}; "
                    "no system settings were changed."
                )
            ],
        )

class ListListeningPortsTool:
    """List every TCP socket in the LISTEN state on this host."""

    spec = ToolSpec(
        name="list_listening_ports",
        description=(
            "List all TCP sockets in the LISTEN state with local address, port, "
            "and (when visible) owning PID. Complements inspect_listening_port "
            "by reporting every listener in one call."
        ),
    )

    def execute(self, **kwargs: Any) -> ToolResult:
        del kwargs
        try:
            connections = psutil.net_connections(kind="inet")
        except (OSError, psutil.Error) as exc:
            return ToolResult(
                tool_name=self.spec.name,
                status="failed",
                error=f"Could not enumerate sockets ({type(exc).__name__}).",
            )

        sockets: list[dict[str, Any]] = []
        for connection in connections:
            if connection.status != psutil.CONN_LISTEN:
                continue
            local_address = connection.laddr
            if not local_address:
                continue
            ip = getattr(local_address, "ip", None)
            port = getattr(local_address, "port", None)
            if port is None and isinstance(local_address, tuple) and len(local_address) > 1:
                ip, port = local_address[0], local_address[1]
            if not isinstance(port, int) or isinstance(port, bool):
                continue
            sockets.append(
                {
                    "protocol": "tcp",
                    "local_address": str(ip or ""),
                    "local_port": int(port),
                    "pid": connection.pid,
                }
            )

        sockets.sort(key=lambda item: (item["local_port"], item["local_address"]))
        return ToolResult(
            tool_name=self.spec.name,
            status="success",
            data={"count": len(sockets), "sockets": sockets},
            evidence=[
                f"Found {len(sockets)} TCP listening socket(s); "
                "no network state was changed."
            ],
        )


def build_tools() -> list[object]:
    return [
        NetworkStateTool(),
        TcpConnectivityTool(),
        HttpEndpointTool(),
        ListeningPortTool(),
        ListListeningPortsTool(),
    ]

