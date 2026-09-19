# core/network_access.py

from functools import wraps
from ipaddress import ip_address, ip_network, IPv4Network, IPv6Network
from typing import Callable, Iterable, TypeVar

from flask import request, abort

from ota_http_server.logger import get_app_logger

logger = get_app_logger(__name__)

F = TypeVar("F", bound=Callable[..., object])

Network = IPv4Network | IPv6Network

DEFAULT_ADMIN_NETWORKS: list[str] = ["127.0.0.0/8", "::1/128"]


def parse_networks(networks: Iterable[str]) -> list[Network]:
    """Parse an iterable of CIDR/IP strings into ip_network objects.

    Invalid entries are logged and skipped rather than raising, so a single
    typo in configuration does not prevent the server from starting.
    """
    parsed: list[Network] = []
    for entry in networks:
        try:
            parsed.append(ip_network(entry, strict=False))
        except ValueError:
            logger.warning("Ignoring invalid network/address in configuration: %r", entry)
    return parsed


def require_networks(networks: Iterable[str | Network]) -> Callable[[F], F]:
    """Route decorator restricting access to a set of IP networks/addresses.

    Args:
        networks: An iterable of ip_network/ip_address objects, or their
            string representations (e.g. "192.168.20.0/24", "127.0.0.1").

    The client's address is taken from ``request.remote_addr``. Requests
    from clients outside all given networks are rejected with HTTP 403.
    """
    allowed_networks = parse_networks(str(net) for net in networks)

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args, **kwargs):
            remote_addr = request.remote_addr
            if remote_addr is None:
                logger.warning("Rejected request to %s: could not determine client address", request.path)
                abort(403, "Access denied: unable to determine client address")

            try:
                client_ip = ip_address(remote_addr)
            except ValueError:
                logger.warning("Rejected request to %s: invalid client address %r", request.path, remote_addr)
                abort(403, "Access denied: invalid client address")

            if not any(client_ip in net for net in allowed_networks):
                logger.warning("Rejected request to %s from disallowed network: %s", request.path, remote_addr)
                abort(403, "Access denied: client network not permitted")

            return func(*args, **kwargs)
        return wrapper  # type: ignore[return-value]

    return decorator
