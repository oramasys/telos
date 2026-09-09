"""Controlled DNS resolution producing Telos-owned identity evidence."""
from __future__ import annotations

import socket
from secrets import token_urlsafe
from collections.abc import Callable
from .address import assert_address_allowed, is_public_address, parse_ip
from .contracts import EndpointIdentity, EndpointRef
from .errors import EndpointPolicyError

Resolver = Callable[[str, int], list[tuple]]


def _stdlib_resolver(host: str, port: int) -> list[tuple]:
    return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)


def resolve_endpoint(
    endpoint: EndpointRef,
    *,
    allow_public: bool,
    allow_private: bool,
    allow_loopback: bool,
    resolver: Resolver = _stdlib_resolver,
) -> EndpointIdentity:
    try:
        literal = parse_ip(endpoint.host)
        addresses = (str(literal),)
    except EndpointPolicyError:
        try:
            infos = resolver(endpoint.host, endpoint.port)
        except OSError as exc:
            raise EndpointPolicyError("dns_resolution_failed", f"DNS resolution failed for {endpoint.host!r}") from exc
        addresses = tuple(dict.fromkeys(info[4][0] for info in infos if info and len(info) >= 5 and info[4]))
        if not addresses:
            raise EndpointPolicyError("dns_resolution_failed", f"DNS resolution returned no addresses for {endpoint.host!r}")
    public_flags = []
    for address in addresses:
        assert_address_allowed(
            address,
            allow_public=allow_public,
            allow_private=allow_private,
            allow_loopback=allow_loopback,
        )
        public_flags.append(is_public_address(address))
    if len(set(public_flags)) != 1:
        raise EndpointPolicyError("mixed_address_classification", "DNS answers span incompatible trust classes")
    return EndpointIdentity(
        endpoint=endpoint,
        resolved_addresses=addresses,
        is_public=public_flags[0],
        resolution_ref=token_urlsafe(18),
    )
