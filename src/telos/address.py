"""Destination address classification for SSRF enforcement."""
from __future__ import annotations

import ipaddress
from .errors import EndpointPolicyError

_METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("100.100.100.200"),
}

# Transition/relay mechanisms are neither ordinary private model-server
# destinations nor ordinary public endpoints. Python's ipaddress predicates
# are not sufficient here: 192.88.99.0/24 may look global, while Teredo/6to4
# may look private. Deny them explicitly so permissive profiles cannot admit
# tunnel/relay semantics as a direct endpoint.
_TRANSITION_NETWORKS = (
    ipaddress.ip_network("192.88.99.0/24"),  # 6to4 relay anycast
    ipaddress.ip_network("2001::/32"),       # Teredo
    ipaddress.ip_network("2002::/16"),       # 6to4
)


def parse_ip(address: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError as exc:
        raise EndpointPolicyError("invalid_ip", f"invalid IP address: {address!r}") from exc
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def is_metadata_address(address: str) -> bool:
    return parse_ip(address) in _METADATA_IPS


def is_public_address(address: str) -> bool:
    ip = parse_ip(address)
    return bool(ip.is_global) and not is_metadata_address(address)


def assert_address_allowed(address: str, *, allow_public: bool, allow_private: bool, allow_loopback: bool) -> None:
    ip = parse_ip(address)
    if is_metadata_address(address):
        raise EndpointPolicyError("metadata_denied", f"metadata endpoint denied: {address}")
    if any(ip in network for network in _TRANSITION_NETWORKS):
        raise EndpointPolicyError("transition_network_denied", f"transition/relay network denied: {address}")
    if ip.is_unspecified:
        raise EndpointPolicyError("unspecified_denied", f"unspecified address denied: {address}")
    if ip.is_multicast:
        raise EndpointPolicyError("multicast_denied", f"multicast address denied: {address}")
    if ip.is_loopback:
        if not allow_loopback:
            raise EndpointPolicyError("loopback_denied", f"loopback address denied: {address}")
        return
    if ip.is_link_local:
        raise EndpointPolicyError("link_local_denied", f"link-local address denied: {address}")
    if ip.is_private:
        if not allow_private:
            raise EndpointPolicyError("private_denied", f"private address denied: {address}")
        return
    if not ip.is_global:
        raise EndpointPolicyError("special_use_denied", f"special-use address denied: {address}")
    if not allow_public:
        raise EndpointPolicyError("public_denied", f"public address denied: {address}")
