"""URL parsing and canonical endpoint identity."""
from __future__ import annotations

from urllib.parse import urlsplit
from .contracts import EndpointRef
from .errors import EndpointPolicyError


def endpoint_from_url(raw_url: str) -> EndpointRef:
    try:
        parsed = urlsplit(raw_url)
    except ValueError as exc:
        raise EndpointPolicyError("malformed_url", "malformed endpoint URL") from exc
    if parsed.scheme.lower() not in {"http", "https"}:
        raise EndpointPolicyError("scheme_disallowed", f"scheme not allowed: {parsed.scheme!r}")
    if parsed.username is not None or parsed.password is not None:
        raise EndpointPolicyError("userinfo_present", "userinfo is not allowed in endpoint URLs")
    if not parsed.hostname:
        raise EndpointPolicyError("no_hostname", "URL has no hostname")
    try:
        port = parsed.port
    except ValueError as exc:
        raise EndpointPolicyError("invalid_port", "invalid endpoint port") from exc
    if port is None:
        port = 443 if parsed.scheme.lower() == "https" else 80
    try:
        return EndpointRef(parsed.scheme, parsed.hostname, port)
    except ValueError as exc:
        raise EndpointPolicyError("invalid_endpoint", str(exc)) from exc
