"""Pinned HTTP(S) transport.

Every hop is normalized, resolved, checked, semantically authorized, and pinned
by Telos. Network PLACE (the vetted IP) is kept separate from endpoint NAME
(the normalized hostname used for Host and TLS SNI).
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from collections.abc import Callable
from urllib.parse import urljoin, urlsplit

from .authorizer import EndpointAuthorizer
from .contracts import AuthorizedEndpoint, EndpointPurpose, EndpointUseRequest
from .errors import EndpointPolicyError
from .identity import endpoint_from_url
from .resolver import Resolver, resolve_endpoint


@dataclass(frozen=True, slots=True)
class TransportPolicy:
    allow_public: bool = False
    allow_private: bool = False
    allow_loopback: bool = True
    require_https_for_public: bool = True
    max_redirects: int = 3


@dataclass(frozen=True, slots=True)
class TelosResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    final_url: str


CancelCheck = Callable[[], bool]


def _raise_if_cancelled(cancel_check: CancelCheck | None) -> None:
    if cancel_check is not None and cancel_check():
        raise EndpointPolicyError("cancelled", "endpoint request was cancelled")


def _verify_peer(sock: object, pinned_ip: str) -> None:
    """Verify the connected peer is exactly the previously vetted pin."""
    try:
        peer = sock.getpeername()[0]  # type: ignore[attr-defined]
        actual = ipaddress.ip_address(peer)
        expected = ipaddress.ip_address(pinned_ip)
    except (AttributeError, IndexError, TypeError, ValueError) as exc:
        raise EndpointPolicyError(
            "peer_pin_unverifiable", "connected peer identity could not be verified"
        ) from exc
    if actual != expected:
        raise EndpointPolicyError(
            "peer_pin_mismatch",
            f"connected peer {actual} does not match vetted pin {expected}",
        )


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, pinned_ip: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        try:
            _verify_peer(sock, self._pinned_ip)
        except Exception:
            close = getattr(sock, "close", None)
            if callable(close):
                close()
            raise
        self.sock = sock


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        host: str,
        port: int,
        pinned_ip: str,
        timeout: float,
        context: ssl.SSLContext | None = None,
    ) -> None:
        super().__init__(
            host,
            port,
            timeout=timeout,
            context=context or ssl.create_default_context(),
        )
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        raw = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        try:
            _verify_peer(raw, self._pinned_ip)
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            close = getattr(raw, "close", None)
            if callable(close):
                close()
            raise


def _authorize_identity(
    authorizer: EndpointAuthorizer,
    identity,
    *,
    actor_id: str,
    workflow_id: str,
    purpose: EndpointPurpose,
    run_id: str,
) -> AuthorizedEndpoint:
    decision = authorizer.authorize(
        EndpointUseRequest(actor_id, workflow_id, purpose, identity, run_id)
    )
    if not decision.allowed:
        raise EndpointPolicyError(
            "purpose_denied", f"endpoint use denied: {decision.reason_code}"
        )
    return AuthorizedEndpoint(identity, decision)


def authorize_url(
    raw_url: str,
    *,
    authorizer: EndpointAuthorizer,
    transport_policy: TransportPolicy,
    actor_id: str,
    workflow_id: str,
    purpose: EndpointPurpose,
    run_id: str,
    resolver: Resolver,
) -> AuthorizedEndpoint:
    endpoint = endpoint_from_url(raw_url)
    identity = resolve_endpoint(
        endpoint,
        allow_public=transport_policy.allow_public,
        allow_private=transport_policy.allow_private,
        allow_loopback=transport_policy.allow_loopback,
        resolver=resolver,
    )
    if (
        identity.is_public
        and transport_policy.require_https_for_public
        and endpoint.scheme != "https"
    ):
        raise EndpointPolicyError("https_required", "public endpoints require HTTPS")
    return _authorize_identity(
        authorizer,
        identity,
        actor_id=actor_id,
        workflow_id=workflow_id,
        purpose=purpose,
        run_id=run_id,
    )


def _drop_headers_case_insensitive(headers: dict[str, str], names: set[str]) -> None:
    wanted = {name.lower() for name in names}
    for key in list(headers):
        if key.lower() in wanted:
            headers.pop(key, None)


def _authority(endpoint) -> str:
    default_port = 443 if endpoint.scheme == "https" else 80
    host = f"[{endpoint.host}]" if ":" in endpoint.host else endpoint.host
    return host if endpoint.port == default_port else f"{host}:{endpoint.port}"


def _origin(raw_url: str) -> tuple[str, str, int]:
    endpoint = endpoint_from_url(raw_url)
    return endpoint.scheme, endpoint.host, endpoint.port


def request(
    method: str,
    raw_url: str,
    *,
    authorizer: EndpointAuthorizer,
    transport_policy: TransportPolicy,
    actor_id: str,
    workflow_id: str,
    purpose: EndpointPurpose,
    run_id: str,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = 10.0,
    resolver: Resolver,
    cancel_check: CancelCheck | None = None,
    _hop: int = 0,
) -> TelosResponse:
    _raise_if_cancelled(cancel_check)
    if _hop > transport_policy.max_redirects:
        raise EndpointPolicyError(
            "redirect_limit",
            f"redirect limit {transport_policy.max_redirects} exceeded",
        )

    authorized = authorize_url(
        raw_url,
        authorizer=authorizer,
        transport_policy=transport_policy,
        actor_id=actor_id,
        workflow_id=workflow_id,
        purpose=purpose,
        run_id=run_id,
        resolver=resolver,
    )
    endpoint = authorized.identity.endpoint
    pinned_ip = authorized.identity.resolved_addresses[0]
    parsed = urlsplit(raw_url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    request_headers = dict(headers or {})
    _drop_headers_case_insensitive(request_headers, {"Proxy-Authorization", "Host"})
    request_headers["Host"] = _authority(endpoint)

    _raise_if_cancelled(cancel_check)
    conn_cls = _PinnedHTTPSConnection if endpoint.scheme == "https" else _PinnedHTTPConnection
    conn = conn_cls(endpoint.host, endpoint.port, pinned_ip, timeout)
    try:
        conn.request(method.upper(), path, body=body, headers=request_headers)
        response = conn.getresponse()
        response_body = response.read()
        response_headers = tuple(response.getheaders())
    finally:
        conn.close()

    if 300 <= response.status < 400:
        location = dict(response_headers).get("Location") or dict(response_headers).get(
            "location"
        )
        if not location:
            raise EndpointPolicyError(
                "redirect_denied", "redirect response missing Location"
            )
        next_url = urljoin(raw_url, location)
        next_headers = dict(request_headers)
        next_method = method
        next_body = body

        if _origin(next_url) != _origin(raw_url):
            _drop_headers_case_insensitive(
                next_headers, {"Authorization", "Cookie", "Proxy-Authorization"}
            )

        if response.status in {301, 302, 303}:
            next_method = "GET"
            next_body = None
            _drop_headers_case_insensitive(
                next_headers, {"Content-Length", "Content-Type", "Transfer-Encoding"}
            )

        _drop_headers_case_insensitive(next_headers, {"Host"})
        return request(
            next_method,
            next_url,
            authorizer=authorizer,
            transport_policy=transport_policy,
            actor_id=actor_id,
            workflow_id=workflow_id,
            purpose=purpose,
            run_id=run_id,
            headers=next_headers,
            body=next_body,
            timeout=timeout,
            resolver=resolver,
            cancel_check=cancel_check,
            _hop=_hop + 1,
        )

    return TelosResponse(response.status, response_headers, response_body, raw_url)
