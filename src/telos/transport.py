"""Pinned HTTP(S) transport. Every hop is normalized, resolved, checked, and pinned by Telos."""
from __future__ import annotations

import http.client
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit
from .contracts import AuthorizedEndpoint, EndpointPurpose, EndpointUseRequest
from .errors import EndpointPolicyError
from .identity import endpoint_from_url
from .resolver import Resolver, resolve_endpoint
from .authorizer import EndpointAuthorizer

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

class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, pinned_ip: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = pinned_ip
    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)

class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, pinned_ip: str, timeout: float, context: ssl.SSLContext | None = None) -> None:
        super().__init__(host, port, timeout=timeout, context=context or ssl.create_default_context())
        self._pinned_ip = pinned_ip
    def connect(self) -> None:
        raw = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def _authorize_identity(authorizer: EndpointAuthorizer, identity, *, actor_id: str, workflow_id: str, purpose: EndpointPurpose, run_id: str) -> AuthorizedEndpoint:
    decision = authorizer.authorize(EndpointUseRequest(actor_id, workflow_id, purpose, identity, run_id))
    if not decision.allowed:
        raise EndpointPolicyError("purpose_denied", f"endpoint use denied: {decision.reason_code}")
    return AuthorizedEndpoint(identity=identity, purpose_decision=decision)


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
    if identity.is_public and transport_policy.require_https_for_public and endpoint.scheme != "https":
        raise EndpointPolicyError("https_required", "public endpoints require HTTPS")
    return _authorize_identity(authorizer, identity, actor_id=actor_id, workflow_id=workflow_id, purpose=purpose, run_id=run_id)


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
    _hop: int = 0,
) -> TelosResponse:
    if _hop > transport_policy.max_redirects:
        raise EndpointPolicyError("redirect_limit", f"redirect limit {transport_policy.max_redirects} exceeded")
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
    request_headers.pop("Proxy-Authorization", None)
    request_headers.setdefault("Host", endpoint.host if endpoint.port in {80, 443} else f"{endpoint.host}:{endpoint.port}")
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
        location = dict(response_headers).get("Location") or dict(response_headers).get("location")
        if not location:
            raise EndpointPolicyError("redirect_denied", "redirect response missing Location")
        next_url = urljoin(raw_url, location)
        next_headers = dict(request_headers)
        if urlsplit(next_url).netloc != urlsplit(raw_url).netloc:
            next_headers.pop("Authorization", None)
        return request(
            method,
            next_url,
            authorizer=authorizer,
            transport_policy=transport_policy,
            actor_id=actor_id,
            workflow_id=workflow_id,
            purpose=purpose,
            run_id=run_id,
            headers=next_headers,
            body=body,
            timeout=timeout,
            resolver=resolver,
            _hop=_hop + 1,
        )
    return TelosResponse(response.status, response_headers, response_body, raw_url)
