"""Language-neutral JSONL stdio bridge for runtimes that cannot import Python Telos.

The bridge performs the network request inside Telos so consumers never receive
an IP and then re-resolve/reconnect outside the authority boundary.
"""
from __future__ import annotations

import base64
import http.client
import json
import re
import sys
from .authorizer import EndpointAuthorizer
from .contracts import EndpointPurpose, EndpointUseDecision, EndpointUseRequest
from .identity import endpoint_from_url
from .transport import TransportPolicy, request
from .errors import EndpointPolicyError, TelosError
from .address import parse_ip

# Same pattern as transport._CREDENTIAL_HEADER_RE -- kept local rather than
# imported to avoid a bridge -> transport-internals coupling for a one-line
# pattern; both were verified against the same 9 real header-name cases.
_CREDENTIAL_HEADER_RE = re.compile(
    r"^(authorization|cookie|proxy-authorization)$"
    r"|.*-(api-key|api-token|auth-token|access-token|secret|token)$",
    re.IGNORECASE,
)


class _HostAllowlistAuthorizer:
    """Wraps an EndpointAuthorizer so allowed_hosts is enforced on every
    authorize() call -- including redirect hops, which transport.request()
    re-authorizes through this same authorizer object on each hop. The bare
    allowed_hosts check in handle() below only ever covered the first
    request; a redirect to a different host that happened to also be a
    listed allowed_endpoint bypassed it entirely."""

    def __init__(self, inner: EndpointAuthorizer, allowed_hosts: set[str]) -> None:
        self._inner = inner
        self._allowed_hosts = allowed_hosts

    def authorize(self, req: EndpointUseRequest) -> EndpointUseDecision:
        host = req.endpoint.endpoint.host
        # Direct-loopback hosts are exempt, matching handle()'s own original
        # semantics below -- allowed_hosts only ever gated remote hosts.
        if not _direct_loopback_host(host) and host not in self._allowed_hosts:
            return EndpointUseDecision(
                allowed=False,
                reason_code="host_not_allowlisted",
                policy_version=self._inner._policy.version,
                decision_ref="host-gate",
                endpoint=req.endpoint,
            )
        return self._inner.authorize(req)

    @property
    def records(self):
        return self._inner.records

    @property
    def _policy(self):
        return self._inner._policy


def _purpose(value: str) -> EndpointPurpose:
    try:
        return EndpointPurpose(value)
    except ValueError as exc:
        raise ValueError(f"unknown endpoint purpose: {value!r}") from exc


def _direct_loopback_host(host: str) -> bool:
    normalized = host.lower().rstrip(".")
    if normalized == "localhost" or normalized.endswith(".localhost"):
        return True
    try:
        return bool(parse_ip(normalized).is_loopback)
    except EndpointPolicyError:
        return False


def handle(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError(f"payload must be a JSON object, got {type(payload).__name__}")
    if "url" not in payload:
        raise ValueError("payload missing required field: url")
    transport_raw = payload.get("transport")
    if transport_raw is not None and not isinstance(transport_raw, dict):
        raise ValueError(f"payload.transport must be an object, got {type(transport_raw).__name__}")
    headers_raw = payload.get("headers")
    if headers_raw is not None and not isinstance(headers_raw, dict):
        raise ValueError(f"payload.headers must be an object, got {type(headers_raw).__name__}")
    method = str(payload.get("method", "GET"))
    url = str(payload["url"])
    purpose = _purpose(str(payload.get("purpose", EndpointPurpose.MODEL_EGRESS.value)))
    endpoint = endpoint_from_url(url)
    allowed = payload.get("allowed_endpoints") or []
    allowed_keys = {
        endpoint_from_url(str(item)).key
        for item in allowed
    }
    allow_remote = bool(payload.get("allow_remote", False))
    allowed_hosts = {
        str(host).lower().rstrip(".")
        for host in (payload.get("allowed_hosts") or [])
    }
    if not _direct_loopback_host(endpoint.host):
        if not allow_remote:
            raise EndpointPolicyError(
                "remote_denied",
                "remote endpoint requires explicit opt-in",
            )
        if endpoint.host not in allowed_hosts:
            raise EndpointPolicyError(
                "host_not_allowlisted",
                f"remote host not allowlisted: {endpoint.host}",
            )
    raw_headers = {str(k): str(v) for k, v in (payload.get("headers") or {}).items()}
    if endpoint.scheme != "https" and not _direct_loopback_host(endpoint.host):
        credential_headers = [k for k in raw_headers if _CREDENTIAL_HEADER_RE.match(k)]
        if credential_headers:
            raise EndpointPolicyError(
                "credentials_require_https",
                f"credential-bearing header(s) {credential_headers} require HTTPS, "
                f"got scheme {endpoint.scheme!r}",
            )
    base_authorizer = EndpointAuthorizer.from_exact_rules({purpose: allowed_keys})
    authorizer = _HostAllowlistAuthorizer(base_authorizer, allowed_hosts)
    body_raw = payload.get("body_base64")
    body = base64.b64decode(body_raw) if body_raw is not None else None
    profile = payload.get("transport") or {}
    policy = TransportPolicy(
        allow_public=bool(profile.get("allow_public", allow_remote)),
        allow_private=bool(profile.get("allow_private", allow_remote)),
        allow_loopback=bool(profile.get("allow_loopback", True)),
        require_https_for_public=bool(profile.get("require_https_for_public", True)),
        max_redirects=int(profile.get("max_redirects", 3)),
    )
    response = request(
        method,
        url,
        authorizer=authorizer,
        transport_policy=policy,
        actor_id=str(payload.get("actor_id", "provider-runtime")),
        workflow_id=str(payload.get("workflow_id", "provider-request")),
        purpose=purpose,
        run_id=str(payload.get("run_id", "unscoped")),
        headers=raw_headers,
        body=body,
        timeout=float(payload.get("timeout_seconds", 10.0)),
        resolver=__import__("telos.resolver", fromlist=["_stdlib_resolver"])._stdlib_resolver,
    )
    return {
        "ok": 200 <= response.status < 300,
        "status": response.status,
        "headers": list(response.headers),
        "body_base64": base64.b64encode(response.body).decode("ascii"),
        "final_url": response.final_url,
        "endpoint": list(endpoint.key),
    }


def main() -> int:
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            result = handle(json.loads(line))
            out = {"ok_bridge": True, "result": result}
        except (TelosError, ValueError, KeyError, TypeError) as exc:
            out = {
                "ok_bridge": False,
                "error": {
                    "code": getattr(exc, "code", "invalid_request"),
                    "message": str(exc),
                },
            }
        except (OSError, http.client.HTTPException) as exc:
            out = {
                "ok_bridge": False,
                "error": {
                    "code": "transport_error",
                    "message": str(exc),
                },
            }
        sys.stdout.write(json.dumps(out, separators=(",", ":")) + "\n")
        sys.stdout.flush()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
