"""Stable serving vocabulary, public error bodies and the local-only egress preset.

Telos owns no readiness or lifecycle state (see docs/BOUNDARIES.md). This module
only fixes the *words* a serving consumer uses when it is not ready, disabled or
asked for a route that is not exposed, so those words and their HTTP statuses
cannot drift between consumers. Nothing here enables anything.
"""
from __future__ import annotations

import uuid
from enum import StrEnum
from typing import Any

from .authorizer import EndpointAuthorizer


class ServingCode(StrEnum):
    """Stable public serving codes (contract section 3) with fixed HTTP statuses."""

    NOT_READY = "serving.not_ready"
    DISABLED = "serving.disabled"
    ROUTE_NOT_EXPOSED = "serving.route_not_exposed"

    @property
    def http_status(self) -> int:
        """HTTP status for this code: 503 for not-ready/disabled, 404 for not exposed."""
        return 404 if self is ServingCode.ROUTE_NOT_EXPOSED else 503


# Every public code the contract allows in an error body. Anything else is refused.
PUBLIC_ERROR_CODES: frozenset[str] = frozenset(
    {c.value for c in ServingCode}
    | {
        "deny.revocation_stale", "deny.unknown_key", "deny.malformed_grant",
        "deny.revoked_grant", "deny.missing_capability_record",
        "deny.unauthorized_caller", "deny.verifier_unavailable",
        "startup.serving_without_verifier", "startup.effects_without_permit_verifier",
        "startup.transport_without_policy", "startup.autonomy_without_activation",
        "startup.monitoring_as_permission", "startup.serving_implies_effects",
        "capability.unsigned_enablement",
    }
)


def new_correlation_id() -> str:
    """Return a fresh random UUID string for an error body."""
    return str(uuid.uuid4())


def build_error_body(code: str, correlation_id: str, *, receipt_ref: str | None = None) -> dict[str, Any]:
    """Build the contract error body ``{"error": {"code", "correlation_id"}}``.

    ``receipt_ref`` is the only optional field, and only when a durable record
    exists; it is placed beside ``error`` as the contract specifies. There is no
    way to pass any other field. Unknown codes and malformed ids raise ValueError.
    """
    code = str(code)
    if code not in PUBLIC_ERROR_CODES:
        raise ValueError("unknown public error code")
    try:
        uuid.UUID(correlation_id)
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValueError("correlation_id must be a UUID string") from exc
    body: dict[str, Any] = {"error": {"code": code, "correlation_id": correlation_id}}
    if receipt_ref is not None:
        if not isinstance(receipt_ref, str) or not receipt_ref or not receipt_ref.isprintable():
            raise ValueError("receipt_ref must be a non-empty printable opaque string")
        body["receipt_ref"] = receipt_ref
    return body


def serving_error(code: ServingCode, correlation_id: str | None = None) -> tuple[int, dict[str, Any]]:
    """Return ``(http_status, body)`` for a serving code, minting an id if needed."""
    code = ServingCode(code)
    return code.http_status, build_error_body(code.value, correlation_id or new_correlation_id())


def validate_error_body(body: object) -> bool:
    """True only for a body with exactly the contract shape and no extra field."""
    if not isinstance(body, dict) or "error" not in body or not set(body) <= {"error", "receipt_ref"}:
        return False
    err = body["error"]
    return (
        isinstance(err, dict)
        and set(err) == {"code", "correlation_id"}
        and err["code"] in PUBLIC_ERROR_CODES
        and isinstance(err["correlation_id"], str)
    )


def local_only_authorizer() -> EndpointAuthorizer:
    """Return an authorizer with no rules: every endpoint use is denied.

    A serving process uses this so it has no provider host (or any remote host)
    to dial; every purpose evaluates to ``unknown_purpose``. It adds no allow path.
    """
    return EndpointAuthorizer.from_exact_rules({}, version="telos-serving-local-only")
