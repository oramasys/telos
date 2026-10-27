"""Stable serving vocabulary, public error bodies and the local-only egress preset.

Telos owns no readiness or lifecycle state (see docs/BOUNDARIES.md). This module
only fixes the *words* a serving consumer uses when it is not ready or
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
    ROUTE_NOT_EXPOSED = "serving.route_not_exposed"

    @property
    def http_status(self) -> int:
        """HTTP status for this code: 503 for not-ready, 404 for not exposed."""
        return 404 if self is ServingCode.ROUTE_NOT_EXPOSED else 503


# Every public code the contract allows in an error body. Anything else is refused.
PUBLIC_ERROR_CODES: frozenset[str] = frozenset(
    {c.value for c in ServingCode}
    | {
        "deny.revocation_stale", "deny.unknown_key", "deny.malformed_grant",
        "deny.revoked_grant", "deny.missing_capability_record",
        "deny.unauthorized_caller", "deny.verifier_unavailable", "deny.grant_conflict",
        "startup.serving_without_verifier", "startup.effects_without_permit_verifier",
        "startup.transport_without_policy", "startup.autonomy_without_activation",
        "startup.monitoring_as_permission", "startup.serving_implies_effects",
        "capability.unsigned_enablement",
    }
)


_ERROR_FIELDS: frozenset[str] = frozenset({"code", "correlation_id", "receipt_ref"})

# HTTP status of each public deny.* code (contract section 3); one table for every surface.
DENY_STATUS: dict[str, int] = {
    "deny.malformed_grant": 400,
    "deny.unauthorized_caller": 401,
    "deny.grant_conflict": 409,
    "deny.unknown_key": 403,
    "deny.revoked_grant": 403,
    "deny.missing_capability_record": 403,
    "deny.revocation_stale": 503,
    "deny.verifier_unavailable": 503,
}


def new_correlation_id() -> str:
    """Return a fresh random UUID string for an error body."""
    return str(uuid.uuid4())


def _valid_correlation_id(value: object) -> bool:
    """True only for a string that parses as a UUID."""
    if not isinstance(value, str):
        return False
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


def _valid_receipt_ref(value: object) -> bool:
    """True only for a non-empty printable opaque string."""
    return isinstance(value, str) and bool(value) and value.isprintable()


def build_error_body(code: str, correlation_id: str, *, receipt_ref: str | None = None) -> dict[str, Any]:
    """Build the contract error body ``{"error": {"code", "correlation_id"}}``.

    ``receipt_ref`` is the only optional field, and only when a durable record
    exists; it is placed inside the ``error`` object as the contract specifies
    and is never a sibling of ``error``. There is no way to pass any other field.
    Unknown codes and malformed ids raise ValueError.
    """
    code = str(code)
    if code not in PUBLIC_ERROR_CODES:
        raise ValueError("unknown public error code")
    if not _valid_correlation_id(correlation_id):
        raise ValueError("correlation_id must be a UUID string")
    error: dict[str, str] = {"code": code, "correlation_id": correlation_id}
    if receipt_ref is not None:
        if not _valid_receipt_ref(receipt_ref):
            raise ValueError("receipt_ref must be a non-empty printable opaque string")
        error["receipt_ref"] = receipt_ref
    return {"error": error}


def serving_error(code: ServingCode, correlation_id: str | None = None) -> tuple[int, dict[str, Any]]:
    """Return ``(http_status, body)`` for a serving code, minting an id if needed."""
    code = ServingCode(code)
    return code.http_status, build_error_body(code.value, correlation_id or new_correlation_id())


def validate_error_body(body: object, *, status: int) -> bool:
    """True only for a body build_error_body could have produced, sent with its status.

    ``status`` is required: a code with a fixed HTTP status (``DENY_STATUS`` or a
    ``ServingCode``) conforms only with exactly that status, so there is no unchecked
    shape-only call. Never raises.
    """
    if not isinstance(body, dict) or set(body) != {"error"}:
        return False
    err = body["error"]
    if not isinstance(err, dict) or not {"code", "correlation_id"} <= set(err) <= _ERROR_FIELDS:
        return False
    if "receipt_ref" in err and not _valid_receipt_ref(err["receipt_ref"]):
        return False
    code = err["code"]
    if not (isinstance(code, str) and code in PUBLIC_ERROR_CODES
            and _valid_correlation_id(err["correlation_id"])):
        return False
    expected = DENY_STATUS.get(code)
    if expected is None and code in {c.value for c in ServingCode}:
        expected = ServingCode(code).http_status
    return expected is None or (type(status) is int and status == expected)


def local_only_authorizer() -> EndpointAuthorizer:
    """Return an authorizer with no rules: every endpoint use is denied.

    A serving process uses this so it has no provider host (or any remote host)
    to dial; every purpose evaluates to ``unknown_purpose``. It adds no allow path.
    """
    return EndpointAuthorizer.from_exact_rules({}, version="telos-serving-local-only")
