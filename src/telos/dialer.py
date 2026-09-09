"""Async secure-dial primitive owned by Telos.

This module exists for consumers such as Oramasys Gateway that need a bounded
connectivity operation rather than an HTTP request. Telos still owns the full
security boundary: DNS answers are validated before dispatch, semantic
authorization binds to Telos-produced endpoint identity, the connector receives
only a vetted pin, and the connected peer is rechecked against that pin.
"""
from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from secrets import token_urlsafe
from typing import Protocol

from .address import assert_address_allowed, is_public_address, parse_ip
from .contracts import EndpointIdentity, EndpointPurpose, EndpointRef, EndpointUseDecision, EndpointUseRequest
from .errors import EndpointPolicyError


AsyncResolver = Callable[[str], Awaitable[Sequence[str]]]


class SecureDialAuthorizer(Protocol):
    def authorize(
        self, request: EndpointUseRequest
    ) -> EndpointUseDecision | Awaitable[EndpointUseDecision]: ...


@dataclass(frozen=True, slots=True)
class SecureDialRequest:
    endpoint: EndpointRef
    purpose: EndpointPurpose
    actor_id: str
    workflow_id: str
    run_id: str
    allow_public: bool = False
    allow_private: bool = True
    allow_loopback: bool = True
    require_https_for_public: bool = True
    timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        for field_name in ("actor_id", "workflow_id", "run_id"):
            if not getattr(self, field_name).strip():
                raise ValueError(f"{field_name} is required")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")


@dataclass(frozen=True, slots=True)
class ConnectedPeer:
    provider_ref: str
    peer_address: str

    def __post_init__(self) -> None:
        if not self.provider_ref.strip():
            raise ValueError("provider_ref is required")
        if not self.peer_address.strip():
            raise ValueError("peer_address is required")


class SecureDialConnector(Protocol):
    async def connect(
        self,
        *,
        endpoint: EndpointRef,
        pinned_address: str,
        purpose: EndpointPurpose,
        timeout_seconds: float,
    ) -> ConnectedPeer: ...


@dataclass(frozen=True, slots=True)
class SecureDialResult:
    allowed: bool
    reason_code: str
    endpoint_identity: EndpointIdentity | None = None
    decision: EndpointUseDecision | None = None
    provider_ref: str | None = None


class SecureDialer:
    """Resolve, authorize and execute one pinned endpoint dial."""

    def __init__(
        self,
        *,
        authorizer: SecureDialAuthorizer,
        resolver: AsyncResolver,
        connector: SecureDialConnector,
    ) -> None:
        self._authorizer = authorizer
        self._resolver = resolver
        self._connector = connector

    async def dial(self, request: SecureDialRequest) -> SecureDialResult:
        try:
            async with asyncio.timeout(request.timeout_seconds):
                identity = await self._resolve(request)
                if (
                    identity.is_public
                    and request.require_https_for_public
                    and request.endpoint.scheme != "https"
                ):
                    return SecureDialResult(False, "https_required", identity)

                maybe_decision = self._authorizer.authorize(
                    EndpointUseRequest(
                        actor_id=request.actor_id,
                        workflow_id=request.workflow_id,
                        purpose=request.purpose,
                        endpoint=identity,
                        run_id=request.run_id,
                    )
                )
                decision = (
                    await maybe_decision
                    if inspect.isawaitable(maybe_decision)
                    else maybe_decision
                )
                if decision.endpoint != identity:
                    return SecureDialResult(
                        False, "authorization_endpoint_mismatch", identity, decision
                    )
                if _decision_is_expired(decision):
                    return SecureDialResult(
                        False, "authorization_expired", identity, decision
                    )
                if not decision.allowed:
                    return SecureDialResult(
                        False, f"purpose_denied:{decision.reason_code}", identity, decision
                    )

                pinned_address = identity.resolved_addresses[0]
                try:
                    connected = await self._connector.connect(
                        endpoint=request.endpoint,
                        pinned_address=pinned_address,
                        purpose=request.purpose,
                        timeout_seconds=request.timeout_seconds,
                    )
                except Exception:
                    return SecureDialResult(False, "connector_refused", identity, decision)

                if parse_ip(connected.peer_address) != parse_ip(pinned_address):
                    return SecureDialResult(False, "peer_pin_mismatch", identity, decision)

                return SecureDialResult(
                    True,
                    "dialed",
                    identity,
                    decision,
                    connected.provider_ref,
                )
        except TimeoutError:
            return SecureDialResult(False, "dial_timeout")
        except EndpointPolicyError as exc:
            return SecureDialResult(False, exc.code)

    async def _resolve(self, request: SecureDialRequest) -> EndpointIdentity:
        endpoint = request.endpoint
        try:
            literal = parse_ip(endpoint.host)
        except EndpointPolicyError:
            try:
                raw_answers = await self._resolver(endpoint.host)
            except OSError as exc:
                raise EndpointPolicyError(
                    "dns_resolution_failed",
                    f"DNS resolution failed for {endpoint.host!r}",
                ) from exc
            addresses = tuple(dict.fromkeys(str(parse_ip(answer)) for answer in raw_answers))
            if not addresses:
                raise EndpointPolicyError(
                    "dns_resolution_failed",
                    f"DNS resolution returned no addresses for {endpoint.host!r}",
                )
        else:
            addresses = (str(literal),)

        public_flags: list[bool] = []
        for address in addresses:
            assert_address_allowed(
                address,
                allow_public=request.allow_public,
                allow_private=request.allow_private,
                allow_loopback=request.allow_loopback,
            )
            public_flags.append(is_public_address(address))
        if len(set(public_flags)) != 1:
            raise EndpointPolicyError(
                "mixed_address_classification",
                "DNS answers span incompatible trust classes",
            )
        return EndpointIdentity(
            endpoint=endpoint,
            resolved_addresses=addresses,
            is_public=public_flags[0],
            resolution_ref=token_urlsafe(18),
        )


def _decision_is_expired(decision: EndpointUseDecision) -> bool:
    expires_at = decision.expires_at
    return expires_at is not None and (
        expires_at.tzinfo is None
        or expires_at.utcoffset() is None
        or expires_at <= datetime.now(UTC)
    )
