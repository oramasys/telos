"""Stable, transport-neutral Telos contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol


class EndpointPurpose(StrEnum):
    CONFIG_READ = "config_read"
    HEALTH_PROBE = "health_probe"
    MODEL_EGRESS = "model_egress"


@dataclass(frozen=True, slots=True)
class EndpointRef:
    """A normalized endpoint identity, never a raw credential-bearing URL.

    `is_public` is trusted evidence, not something Telos can verify on its
    own -- Telos explicitly does not resolve DNS or classify IP addresses
    (see module docstring / boundary record). It MUST be supplied by the
    canonical endpoint-normalization primitive that constructs this object,
    never by an untrusted actor whose request Telos is about to authorize.
    There is deliberately no default: a caller that omits it is forced to
    make an explicit, auditable classification instead of silently getting
    the permissive (non-public) value, which previously let a genuinely
    public endpoint be asserted as private to bypass the `allow_public`
    policy gate.
    """

    scheme: str
    host: str
    port: int
    is_public: bool

    def __post_init__(self) -> None:
        scheme = self.scheme.strip().lower()
        host = self.host.strip().lower().rstrip(".")
        if not scheme or not host:
            raise ValueError("endpoint scheme and host are required")
        if any(character.isspace() for character in scheme + host):
            raise ValueError("endpoint scheme and host must not contain whitespace")
        if not 1 <= self.port <= 65535:
            raise ValueError("endpoint port must be between 1 and 65535")
        object.__setattr__(self, "scheme", scheme)
        object.__setattr__(self, "host", host)

    @property
    def key(self) -> tuple[str, str, int]:
        return self.scheme, self.host, self.port


@dataclass(frozen=True, slots=True)
class EndpointUseRequest:
    actor_id: str
    workflow_id: str
    purpose: EndpointPurpose
    endpoint: EndpointRef
    run_id: str

    def __post_init__(self) -> None:
        for field_name in ("actor_id", "workflow_id", "run_id"):
            if not getattr(self, field_name).strip():
                raise ValueError(f"{field_name} is required")


@dataclass(frozen=True, slots=True)
class EndpointUseDecision:
    allowed: bool
    reason_code: str
    policy_version: str
    decision_ref: str
    endpoint: EndpointRef
    expires_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class DecisionRecord:
    request: EndpointUseRequest
    decision: EndpointUseDecision
    recorded_at: datetime


class TelosPort(Protocol):
    """Composition boundary used by the Oramasys gateway lifecycle."""

    def authorize(self, request: EndpointUseRequest) -> EndpointUseDecision:
        """Return a purpose-scoped decision for a normalized endpoint."""
