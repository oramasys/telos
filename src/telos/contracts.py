"""Canonical Telos contracts spanning endpoint identity, transport, and use."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol
import ipaddress
class EndpointPurpose(StrEnum):
    CONFIG_READ="config_read"; HEALTH_PROBE="health_probe"; MODEL_EGRESS="model_egress"
    # IdP purpose IDs registered per docs/IDP-SSRF-EGRESS.md Step 1 of 3. Adding
    # these members grants no access by itself -- EndpointPolicy.evaluate()
    # still returns "unknown_purpose" for any purpose with no rule in a
    # trusted pack (policy.py), and no such pack exists for these yet. Steps
    # 2 (request-profile enforcement: exact method/path/query, not just
    # origin) and 3 (Oramasys provider wiring) remain separate, later work.
    # idp-x-oauth is intentionally NOT a member: the design doc supersedes it
    # with IDP_X_TOKEN for server HTTP plus a browser-only authorization
    # flow Telos never server-fetches. Preserve the old ID as historical
    # provenance in the doc; do not register or alias it here.
    IDP_GOOGLE_OIDC_DISCOVERY="idp-google-oidc-discovery"
    IDP_GOOGLE_JWKS="idp-google-jwks"
    IDP_GOOGLE_TOKEN="idp-google-token"
    IDP_GOOGLE_USERINFO="idp-google-userinfo"
    IDP_X_TOKEN="idp-x-token"
    IDP_X_USERINFO="idp-x-userinfo"
@dataclass(frozen=True, slots=True)
class EndpointRef:
    scheme:str; host:str; port:int
    def __post_init__(self)->None:
        scheme = self.scheme.strip().lower()
        host = self.host.strip().lower().rstrip(".")
        if scheme not in {"http", "https"}:
            raise ValueError("endpoint scheme must be http or https")
        if not host or any(ch.isspace() for ch in host):
            raise ValueError("endpoint host is required and must not contain whitespace")
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            try:
                host = host.encode("idna").decode("ascii")
            except UnicodeError as exc:
                raise ValueError("endpoint hostname is not valid IDNA") from exc
        if not 1 <= self.port <= 65535:
            raise ValueError("endpoint port must be between 1 and 65535")
        object.__setattr__(self, "scheme", scheme)
        object.__setattr__(self, "host", host)
    @property
    def key(self): return self.scheme,self.host,self.port
@dataclass(frozen=True, slots=True)
class EndpointIdentity:
    endpoint:EndpointRef; resolved_addresses:tuple[str,...]; is_public:bool; resolution_ref:str
    def __post_init__(self):
        if not self.resolved_addresses: raise ValueError("resolved_addresses must not be empty")
        if not self.resolution_ref.strip(): raise ValueError("resolution_ref is required")
@dataclass(frozen=True, slots=True)
class EndpointUseRequest:
    actor_id:str; workflow_id:str; purpose:EndpointPurpose; endpoint:EndpointIdentity; run_id:str
    def __post_init__(self):
        for field_name in ("actor_id","workflow_id","run_id"):
            if not getattr(self,field_name).strip(): raise ValueError(f"{field_name} is required")
@dataclass(frozen=True, slots=True)
class EndpointUseDecision:
    allowed:bool; reason_code:str; policy_version:str; decision_ref:str; endpoint:EndpointIdentity; expires_at:datetime|None=None
@dataclass(frozen=True, slots=True)
class DecisionRecord:
    request:EndpointUseRequest; decision:EndpointUseDecision; recorded_at:datetime
@dataclass(frozen=True, slots=True)
class AuthorizedEndpoint:
    identity:EndpointIdentity; purpose_decision:EndpointUseDecision
class TelosPort(Protocol):
    def authorize(self, request:EndpointUseRequest)->EndpointUseDecision: ...
