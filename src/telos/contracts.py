"""Canonical Telos contracts spanning endpoint identity, transport, and use."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol
import ipaddress
class EndpointPurpose(StrEnum):
    CONFIG_READ="config_read"; HEALTH_PROBE="health_probe"; MODEL_EGRESS="model_egress"
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
