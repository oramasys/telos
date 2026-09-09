"""Stable fail-closed Telos error codes."""
from __future__ import annotations

class TelosError(RuntimeError):
    """Base class for endpoint-security failures."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code

class EndpointPolicyError(TelosError):
    """Endpoint identity or transport policy rejected a destination."""
