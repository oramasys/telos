"""Inbound exposure policy: which local routes a consumer may expose.

This governs *inbound* routes only. It has no host, URL or provider field, so no
provider host can be added through it. The default is empty: nothing exposed.
Matching is exact and case-sensitive on (method, path); anything else, including
malformed input, is ``serving.route_not_exposed``.
"""
from __future__ import annotations

from dataclasses import dataclass

from .serving import ServingCode

_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
READINESS_ROUTES: tuple[tuple[str, str], ...] = (("GET", "/healthz"), ("GET", "/readyz"))


def _valid_path(path: object) -> bool:
    """Accept only a plain absolute path: no query, fragment, wildcard, dot-segment or control chars."""
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        return False
    if any(ch in path for ch in "?#*%\\ ") or not path.isprintable():
        return False
    return not any(seg in {".", ".."} for seg in path.split("/"))


def _valid_route(route: object) -> bool:
    """True for a (METHOD, /path) pair using a known uppercase method."""
    return (
        isinstance(route, tuple) and len(route) == 2
        and isinstance(route[0], str)
        and route[0] in _METHODS and _valid_path(route[1])
    )


@dataclass(frozen=True, slots=True)
class ExposureDecision:
    """Result of an exposure check; ``code``/``status`` are set only when refused."""

    exposed: bool
    code: str | None = None
    status: int | None = None


@dataclass(frozen=True, slots=True)
class ExposurePolicy:
    """Immutable explicit allowlist of (method, path) routes; default exposes nothing."""

    routes: frozenset[tuple[str, str]] = frozenset()

    def __post_init__(self) -> None:
        """Freeze and validate the routes; any malformed entry raises ValueError."""
        routes = frozenset(self.routes)
        if not all(_valid_route(r) for r in routes):
            raise ValueError("routes must be (UPPERCASE_METHOD, '/exact/path') pairs")
        object.__setattr__(self, "routes", routes)

    @classmethod
    def verify_readiness_only(cls, verify_path: str, verify_method: str = "POST") -> "ExposurePolicy":
        """Allow only GET /healthz, GET /readyz and the one named verify route."""
        verify = (verify_method, verify_path)
        if not _valid_route(verify):
            raise ValueError("verify route must be a valid (METHOD, path) pair")
        if verify in READINESS_ROUTES:
            raise ValueError("verify route must differ from the readiness routes")
        return cls(frozenset(READINESS_ROUTES) | {verify})

    def decide(self, method: object, path: object) -> ExposureDecision:
        """Return exposed, or ``serving.route_not_exposed`` (404) for anything else."""
        if _valid_route((method, path)) and (method, path) in self.routes:
            return ExposureDecision(True)
        return ExposureDecision(
            False, ServingCode.ROUTE_NOT_EXPOSED.value, ServingCode.ROUTE_NOT_EXPOSED.http_status
        )
