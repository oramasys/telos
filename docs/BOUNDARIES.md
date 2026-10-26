# Telos Boundaries

Telos owns **all endpoint-specific security**. This restores the accepted 2026-08-29 Tripwire/Telos architecture.

| Concern | Canonical owner |
| --- | --- |
| URL parse/canonicalization and scheme/host/port identity | Telos |
| IP/CIDR, metadata and special-use classification | Telos |
| SSRF, DNS resolution, DNS rebinding defense | Telos |
| Connection-time IP/socket pinning | Telos |
| Redirect/proxy/TLS destination safety | Telos |
| Purpose-scoped endpoint-use authorization | Telos |
| Provider protocol/readiness/lifecycle | provider owner / Oramasys composition |
| Hardware capability and placement | Agate |
| Generic runtime security/safety/admission/monitorability | Phylax |
| Generic execution primitives and event contracts | Core (`oramasys/perpetua-core`) |
| Workflow state, idempotency, routing and progress | Oramasys |

A semantic `EndpointUseDecision` is not transport-safety evidence by itself. A transport-safe endpoint is not purpose-authorized by itself. Telos composes both decisions before network use.

Optional constellation IdP providers (Google / X) must not dial the public
internet raw. Telos owns purpose-scoped IdP/JWKS/token egress and SSRF
deny-by-default for those paths. Local Bearer/gossip remain root of trust; IdP
absence never disables local auth. See `docs/IDP-SSRF-EGRESS.md`.

## Migration evidence

- v1 PT `packages/endpoint-policy`, `src/utils/endpoint_policy_core.py`, `src/utils/ssrf_fetch_policy.py`, and `src/utils/ssrf_pinned_adapter.py` are read-only golden evidence.
- `oramasys/Claude-Desktop-LLM/src/policy/endpoint-policy.ts` is v2 implementation evidence to be transferred to Telos, not a permanent duplicate authority.
- no v2 runtime may import or execute PT endpoint-security code.

## Serving contracts (draft, D3)

Telos supplies the *vocabulary and guards* a serving consumer uses. It still
owns **no readiness, lifecycle or enablement state**; the consumer (Oramasys)
decides when it is ready or disabled and calls these helpers. Nothing here
enables anything, and none of it is an activation record.

- **Exposure policy** (`telos.exposure.ExposurePolicy`): an immutable, explicit
  allowlist of exact `(METHOD, /path)` pairs for *inbound* routes. The default is
  empty, so nothing is exposed. `verify_readiness_only(verify_path)` allows only
  `GET /healthz`, `GET /readyz` and the one named verify route. Anything else,
  including malformed input, yields `serving.route_not_exposed` (404). It has no
  host field, so no provider host can be added through it.
- **Stable codes** (`telos.serving.ServingCode`): `serving.not_ready` and
  `serving.disabled` (HTTP 503) and `serving.route_not_exposed` (404).
  `build_error_body` emits exactly `{"error": {"code", "correlation_id"}}` (plus
  an opaque `receipt_ref` only when a durable record exists) and accepts no other
  field. A not-ready state is a 503, never a 200 with a warning.
- **Proxy isolation**: `TransportPolicy.trust_env` is `False` and `False` is the
  only accepted value. `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY`
  are never read; each hop dials its vetted, pinned IP directly. Redirect rules
  are unchanged and now pinned by tests: credential headers are dropped on an
  origin change, a public `http://` hop is refused (`https_required`), and every
  hop is re-authorized.
- **Local-only egress** (`telos.serving.local_only_authorizer`): an authorizer
  with no rules, so a serving process has no provider or remote host to dial.
