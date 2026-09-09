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
| Workflow state, idempotency, routing and progress | Oramasys |

A semantic `EndpointUseDecision` is not transport-safety evidence by itself. A transport-safe endpoint is not purpose-authorized by itself. Telos composes both decisions before network use.

## Migration evidence

- v1 PT `packages/endpoint-policy`, `src/utils/endpoint_policy_core.py`, `src/utils/ssrf_fetch_policy.py`, and `src/utils/ssrf_pinned_adapter.py` are read-only golden evidence.
- `oramasys/Claude-Desktop-LLM/src/policy/endpoint-policy.ts` is v2 implementation evidence to be transferred to Telos, not a permanent duplicate authority.
- no v2 runtime may import or execute PT endpoint-security code.
