# Telos Boundaries

Telos is the semantic endpoint-use authority during the v2 migration.

| Concern | Owner |
| --- | --- |
| Normalized scheme/host/port identity | endpoint-policy primitive |
| Arbitrary URL safety, DNS resolution, pinning, redirects | SSRF/transport layer |
| Purpose-scoped permission to use a known endpoint | Telos |
| Provider selection and readiness | provider adapter / Oramasys |
| Hardware capability and placement | Agate |
| Artifact provenance and runtime admission | Phylax |
| Workflow state, idempotency, and progress | Oramasys |

Telos must deny unknown purposes and unknown endpoints. It must not accept a
credential-bearing raw URL as an authorization shortcut. An allow decision is
not a transport safety decision and is not a cost reservation.

## Migration posture

Perpetua-Tools and orama-system remain the dual v1 authorities. This package
is a compatibility-ready reference boundary, not proof that the v1 code has
been migrated. New integrations must be injected behind contracts and must
retain the legacy behavior until equivalent tests and review evidence exist.

