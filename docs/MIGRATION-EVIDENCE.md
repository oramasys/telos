# Tripwire/Telos Clean-Room Migration Evidence

Telos restores the accepted 2026-08-29 architecture: it is the single v2
endpoint-security authority succeeding Tripwire. The implementation is a
clean-room reimplementation. Historical implementations are behavioral evidence
only and are never imported, loaded, or invoked by the v2 runtime.

## Authority lineage

The intended lineage is additive, not a scope reduction:

```text
Tripwire concept
  -> PT v1 endpoint-policy / SSRF / pinned-dialer evidence
  -> accepted 2026-08-29 Telos/Phylax ownership split
  -> Telos v2 clean-room implementation
```

The September semantic-only Telos scaffold was implementation drift. It did not
supersede the 2026-08-29 design and is retained only as provenance for the
semantic endpoint-use contract that was subsequently recomposed with transport
security inside Telos.

## Pinned evidence revisions

| Source | Revision | Evidence |
| --- | --- | --- |
| `diazMelgarejo/Perpetua-Tools` | `a551da4fa97e5fbc6f908ad077c7b6d8030a3220` | v1 endpoint identity, deny predicates, pinned transport, regression tests |
| `oramasys/Claude-Desktop-LLM` | `ba4f3910efc6496cd6476a274b93f4b877ba12b3` | v2 Node local-first endpoint policy, DNS pinning, redirect revalidation, Host/SNI preservation, cancellation behavior |
| `oramasys/oramasys` | `8ad2574010013d9f5b40b193d316516872462130` | Gateway Lifecycle dialer behavior and additional prohibited-range vectors; transitional duplicate authority to migrate |
| `oramasys/telos` scaffold | `88fba4beb95b3809e0a6094fedc766b03cb95b0e` | semantic endpoint-use authorization contracts and deny-by-default purpose policy |

Governance/correction inputs also include the 2026-09-10 restoration package
(`CORRECTION-2026-09-10.md`, Telos/Phylax boundary/license corrections, and
apply instructions) supplied for this reconciliation. Those files are planning
and provenance inputs; the live tested Telos branch remains the implementation
source of truth.

## PT parity evidence

The clean-room implementation was compared directly against:

- `src/utils/endpoint_policy_core.py` — http/https endpoint identity,
  credential rejection, malformed-port rejection, IPv6-safe reconstruction;
- `src/utils/ssrf_fetch_policy.py` — loopback/private/link-local/CGNAT,
  multicast/reserved/unspecified and metadata protections, including
  IPv4-mapped IPv6 normalization;
- `src/utils/ssrf_pinned_adapter.py` — validate every DNS answer, connect to a
  vetted pin, preserve Host/TLS SNI identity, re-check the connected peer,
  reject proxy bypass, and manually revalidate redirects;
- `tests/test_ssrf_pinned_adapter.py` — metadata redirect rejection,
  split-identity pinning, peer checking, DNS-change isolation, redirect method
  rules, and concurrency/pool-contamination regressions;
- `docs/plans/2026-08-21-pt-endpoint-hardening-checklists.md` — the original
  Layer-1/Layer-2/Layer-3 hardening contract;
- PT `.agent` semantic/working memory around the 2026-08-21 through 2026-08-23
  SSRF split-identity and pinned-transport decisions.

## Claude-Desktop-LLM parity evidence and transfer

The clean-room implementation was compared directly against
`src/policy/endpoint-policy.ts` at the pinned revision. The reusable behaviors
moved into Telos include:

- local-first vs explicitly opted-in remote endpoints;
- hostname allowlisting for remote provider endpoints through the Telos bridge;
- structural URL validation and credential rejection;
- direct-loopback vs DNS-mediated loopback distinction through Telos transport
  profiles and address validation;
- connect-time IP pinning while preserving the original hostname as HTTP/TLS
  identity;
- manual redirect revalidation with a bounded redirect count;
- canonical hostname handling, including IDNA;
- bounded socket/read timeout propagation.

The consumer transfer is implemented in `oramasys/Claude-Desktop-LLM` PR #1,
branch `2026-09-10-transfer-endpoint-security-to-telos`. Its verified transfer
tree reached CI success before final squash; the final branch retains the same
tree under one cohesive commit. `guardedFetch()` remains only as a provider-
facing compatibility facade backed by `telos.bridge`; there is no direct-fetch
fallback. Provider contract tests inject a deterministic Telos transport double
rather than reimplement endpoint security.

Claude's `AbortSignal` cannot be reproduced byte-for-byte by a synchronous
Python socket after the operating system has entered a blocking call. Telos
therefore provides cooperative cancellation checks before resolution/network
work and at redirect re-entry boundaries, plus bounded socket timeouts. The
Claude language bridge terminates the in-flight bridge process on cancellation
instead of maintaining a second secure connector.

## Oramasys Gateway Lifecycle evidence and migration dependency

`oramasys/oramasys/src/orama/gateway/dialer.py` is strong implementation evidence
but is not a permissible steady-state owner. It currently contains DNS
resolution, special-address classification, public/local admission, timeout
handling, and a connector discipline created under the semantic-only Telos
scaffold. Its additional behavior vectors include CGNAT (`100.64.0.0/10`),
6to4 relay anycast (`192.88.99.0/24`), Teredo (`2001::/32`), 6to4
(`2002::/16`), all-answer validation, and bounded dial timeouts.

These vectors belong in Telos parity/conformance evidence. The Gateway may keep
provider/application-specific purpose and port policy, but must not remain a
second DNS/classification/socket-pinning authority. Consumer migration must be
performed against the restored Telos contracts rather than merely changing the
Telos dependency SHA: the old Gateway code still depends on the superseded
caller-supplied `EndpointRef.is_public` shape.

## Semantic and transport separation

Both concerns belong to Telos, but they are deliberately distinct decisions:

1. transport policy determines whether the destination/address class and
   connection path are safe;
2. semantic policy determines whether the normalized endpoint is authorized for
   the declared purpose;
3. an `AuthorizedEndpoint` is produced only when both decisions succeed.

Public/private/loopback classification is Telos-produced resolution evidence,
not caller-supplied semantic authority. An exact semantic endpoint allow rule
therefore does not independently reinterpret transport classification.

## Implemented parity vectors

- canonical http/https identity and IDNA host normalization;
- all-address DNS validation and fail-closed mixed trust classes;
- metadata, loopback, private, link-local, multicast, unspecified, special-use,
  CGNAT and IPv4-mapped IPv6 handling;
- public HTTPS requirement where configured;
- semantic allow does not bypass transport denial;
- transport safety does not imply semantic permission;
- pinned TCP connection to the vetted IP;
- post-connect peer equality check;
- authoritative Host header and TLS SNI use the normalized endpoint NAME;
- environment proxy settings are not consulted by the direct pinned transport;
- every redirect re-enters normalization, resolution, transport policy and
  semantic authorization;
- 301/302/303 switch to GET and drop request body/body headers;
- 307/308 preserve method and body;
- cross-origin redirects strip Authorization, Cookie and Proxy-Authorization;
- redirect limit remains bounded;
- cooperative pre-network cancellation and bounded timeouts.

## Coverage gate

The Telos project enforces a minimum line coverage threshold of **80%** via
pytest configuration. A stricter component-specific threshold, if introduced,
supersedes this floor and must never be lowered. The restoration hardening suite
was verified locally at **91.29%** coverage with **28 passing tests** before
publication.

## Related restoration evidence

- `oramasys/telos` PR #1 — full Tripwire/Telos endpoint-security authority;
- `oramasys/Claude-Desktop-LLM` PR #1 — consumer transfer, no permanent local
  secure connector;
- `oramasys/phylax` PR #1 — Apache-2.0 and explicit exclusion of endpoint-
  specific authority;
- `diazMelgarejo/orama-system` PR #351 — canonical migration/errata record;
- PT PR #382 — v1 dialer parity evidence; it does not confer v2 authority on PT.

## Canonical result

The union of endpoint identity, SSRF/address policy, DNS/rebinding defense,
pinned transport, redirect/proxy/TLS destination safety, and purpose-scoped
endpoint authorization lives in `oramasys/telos`. Provider/application packages
consume Telos and must not maintain permanent independent endpoint-security
implementations. PT remains a v1 authority only within its own regime and an
evidence source for the clean-room v2 implementation.
