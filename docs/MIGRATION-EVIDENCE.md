# Tripwire/Telos Clean-Room Migration Evidence

Telos restores the accepted 2026-08-29 architecture: it is the single v2
endpoint-security authority succeeding Tripwire. The implementation is a
clean-room reimplementation. Historical implementations are behavioral evidence
only and are never imported, loaded, or invoked by the v2 runtime.

## Authority lineage

```text
Tripwire concept
  -> PT v1 endpoint-policy / SSRF / pinned-dialer evidence
  -> accepted 2026-08-29 Telos/Phylax ownership split
  -> Telos v2 clean-room implementation
```

The September semantic-only Telos scaffold was implementation drift. It did not
supersede the 2026-08-29 design and is retained only as provenance for the
semantic endpoint-use contract subsequently recomposed with transport security
inside Telos.

## Pinned evidence revisions

| Source | Revision | Evidence |
| --- | --- | --- |
| `diazMelgarejo/Perpetua-Tools` | `a551da4fa97e5fbc6f908ad077c7b6d8030a3220` | v1 endpoint identity, deny predicates, pinned transport, regression tests |
| `oramasys/Claude-Desktop-LLM` | `ba4f3910efc6496cd6476a274b93f4b877ba12b3` | pre-transfer v2 Node endpoint policy, DNS pinning, redirects, Host/SNI, cancellation evidence |
| `oramasys/oramasys` | `8ad2574010013d9f5b40b193d316516872462130` | Gateway Lifecycle dialer behavior and additional prohibited-range vectors; transitional duplicate authority |
| `oramasys/telos` scaffold | `88fba4beb95b3809e0a6094fedc766b03cb95b0e` | semantic endpoint-use contracts and deny-by-default purpose policy |

Governance/correction inputs also include the 2026-09-10 restoration package
(`CORRECTION-2026-09-10.md`, Telos/Phylax boundary/license corrections, and
apply instructions). Those files are planning/provenance inputs; the live
verified Telos branch is the implementation source of truth.

## PT parity evidence

The clean-room implementation was compared directly against:

- `src/utils/endpoint_policy_core.py` — HTTP/HTTPS identity, credential
  rejection, malformed-port rejection and IPv6-safe reconstruction;
- `src/utils/ssrf_fetch_policy.py` — loopback/private/link-local/CGNAT,
  multicast/reserved/unspecified and metadata protections, including
  IPv4-mapped IPv6 normalization;
- `src/utils/ssrf_pinned_adapter.py` — all-answer DNS validation, vetted-pin
  connection, Host/TLS SNI preservation, peer re-check, proxy isolation and
  redirect revalidation;
- `tests/test_ssrf_pinned_adapter.py` — metadata redirects, split identity,
  peer checking, DNS-change isolation, redirect methods and pool/concurrency
  regressions;
- `docs/plans/2026-08-21-pt-endpoint-hardening-checklists.md` and PT `.agent`
  evidence around the split-identity/pinned-transport decisions.

## Claude-Desktop-LLM parity evidence and transfer

The reusable behavior in the pre-transfer TypeScript endpoint-policy module was
absorbed into Telos. The consumer transfer is implemented in
`oramasys/Claude-Desktop-LLM` PR #1, branch
`2026-09-10-transfer-endpoint-security-to-telos`.

**Verified consumer-transfer head:**
`29aa88cb4191669a575b4ba7b9734c4e98482995`.

GitHub Actions CI run `34407006219` completed successfully at that exact head.
`guardedFetch()` is now only a provider-facing compatibility facade backed by
the Telos bridge; there is no direct-fetch fallback. Provider contract tests
inject a deterministic Telos transport double instead of recreating endpoint
security.

Claude's `AbortSignal` cannot be reproduced byte-for-byte by a synchronous
Python socket after the OS has entered a blocking call. Telos therefore owns
cooperative cancellation checks before resolution/network work and at redirect
re-entry, plus bounded socket timeouts; the Node bridge terminates the in-flight
Telos bridge process on cancellation.

## Phylax governance evidence

`oramasys/phylax` PR #1 restores Apache-2.0 and explicitly excludes endpoint
security from Phylax's generic security/safety/admission boundary.

**Verified Phylax head:**
`9c5ad79e95c0400a0e24ef7c4f5d6fd90a9b27c5`.

GitHub Actions CI run `34407316622` completed successfully at that exact head
under the project coverage gate. Runtime admission logic is unchanged by that
governance correction.

## Oramasys Gateway Lifecycle evidence and migration dependency

`oramasys/oramasys/src/orama/gateway/dialer.py` is strong implementation evidence
but is not a permissible steady-state owner. It currently contains DNS
resolution, special-address classification, public/local admission, timeout
handling and connector discipline created under the semantic-only Telos
scaffold. Its additional vectors include CGNAT (`100.64.0.0/10`), 6to4 relay
anycast (`192.88.99.0/24`), Teredo (`2001::/32`), 6to4 (`2002::/16`),
all-answer validation and bounded dial timeouts.

These vectors belong in Telos parity/conformance evidence. Oramasys may keep
provider/application purpose and port policy, but it must not remain a second
DNS/classification/socket-pinning authority. Consumer migration must target the
restored Telos contracts rather than merely changing a dependency SHA.

## Semantic and transport separation

Both concerns belong to Telos, but remain distinct decisions:

1. transport policy determines whether destination/address class and connection
   path are safe;
2. semantic policy determines whether the normalized endpoint is authorized for
   the declared purpose;
3. an `AuthorizedEndpoint` exists only when both succeed.

Public/private/loopback classification is Telos-produced resolution evidence,
not caller-supplied semantic authority.

## Implemented parity vectors

- canonical HTTP/HTTPS identity and IDNA host normalization;
- all-answer DNS validation and fail-closed mixed trust classes;
- metadata, loopback, private, link-local, multicast, unspecified, special-use,
  CGNAT and IPv4-mapped IPv6 handling;
- public HTTPS requirement where configured;
- semantic allow cannot bypass transport denial;
- transport safety cannot imply semantic permission;
- pinned TCP connection to the vetted IP;
- post-connect peer equality check;
- authoritative Host header and TLS SNI use the normalized endpoint NAME;
- environment proxy settings are not consulted by direct pinned transport;
- every redirect re-enters normalization, resolution, transport policy and
  semantic authorization;
- 301/302/303 switch to GET and drop body/body headers;
- 307/308 preserve method and body;
- cross-origin redirects strip Authorization, Cookie and Proxy-Authorization;
- bounded redirects, cooperative cancellation and bounded timeouts.

## Coverage and verification gate

Telos enforces at least **80%** line coverage through pytest configuration; any
stricter component threshold takes precedence and must never be lowered.

The restoration suite was first verified locally with **28 passing tests** and
coverage above the project floor. A GitHub Actions gate was then added. Its
first CI run exposed a Python-version portability defect in the TLS **test
double** (missing `SSLContext.verify_mode`), while 27/28 tests passed and total
coverage remained 87.02%. Production TLS/pinning code was not weakened. The
fake context was corrected to satisfy the real stdlib HTTPSConnection contract;
final exact-head CI is the completion gate.

## Canonical documentation evidence

`diazMelgarejo/orama-system` PR #351 contains the current reconciliation.
ADR 62 was corrected in commit
`42bef136120eaadd311ab2e21a7f17d2db1017ba` to restore the 2026-08-29
Tripwire/Telos authority, reject the semantic-only scaffold as implementation
drift, and classify the Oramasys Gateway dialer as transitional.

## Related restoration evidence

- `oramasys/telos` PR #1 — full Tripwire/Telos endpoint-security authority;
- `oramasys/Claude-Desktop-LLM` PR #1 — verified consumer transfer;
- `oramasys/phylax` PR #1 — verified Apache-2.0/boundary correction;
- `diazMelgarejo/orama-system` PR #351 — canonical ADR/errata record;
- `diazMelgarejo/Perpetua-Tools` PR #382 — v1 dialer parity evidence; it does
  not confer v2 authority on PT.

## Canonical result

The union of endpoint identity, SSRF/address policy, DNS/rebinding defense,
pinned transport, redirect/proxy/TLS destination safety and purpose-scoped
endpoint authorization lives in `oramasys/telos`. Provider/application packages
consume Telos and must not maintain permanent independent endpoint-security
implementations. PT remains a v1 authority only inside its own regime and a
read-only evidence source for clean-room v2 implementation.
