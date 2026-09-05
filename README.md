# Telos

Telos is the semantic endpoint-use authorization boundary for Oramasys.

It answers one narrow question:

> May this actor use this already-normalized endpoint for this declared purpose?

Telos does not parse arbitrary URLs, resolve DNS, pin connections, follow
redirects, choose a provider, select hardware, or execute a request. Those
responsibilities remain with the endpoint primitive, SSRF transport policy,
provider adapter, and Agate respectively.

## Initial vertical slice

The package provides:

- immutable `EndpointRef`, `EndpointUseRequest`, and `EndpointUseDecision`
  contracts;
- deny-by-default, exact-match policy rules;
- explicit purpose names (`config_read`, `health_probe`, and `model_egress`);
- redacted in-memory decision records for tests and local composition;
- a protocol-shaped authorizer that can later be backed by a durable policy
  service without changing callers.

This is a contract/reference implementation, not a production network service.
The caller must obtain endpoint identity from the canonical endpoint-policy
primitive and must still run the appropriate SSRF/transport checks before
network access.

## Example

```python
from telos import EndpointAuthorizer, EndpointRef, EndpointUseRequest, EndpointPurpose

authorizer = EndpointAuthorizer.from_exact_rules({
    EndpointPurpose.HEALTH_PROBE: {("https", "model.internal", 443)},
})

decision = authorizer.authorize(EndpointUseRequest(
    actor_id="gateway",
    workflow_id="readiness",
    purpose=EndpointPurpose.HEALTH_PROBE,
    endpoint=EndpointRef(scheme="https", host="model.internal", port=443),
    run_id="run-1",
))
assert decision.allowed
```

## Boundary status

This repository is intentionally being introduced during the transition from
Perpetua-Tools and Orama. It does not claim that either legacy authority has
already been migrated. See the companion reconstruction plan in the OpenClaw
references directory and Orama's v2 kernel/security plans before adding new
consumers.

