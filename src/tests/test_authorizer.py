from telos import EndpointAuthorizer, EndpointPurpose, EndpointRef, EndpointUseRequest


def request(endpoint: EndpointRef, purpose: EndpointPurpose = EndpointPurpose.HEALTH_PROBE) -> EndpointUseRequest:
    return EndpointUseRequest("gateway", "readiness", purpose, endpoint, "run-1")


def test_exact_endpoint_is_allowed_and_recorded() -> None:
    authorizer = EndpointAuthorizer.from_exact_rules(
        {EndpointPurpose.HEALTH_PROBE: {("https", "model.internal", 443)}}
    )

    decision = authorizer.authorize(request(EndpointRef("https", "model.internal", 443)))

    assert decision.allowed
    assert decision.reason_code == "allowed"
    assert len(authorizer.records) == 1
    assert authorizer.records[0].decision.decision_ref == decision.decision_ref


def test_unknown_purpose_is_denied() -> None:
    authorizer = EndpointAuthorizer.from_exact_rules({})

    decision = authorizer.authorize(request(EndpointRef("https", "model.internal", 443)))

    assert not decision.allowed
    assert decision.reason_code == "unknown_purpose"


def test_public_endpoint_requires_explicit_rule_opt_in() -> None:
    authorizer = EndpointAuthorizer.from_exact_rules(
        {EndpointPurpose.MODEL_EGRESS: {("https", "api.example", 443)}}
    )

    decision = authorizer.authorize(
        request(EndpointRef("https", "api.example", 443, is_public=True), EndpointPurpose.MODEL_EGRESS)
    )

    assert not decision.allowed
    assert decision.reason_code == "endpoint_not_permitted"


def test_endpoint_identity_normalizes_scheme_and_host() -> None:
    endpoint = EndpointRef(" HTTPS ", "Model.Internal.", 443)

    assert endpoint.key == ("https", "model.internal", 443)

