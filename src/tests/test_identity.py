import pytest
from telos import EndpointPolicyError,endpoint_from_url
def test_normalizes_endpoint_and_default_port(): assert endpoint_from_url(" HTTPS://Model.Internal./health ").key==("https","model.internal",443)
def test_rejects_userinfo():
    with pytest.raises(EndpointPolicyError) as exc:endpoint_from_url("https://user:pass@example.com/")
    assert exc.value.code=="userinfo_present"
def test_rejects_non_http_scheme():
    with pytest.raises(EndpointPolicyError) as exc:endpoint_from_url("file:///etc/passwd")
    assert exc.value.code=="scheme_disallowed"

def test_idna_hostname_is_canonicalized():
    endpoint = endpoint_from_url("https://BÜCHER.example./")
    assert endpoint.key == ("https", "xn--bcher-kva.example", 443)
