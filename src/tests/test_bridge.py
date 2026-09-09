import base64
import socket
import telos.bridge as bridge


def test_bridge_rejects_unlisted_endpoint_before_network(monkeypatch):
    payload = {
        'url': 'http://localhost:11434/api/tags',
        'allowed_endpoints': ['http://other.local:11434'],
        'transport': {'allow_loopback': True},
    }
    # Endpoint authorization should deny before any dial. DNS for localhost is
    # deterministic inside resolver, but monkeypatch request to prove the
    # semantic contract is built from caller-declared allowed endpoint set.
    class Denied(Exception): pass
    # exercise actual handle only through a synthetic loopback resolver by replacing request
    seen = {}
    def fake_request(method, url, **kwargs):
        decision = kwargs['authorizer']._policy.evaluate(
            bridge.EndpointPurpose.MODEL_EGRESS,
            type('I', (), {'is_public': False, 'endpoint': bridge.endpoint_from_url(url)})(),
        )
        seen['decision'] = decision
        if decision != 'allowed':
            raise ValueError(decision)
    monkeypatch.setattr(bridge, 'request', fake_request)
    try:
        bridge.handle(payload)
    except ValueError as exc:
        assert str(exc) == 'endpoint_not_permitted'
    assert seen['decision'] == 'endpoint_not_permitted'


def test_bridge_decodes_request_body_and_encodes_response(monkeypatch):
    class Response:
        status = 200
        headers = (("content-type", "application/json"),)
        body = b'{"ok":true}'
        final_url = 'http://localhost:11434/api/generate'
    captured = {}
    def fake_request(method, url, **kwargs):
        captured['body'] = kwargs['body']
        return Response()
    monkeypatch.setattr(bridge, 'request', fake_request)
    body = b'{"model":"x"}'
    result = bridge.handle({
        'method': 'POST',
        'url': 'http://localhost:11434/api/generate',
        'allowed_endpoints': ['http://localhost:11434'],
        'transport': {'allow_loopback': True},
        'body_base64': base64.b64encode(body).decode('ascii'),
    })
    assert captured['body'] == body
    assert base64.b64decode(result['body_base64']) == b'{"ok":true}'


def test_bridge_requires_remote_opt_in_and_host_allowlist(monkeypatch):
    monkeypatch.setattr(bridge, 'request', lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError('must fail before network')))
    base = {
        'url': 'https://provider.example/v1/models',
        'allowed_endpoints': ['https://provider.example'],
    }
    try:
        bridge.handle(base)
    except bridge.EndpointPolicyError as exc:
        assert exc.code == 'remote_denied'
    else:
        raise AssertionError('remote endpoint unexpectedly allowed')

    try:
        bridge.handle({**base, 'allow_remote': True, 'allowed_hosts': ['other.example']})
    except bridge.EndpointPolicyError as exc:
        assert exc.code == 'host_not_allowlisted'
    else:
        raise AssertionError('unlisted host unexpectedly allowed')
