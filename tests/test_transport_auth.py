"""Transport authentication at the reference target: the principal is the
client certificate the TLS-terminating proxy verified (X-Forwarded-Client-
Cert), or a proxy-set header, never anything the caller wrote itself."""

import uuid

from fastapi.testclient import TestClient

from gargoyle.consumer import (
    REF_TARGET_NO_PRINCIPAL, XFCC_HEADER, _xfcc_elements, build_reference_target_app,
    config_from_env, principal_from_xfcc,
)
from gargoyle.envelope import build_envelope, canonical_json, sign_envelope
from gargoyle.published_source import anchor_sha256
from gargoyle.verifier import REF_VERIFY_PRINCIPAL_MISMATCH
from reference import reference_pin, reference_policy, reference_record_bytes

TARGET_URL = "http://127.0.0.1:9000/target"
SPIFFE = "spiffe://example.org/agents/agent-7"
XFCC_ONE_HOP = ('By=spiffe://example.org/tools;Hash=ab12;'
                'Subject="CN=agent-7,O=Example";URI=' + SPIFFE)


class _Req:
    def __init__(self, headers):
        from starlette.datastructures import Headers
        self.headers = Headers(raw=[(k.lower().encode(), v.encode()) for k, v in headers])


def test_xfcc_parsing_handles_quoted_subjects_and_multiple_hops():
    two_hops = 'By=spiffe://a;URI=spiffe://first-hop,' + XFCC_ONE_HOP
    els = _xfcc_elements(two_hops)
    assert [e.get("URI") for e in els] == ["spiffe://first-hop", SPIFFE]
    assert els[1]["Subject"] == "CN=agent-7,O=Example"
    assert _xfcc_elements('Subject="unterminated') == []


def test_principal_is_the_last_hop_uri_else_subject():
    assert principal_from_xfcc(_Req([(XFCC_HEADER, XFCC_ONE_HOP)]), {}) == SPIFFE
    assert principal_from_xfcc(_Req([(XFCC_HEADER, 'Hash=ab12;Subject="CN=agent-7,O=Example"')]), {}) == "CN=agent-7,O=Example"
    assert principal_from_xfcc(_Req([(XFCC_HEADER, "Hash=ab12")]), {}) is None
    assert principal_from_xfcc(_Req([]), {}) is None
    assert principal_from_xfcc(_Req([(XFCC_HEADER, XFCC_ONE_HOP), (XFCC_HEADER, XFCC_ONE_HOP)]), {}) is None


def _target(gate_signing, principal_source="xfcc"):
    config = {
        "target_url": TARGET_URL, "publisher_url": "http://pub", "pinned_root_sha256": "x",
        "pinned_public_keys": {gate_signing["key_id"]: gate_signing["public_key"]},
        "principal_source": principal_source, "principal_header": "X-Peer",
    }
    app = build_reference_target_app(config_provider=lambda: config, fetch=lambda url, anchor: reference_pin())
    return app, TestClient(app)


def _receipt(gate_signing, principal):
    env = build_envelope(policy_pin=reference_policy().pin(), decision="ELIGIBLE", target_url=TARGET_URL,
                         call={"tool": "transfer", "args": {"amount": 5}, "principal": principal})
    return sign_envelope(env, gate_signing["private_key"], gate_signing["key_id"], decision_id=uuid.uuid4().hex)


def test_target_authenticates_by_proxy_verified_client_certificate(gate_signing):
    app, client = _target(gate_signing)
    body = {"tool": "transfer", "args": {"amount": 5}}
    env = _receipt(gate_signing, SPIFFE)
    r = client.post("/target", json=body, headers={"X-Gargoyle-Envelope": canonical_json(env),
                                                    XFCC_HEADER: XFCC_ONE_HOP})
    assert r.status_code == 200, r.text
    # The identity header is not consulted in xfcc mode.
    r = client.post("/target", json=body, headers={"X-Gargoyle-Envelope": canonical_json(_receipt(gate_signing, SPIFFE)),
                                                    "X-Peer": SPIFFE})
    assert r.json()["detail"]["reason"] == REF_TARGET_NO_PRINCIPAL
    # A certificate for someone else cannot spend agent-7's receipt.
    other = XFCC_ONE_HOP.replace("agent-7", "agent-8")
    r = client.post("/target", json=body, headers={"X-Gargoyle-Envelope": canonical_json(_receipt(gate_signing, SPIFFE)),
                                                    XFCC_HEADER: other})
    assert r.json()["detail"]["reason"] == REF_VERIFY_PRINCIPAL_MISMATCH
    assert len(app.state.received) == 1


def test_header_mode_is_explicit(gate_signing):
    app, client = _target(gate_signing, principal_source="header")
    body = {"tool": "transfer", "args": {"amount": 5}}
    r = client.post("/target", json=body, headers={"X-Gargoyle-Envelope": canonical_json(_receipt(gate_signing, "agent-7")),
                                                    "X-Peer": "agent-7"})
    assert r.status_code == 200
    r = client.post("/target", json=body, headers={"X-Gargoyle-Envelope": canonical_json(_receipt(gate_signing, SPIFFE)),
                                                    XFCC_HEADER: XFCC_ONE_HOP})
    assert r.json()["detail"]["reason"] == REF_TARGET_NO_PRINCIPAL


def test_config_defaults_to_xfcc_and_refuses_unknown_source(monkeypatch, gate_signing):
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    monkeypatch.setenv("GARGOYLE_TARGET_URL", TARGET_URL)
    monkeypatch.setenv("GARGOYLE_PUBLISHER_URL", "http://pub")
    monkeypatch.setenv("GARGOYLE_PINNED_ROOT_SHA256", anchor_sha256(reference_record_bytes()))
    monkeypatch.setenv("GARGOYLE_GATE_KEY_ID", gate_signing["key_id"])
    monkeypatch.setenv("GARGOYLE_GATE_PUBLIC_KEY_HEX",
                       gate_signing["public_key"].public_bytes(Encoding.Raw, PublicFormat.Raw).hex())
    for v in ("GARGOYLE_PRINCIPAL_SOURCE", "GARGOYLE_PRINCIPAL_HEADER"):
        monkeypatch.delenv(v, raising=False)
    assert config_from_env()["principal_source"] == "xfcc"
    monkeypatch.setenv("GARGOYLE_PRINCIPAL_SOURCE", "header")
    assert config_from_env()["principal_source"] == "header"
    monkeypatch.setenv("GARGOYLE_PRINCIPAL_SOURCE", "body")
    assert config_from_env() is None
