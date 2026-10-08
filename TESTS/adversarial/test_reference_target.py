"""
Reference enforcing-target tests for Elyon-Sol
(docs/restructure/12_g5_transport_design.md step 4).

These exercise IMPLEMENTATION/reference_target.py - the standalone, deployable
enforcing target that supersedes the target.py stub and promotes the in-process
scaffolding of TESTS/adversarial/test_cross_host.py
(_build_cross_host_target_app) and TESTS/adversarial/test_enforcement.py
(build_enforcing_target_app) into a real service.

The app is driven via TestClient with an injected config_provider (the
out-of-band pins) and an injected fetch (the published-record hop wired through
a publisher TestClient, so the suite stays deterministic and network-free; the
genuinely-two-process, real-socket, real-env-config demonstration is the
EVIDENCE runner EVIDENCE/proofs/g5_reference_target_001_runner.py).

The gate signing keypair comes from the autouse `gate_signing` conftest fixture;
envelopes are SIGNED with its private half because reference_target pins the gate
key, which makes verify_envelope require a signature (the signed path; the
production gate signs every default forward, VL-047).

Per VL-039 constraint (i): no hash-value pinning; the anchor is derived live
from the actual published_hashes.json bytes, and envelopes carry a pinned
timestamp_utc.

Ledger: VL-061 (T-G5-transport; artifact 12 step 4 reference enforcing target).
"""

import json
import uuid

from fastapi import FastAPI, Response
from fastapi.testclient import TestClient

from IMPLEMENTATION.envelope import build_envelope, canonical_json, sign_envelope
from IMPLEMENTATION.evaluator import load_manifest, manifest_sha256
from IMPLEMENTATION.published_source import anchor_sha256, load_record_from_bytes
from IMPLEMENTATION.reference_target import (
    REF_TARGET_ANCHOR_MISMATCH,
    REF_TARGET_NOT_CONFIGURED,
    build_reference_target_app,
)
from IMPLEMENTATION.verifier import (
    ACCEPT_REASSERTED_AND_BOUND,
    REF_VERIFY_BINDING_MISMATCH,
    REF_VERIFY_ENVELOPE_ABSENT,
    REF_VERIFY_SIGNATURE_INVALID,
    REF_VERIFY_REPLAY,
)


TARGET_URL = "http://127.0.0.1:9000/target"
OTHER_URL = "http://127.0.0.1:9000/other"
PUBLISHED_HASHES_PATH = "EVIDENCE/published_hashes.json"


# ---------------------------------------------------------------------------
# Fixtures (self-contained, per the established adversarial-test precedent)
# ---------------------------------------------------------------------------


def _published_bytes():
    with open(PUBLISHED_HASHES_PATH, "rb") as f:
        return f.read()


def _pinned_root():
    """The pinned anchor, derived live (constraint (i)): sha256 of the bytes."""
    return anchor_sha256(_published_bytes())


def _normalized_interaction(ap=None, op=None, context=None):
    return {
        "AP": ["identity", "role"] if ap is None else ap,
        "OP": ["session", "request"] if op is None else op,
        "context": {} if context is None else context,
        "expected_manifest_version": "1.0",
        "expected_manifest_sha256": manifest_sha256(),
    }


def _signed_envelope(gate_signing, interaction=None, target_url=TARGET_URL,
                     timestamp_utc="2026-06-08T00:00:00+00:00"):
    """Build then SIGN an envelope with the conftest gate key."""
    if interaction is None:
        interaction = _normalized_interaction()
    env = build_envelope(
        decision="ELIGIBLE",
        target_url=target_url,
        normalized_interaction=interaction,
        manifest=load_manifest(),
        ac3=True,
        t26=True,
        manifest_integrity=True,
        timestamp_utc=timestamp_utc,
    )
    return sign_envelope(env, gate_signing["private_key"], gate_signing["key_id"],
                         decision_id=uuid.uuid4().hex)


def _publisher_client(serve_bytes):
    app = FastAPI()

    @app.get("/published_hashes.json")
    async def published():
        return Response(content=serve_bytes, media_type="application/json")

    return TestClient(app)


def _fetch_via(pub_client):
    def fetch(url, pinned_root):
        resp = pub_client.get("/published_hashes.json")
        if resp.status_code != 200:
            return None
        return load_record_from_bytes(resp.content, pinned_root)
    return fetch


def _make_target(gate_signing, target_url=TARGET_URL, serve_bytes=None, replay_cache=None):
    """Build the reference target with injected config + fetch. Returns (app, client)."""
    if serve_bytes is None:
        serve_bytes = _published_bytes()
    config = {
        "target_url": target_url,
        "publisher_url": "http://publisher.test/published_hashes.json",
        "pinned_root_sha256": _pinned_root(),
        "pinned_public_keys": {
            gate_signing["key_id"]: gate_signing["public_key"]
        },
    }
    app = build_reference_target_app(
        config_provider=lambda: config,
        fetch=_fetch_via(_publisher_client(serve_bytes)),
        replay_cache=replay_cache,
    )
    return app, TestClient(app)


def _post(client, interaction, envelope=None):
    headers = {}
    if envelope is not None:
        headers["X-Elyon-Sol-Envelope"] = canonical_json(envelope)
    return client.post("/target", json=interaction, headers=headers)


# ---------------------------------------------------------------------------
# Honor: a valid, signed, current, bound routed call is honored and acted on.
# ---------------------------------------------------------------------------


def test_reference_target_honors_valid_signed_routed_call(gate_signing):
    app, client = _make_target(gate_signing)
    interaction = _normalized_interaction()
    env = _signed_envelope(gate_signing, interaction=interaction)
    resp = _post(client, interaction, env)
    assert resp.status_code == 200
    assert resp.json()["honored"] is True
    assert resp.json()["reason"] == ACCEPT_REASSERTED_AND_BOUND
    assert len(app.state.received) == 1  # acted exactly once


# ---------------------------------------------------------------------------
# Refusals. Each asserts non-200 AND that the target did not act.
# ---------------------------------------------------------------------------


def test_reference_target_refuses_absent_envelope_a1(gate_signing):
    """A1: a direct, un-attested caller (no header) is refused by the target's
    own policy, not by the gate."""
    app, client = _make_target(gate_signing)
    resp = _post(client, _normalized_interaction(), envelope=None)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == REF_VERIFY_ENVELOPE_ABSENT
    assert app.state.received == []


def test_reference_target_refuses_keyless_forge(gate_signing):
    """The VL-039-follow-up-2 keyless forge: an envelope with the signature
    stripped. The signed path (pinned key) rejects it."""
    app, client = _make_target(gate_signing)
    env = _signed_envelope(gate_signing)
    forge = {k: v for k, v in env.items() if k != "issuer_signature"}
    resp = _post(client, _normalized_interaction(), forge)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == REF_VERIFY_SIGNATURE_INVALID
    assert app.state.received == []


def test_reference_target_refuses_tampered_signed_envelope_a2(gate_signing):
    """A2: a signed envelope whose request_context is mutated after signing.
    The mutation is inside the signed region, so signature verification fails."""
    app, client = _make_target(gate_signing)
    env = _signed_envelope(gate_signing)
    env["request_context"]["AP"] = ["identity", "role", "admin"]  # tamper post-sign
    resp = _post(client, _normalized_interaction(), env)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == REF_VERIFY_SIGNATURE_INVALID
    assert app.state.received == []


def test_reference_target_refuses_replay_binding_mismatch_a3(gate_signing):
    """A3: a genuine signed envelope for interaction X delivered alongside a
    different live interaction Y. The binding check refuses."""
    app, client = _make_target(gate_signing)
    interaction_x = _normalized_interaction(ap=["identity", "role"])
    env = _signed_envelope(gate_signing, interaction=interaction_x)
    interaction_y = _normalized_interaction(ap=["identity", "role", "admin"])
    resp = _post(client, interaction_y, env)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == REF_VERIFY_BINDING_MISMATCH
    assert app.state.received == []


def test_reference_target_refuses_target_url_swap(gate_signing):
    """A signed envelope bound to a different target_url than this target
    serves. target_url is inside the signed region; the binding refuses."""
    app, client = _make_target(gate_signing, target_url=TARGET_URL)
    env = _signed_envelope(gate_signing, target_url=OTHER_URL)
    resp = _post(client, _normalized_interaction(), env)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == REF_VERIFY_BINDING_MISMATCH
    assert app.state.received == []


def test_reference_target_refuses_record_failing_anchor(gate_signing):
    """The publisher serves bytes that do not hash to the pinned anchor
    (substituted / tampered record on the wire). fetch returns None -> the
    target refuses before any currency check."""
    tampered = _published_bytes().replace(b"0.9.8.4", b"6.6.6.6")
    assert tampered != _published_bytes()
    app, client = _make_target(gate_signing, serve_bytes=tampered)
    env = _signed_envelope(gate_signing)
    resp = _post(client, _normalized_interaction(), env)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == REF_TARGET_ANCHOR_MISMATCH
    assert app.state.received == []


def test_reference_target_fails_closed_when_unconfigured(gate_signing):
    """Incomplete out-of-band configuration -> the target fails closed per
    request rather than acting on an unconfigured trust base."""
    app = build_reference_target_app(
        config_provider=lambda: None,
        fetch=_fetch_via(_publisher_client(_published_bytes())),
    )
    client = TestClient(app)
    env = _signed_envelope(gate_signing)
    resp = _post(client, _normalized_interaction(), env)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == REF_TARGET_NOT_CONFIGURED
    assert app.state.received == []


def test_reference_target_received_endpoint_reflects_acted_count(gate_signing):
    """The read-only /received observability endpoint reports the acted-on count:
    0 before any honored call, 1 after one. This is what a multi-process /
    real-transport runner reads to confirm an honor verdict over a real socket
    without redelivering the envelope (it is not part of the admission policy)."""
    app, client = _make_target(gate_signing)
    assert client.get("/received").json()["count"] == 0
    interaction = _normalized_interaction()
    env = _signed_envelope(gate_signing, interaction=interaction)
    assert _post(client, interaction, env).status_code == 200
    assert client.get("/received").json()["count"] == 1


def test_reference_target_refuses_replay(gate_signing):
    """Exactly-once over the freshness window: the SAME admitted envelope (same
    decision_id) honored once, then refused on replay; acted exactly once."""
    app, client = _make_target(gate_signing)
    interaction = _normalized_interaction()
    env = _signed_envelope(gate_signing, interaction=interaction)
    first = _post(client, interaction, env)
    assert first.status_code == 200
    second = _post(client, interaction, env)  # exact replay -> same decision_id
    assert second.status_code == 403
    assert second.json()["detail"]["reason"] == REF_VERIFY_REPLAY
    assert len(app.state.received) == 1


def test_reference_target_decision_id_is_signed(gate_signing):
    """decision_id is inside the signed region: mutating it breaks the signature."""
    app, client = _make_target(gate_signing)
    interaction = _normalized_interaction()
    env = _signed_envelope(gate_signing, interaction=interaction)
    env["decision_id"] = "tampered-id"
    resp = _post(client, interaction, env)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == REF_VERIFY_SIGNATURE_INVALID
    assert app.state.received == []


def test_shared_replay_cache_cross_instance(gate_signing):
    """B3 wired (VL-094): two target instances sharing one ReplayCache enforce exactly-once across
    them - a decision_id honored on instance A is refused REF_VERIFY_REPLAY on instance B. (One
    shared InMemoryReplayCache object is the in-process analog of a shared Redis store.)"""
    from IMPLEMENTATION.replay_cache import InMemoryReplayCache

    shared = InMemoryReplayCache()
    _, client_a = _make_target(gate_signing, replay_cache=shared)
    _, client_b = _make_target(gate_signing, replay_cache=shared)
    interaction = _normalized_interaction()
    env = _signed_envelope(gate_signing, interaction)

    r1 = _post(client_a, interaction, env)
    assert r1.status_code == 200, r1.text                       # honored on instance A

    r2 = _post(client_b, interaction, env)                      # SAME envelope, instance B
    assert r2.status_code == 403
    assert r2.json()["detail"]["reason"] == REF_VERIFY_REPLAY   # cross-instance replay caught


def test_reference_target_refuses_duplicate_envelope_header_p01(gate_signing):
    """P-01: a VALID envelope presented as a DUPLICATE header is treated as absent
    (fail closed), not first-wins honored. Fails if the envelope guard is reverted."""
    app, client = _make_target(gate_signing)
    interaction = _normalized_interaction()
    env = _signed_envelope(gate_signing, interaction=interaction)
    body = canonical_json(env)
    resp = client.post("/target", json=interaction,
                       headers=[("X-Elyon-Sol-Envelope", body), ("X-Elyon-Sol-Envelope", body)])
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == REF_VERIFY_ENVELOPE_ABSENT
    assert app.state.received == []
