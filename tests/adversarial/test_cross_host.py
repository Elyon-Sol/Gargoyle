"""
Cross-host tests: a target on another host checks receipts against a fetched,
anchor-verified published record, not against its own local policy state.

The target pins one anchor out of band: the SHA-256 of the published record's
bytes. A fetched record that does not hash to the anchor is never trusted.
The key property is that the policy-pin check uses the fetched record. The
tests show it by making the target's local policy pin diverge and checking
that a record_source overrides it.

The anchor is computed from the committed EVIDENCE/published_hashes.json
bytes, and receipts use a fixed timestamp_utc.
"""

import json

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.testclient import TestClient

from gargoyle.policy import ManifestPolicy
from gargoyle.envelope import (
    REASSERTED,
    RE_EVALUATE_REQUIRED,
    build_envelope,
    canonical_json,
    reassert,
)
from gargoyle.policy import MANIFEST_POLICY_ID
from gargoyle.published_source import (
    anchor_sha256,
    fetch_published_record,
    load_record_from_bytes,
)
from gargoyle.verifier import (
    ACCEPT_REASSERTED_AND_BOUND,
    REF_VERIFY_REASSERT_INVALIDATED,
    REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED,
    verify_envelope,
)


TARGET_URL = "http://127.0.0.1:9000/target"
PUBLISHED_HASHES_PATH = "EVIDENCE/published_hashes.json"

# A fetched record that fails the pinned anchor never becomes a trusted
# record_source; the target refuses with this reason.
REF_TARGET_ANCHOR_MISMATCH = "REF_TARGET_ANCHOR_MISMATCH"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _published_bytes():
    """The authentic published record bytes, as committed on disk."""
    with open(PUBLISHED_HASHES_PATH, "rb") as f:
        return f.read()


def _published_record():
    return json.loads(_published_bytes())


def _pinned_root():
    """The pinned anchor: the SHA-256 of the record bytes."""
    return anchor_sha256(_published_bytes())


PRINCIPAL_HEADER = "X-Peer"  # stands in for the front proxy's identity header


def _normalized_interaction(tool="transfer", args=None, principal="agent-7"):
    return {
        "tool": tool,
        "args": {"amount": 5} if args is None else args,
        "principal": principal,
    }


def _build_valid_envelope(interaction=None, target_url=TARGET_URL,
                          timestamp_utc="2026-05-31T00:00:00+00:00"):
    if interaction is None:
        interaction = _normalized_interaction()
    return build_envelope(
        policy_pin=ManifestPolicy().pin(),
        decision="ELIGIBLE",
        target_url=target_url,
        call=interaction,
        timestamp_utc=timestamp_utc,
    )


def _post_call(client, path, call, env):
    """POST tool and args as the body, the principal as the proxy header."""
    return client.post(
        path,
        json={"tool": call["tool"], "args": call["args"]},
        headers={"X-Gargoyle-Envelope": canonical_json(env),
                 PRINCIPAL_HEADER: call["principal"]},
    )


def _build_publisher_app(serve_bytes):
    """A minimal publisher serving the record bytes (deployment infra)."""
    app = FastAPI()

    @app.get("/published_hashes.json")
    async def published():
        return Response(content=serve_bytes, media_type="application/json")

    return app


def _build_cross_host_target_app(publisher_base, pinned_root, fetch=fetch_published_record,
                                 expected_target_url=TARGET_URL):
    """
    A cross-host enforcing target. On each call it:
      1. reads the X-Gargoyle-Envelope header (absent or unparseable -> absent);
      2. fetches the published record and anchor-verifies it; a fetch or anchor
         failure refuses with REF_TARGET_ANCHOR_MISMATCH;
      3. runs verify_envelope(..., record_source=<fetched record>), so the policy
         pin is checked against the fetched record, not local state;
      4. honors the call (200, recorded) only if verify_envelope accepts.
    Returns (app, received).
    """
    app = FastAPI()
    received = []

    @app.post("/act")
    async def act(request: Request):
        body = await request.json()
        # The principal is what the target authenticated (here: the proxy
        # header), never a field of the body.
        interaction = {"tool": body["tool"], "args": body["args"],
                       "principal": request.headers.get(PRINCIPAL_HEADER)}

        raw = request.headers.get("X-Gargoyle-Envelope")
        envelope = None
        if raw is not None:
            try:
                envelope = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                envelope = None

        record = fetch(publisher_base + "/published_hashes.json", pinned_root)
        if record is None:
            raise HTTPException(
                status_code=403,
                detail={"honored": False, "reason": REF_TARGET_ANCHOR_MISMATCH},
            )

        result = verify_envelope(
            envelope, interaction, expected_target_url, record_source=record
        )
        if not result["accepted"]:
            raise HTTPException(
                status_code=403,
                detail={"honored": False, "reason": result["reason"]},
            )
        received.append(interaction)
        return {"honored": True, "reason": result["reason"]}

    return app, received


# ---------------------------------------------------------------------------
# Currency comes from the fetched record, not local state.
# ---------------------------------------------------------------------------


def test_reassert_currency_comes_from_record_not_local_disk(monkeypatch):
    """
    With the target's local policy pin made to diverge, reassert() with the
    authentic record as record_source still returns REASSERTED, while the same
    receipt with no record_source returns RE-EVALUATE-REQUIRED. The contrast
    shows the fetched record, not local state, decides currency.
    """
    env = _build_valid_envelope()
    record = _published_record()

    # The target's local policy pin diverges from the published one.
    monkeypatch.setattr(
        "gargoyle.policy.ManifestPolicy.pin",
        lambda self: {"policy_id": MANIFEST_POLICY_ID, "policy_sha256": "0" * 64},
    )

    # Cross-host: currency from the authentic record -> REASSERTED.
    assert reassert(env, record_source=record)["outcome"] == REASSERTED

    # Local-state path with the same divergence -> not honored.
    assert reassert(env)["outcome"] == RE_EVALUATE_REQUIRED


def test_verify_envelope_honors_valid_despite_divergent_local_disk(monkeypatch):
    """
    A valid receipt is honored by a target whose local policy pin diverges,
    because verify_envelope checks currency against the fetched record. Without
    a record_source the same receipt is refused.
    """
    interaction = _normalized_interaction()
    env = _build_valid_envelope(interaction=interaction)
    record = _published_record()

    monkeypatch.setattr(
        "gargoyle.policy.ManifestPolicy.pin",
        lambda self: {"policy_id": MANIFEST_POLICY_ID, "policy_sha256": "0" * 64},
    )

    bound = verify_envelope(env, interaction, TARGET_URL, record_source=record)
    assert bound["accepted"] is True
    assert bound["reason"] == ACCEPT_REASSERTED_AND_BOUND

    local = verify_envelope(env, interaction, TARGET_URL)
    assert local["accepted"] is False
    assert local["reason"] == REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED


def test_verify_envelope_refuses_forged_despite_divergent_local_disk(monkeypatch):
    """
    Using the fetched record must not weaken tamper detection. A receipt whose
    request_context was changed without re-hashing fails the integrity check
    whatever the record or local state says.
    """
    env = _build_valid_envelope()
    env["request_context"]["tool"] = "delete_database"  # tamper, no rehash
    record = _published_record()
    monkeypatch.setattr(
        "gargoyle.policy.ManifestPolicy.pin",
        lambda self: {"policy_id": MANIFEST_POLICY_ID, "policy_sha256": "0" * 64},
    )
    result = verify_envelope(env, _normalized_interaction(), TARGET_URL, record_source=record)
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_REASSERT_INVALIDATED


# ---------------------------------------------------------------------------
# The pinned record anchor.
# ---------------------------------------------------------------------------


def test_anchor_accepts_authentic_record_bytes():
    """
    load_record_from_bytes returns the parsed record when the bytes hash to the
    pinned anchor.
    """
    record = load_record_from_bytes(_published_bytes(), _pinned_root())
    assert isinstance(record, dict)
    assert record["policy_sha256"] == _published_record()["policy_sha256"]


def test_anchor_refuses_wrong_pinned_root():
    """
    Authentic bytes with the wrong pinned anchor return None: a target must not
    trust a record it cannot anchor.
    """
    assert load_record_from_bytes(_published_bytes(), "0" * 64) is None


def test_anchor_refuses_tampered_record_bytes():
    """
    A record altered in transit no longer hashes to the anchor and returns None,
    even though it is still valid JSON.
    """
    tampered = _published_bytes().replace(b"manifest-subset/1", b"manifest-subset/9")
    assert tampered != _published_bytes()
    assert load_record_from_bytes(tampered, _pinned_root()) is None


# ---------------------------------------------------------------------------
# End to end over a served publisher (in-process).
# ---------------------------------------------------------------------------


def test_cross_host_target_honors_routed_valid_call():
    """
    End to end: a publisher serves the authentic record, the target fetches and
    anchor-verifies it, and honors a valid receipt checked against that record.
    The fetch goes through a TestClient, so the test needs no network.
    """
    pub_client = TestClient(_build_publisher_app(_published_bytes()))

    def fetch_via_testclient(url, pinned_root):
        resp = pub_client.get("/published_hashes.json")
        if resp.status_code != 200:
            return None
        return load_record_from_bytes(resp.content, pinned_root)

    target_app, received = _build_cross_host_target_app(
        "http://publisher.test", _pinned_root(), fetch=fetch_via_testclient
    )
    client = TestClient(target_app)

    interaction = _normalized_interaction()
    env = _build_valid_envelope(interaction=interaction)
    resp = _post_call(client, "/act", interaction, env)
    assert resp.status_code == 200
    assert resp.json()["honored"] is True
    assert resp.json()["reason"] == ACCEPT_REASSERTED_AND_BOUND
    assert len(received) == 1


def test_cross_host_target_refuses_when_fetched_record_fails_anchor():
    """
    The publisher serves bytes that do not hash to the target's anchor, modeling
    a substituted record. The target refuses with REF_TARGET_ANCHOR_MISMATCH and
    does not act, before checking any receipt.
    """
    forged_record_bytes = _published_bytes().replace(b"manifest-subset/1", b"manifest-subset/9")
    pub_client = TestClient(_build_publisher_app(forged_record_bytes))

    def fetch_via_testclient(url, pinned_root):
        resp = pub_client.get("/published_hashes.json")
        if resp.status_code != 200:
            return None
        return load_record_from_bytes(resp.content, pinned_root)

    target_app, received = _build_cross_host_target_app(
        "http://publisher.test", _pinned_root(), fetch=fetch_via_testclient
    )
    client = TestClient(target_app)

    interaction = _normalized_interaction()
    env = _build_valid_envelope(interaction=interaction)
    resp = _post_call(client, "/act", interaction, env)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == REF_TARGET_ANCHOR_MISMATCH
    assert received == []
