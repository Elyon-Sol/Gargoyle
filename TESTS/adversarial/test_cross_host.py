"""
Cross-host transport tests for Elyon-Sol (VL-039, T-G5-transport).

These tests derive from docs/restructure/08_enforcement_design.md section 6
(the G4/G5 boundary; reassert() reads local disk, a cross-host target needs a
published reference) and VL-039 Decisions B (loopback transport), B-prime-1
(pinned root hash), C (currency from the fetched record, not local disk), and
D-b (parameterize reassert()/verify_envelope() with record_source). Canon
basis per test docstring: section 11.9 (integrity-verifiable), section 13
(revalidation), section 8.2 (implementation-dependent anchoring), section 14
(non-executing).

The load-bearing proof (Decision C) is that the cross-host currency check
comes from the FETCHED, anchor-verified record and NOT from reassert()'s
local-disk reads. It is demonstrated at unit level by monkeypatching the
local-disk reads to diverge and showing that record_source overrides them
(the same divergence that, in the EVIDENCE runner
g5_cross_host_001_runner.py, is a genuinely-mutated target tree across two
real loopback processes).

Fixtures duplicate the build_envelope helpers from the other adversarial
test files per the established self-contained precedent. Per VL-039
constraint (i): no hash-value pinning; the pinned anchor is derived live from
the actual published_hashes.json bytes, and envelopes are built with a pinned
timestamp_utc.

Ledger: VL-039 (T-G5-transport; cross-host transport of the published record).
"""

import json

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.testclient import TestClient

from IMPLEMENTATION.envelope import (
    REASSERTED,
    RE_EVALUATE_REQUIRED,
    build_envelope,
    canonical_json,
    reassert,
)
from IMPLEMENTATION.evaluator import load_manifest, manifest_sha256
from IMPLEMENTATION.published_source import (
    anchor_sha256,
    fetch_published_record,
    load_record_from_bytes,
)
from IMPLEMENTATION.verifier import (
    ACCEPT_REASSERTED_AND_BOUND,
    REF_VERIFY_REASSERT_INVALIDATED,
    REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED,
    verify_envelope,
)


TARGET_URL = "http://127.0.0.1:9000/target"
PUBLISHED_HASHES_PATH = "EVIDENCE/published_hashes.json"

# The single new harness reason (parallels VL-038's
# REF_TARGET_PUBLISHED_RECORD_MISMATCH). A fetched record that fails the
# pinned anchor never becomes a trusted record_source.
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


def _build_valid_envelope(interaction=None, target_url=TARGET_URL,
                          timestamp_utc="2026-05-31T00:00:00+00:00"):
    if interaction is None:
        interaction = _normalized_interaction()
    return build_envelope(
        decision="ELIGIBLE",
        target_url=target_url,
        normalized_interaction=interaction,
        manifest=load_manifest(),
        ac3=True,
        t26=True,
        manifest_integrity=True,
        timestamp_utc=timestamp_utc,
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
      1. reads the X-Elyon-Sol-Envelope header (absent/unparseable -> absent);
      2. FETCHES the published record from the publisher and anchor-verifies
         it against the pinned root (Decision B-prime-1); a fetch/anchor
         failure refuses with REF_TARGET_ANCHOR_MISMATCH;
      3. runs verify_envelope(..., record_source=<fetched record>) so the
         currency check comes from the FETCHED record, not local disk
         (Decision C / D-b);
      4. honors (200, records) iff verify_envelope accepts.
    Returns (app, received).
    """
    app = FastAPI()
    received = []

    @app.post("/act")
    async def act(request: Request):
        interaction = await request.json()

        raw = request.headers.get("X-Elyon-Sol-Envelope")
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
# Decision C: currency comes from the fetched record, NOT local disk.
# ---------------------------------------------------------------------------


def test_reassert_currency_comes_from_record_not_local_disk(monkeypatch):
    """
    VL-039 Decision C + D-b. Canon section 13: revalidation against the
    current authority. The cross-host currency check must consult the
    fetched-and-anchor-verified record, not the target's local disk.

    Monkeypatch the local-disk evaluator read to a DIVERGENT hash (modeling
    a target whose local IMPLEMENTATION/evaluator.py differs from the
    publisher's). With record_source = the authentic record, reassert()
    REASSERTS (it consults the record's evaluator hash, which matches the
    envelope's pin). With NO record_source (the VL-038 local-disk path), the
    SAME envelope on the SAME divergent disk returns RE-EVALUATE-REQUIRED.
    The contrast is the proof that record_source is load-bearing: if the
    cross-host path still read local disk, the honor case would fail.
    """
    env = _build_valid_envelope()
    record = _published_record()

    # Target's local disk diverges from the publisher (mutated evaluator).
    monkeypatch.setattr(
        "IMPLEMENTATION.envelope._evaluator_sha256", lambda *a, **k: "0" * 64
    )

    # Cross-host: currency from the authentic record -> REASSERTED.
    assert reassert(env, record_source=record)["outcome"] == REASSERTED
    assert reassert(env, record_source=record)["ccs"] is True

    # VL-038-style local-disk path on the same divergent disk -> not honored.
    assert reassert(env)["outcome"] == RE_EVALUATE_REQUIRED


def test_verify_envelope_honors_valid_despite_divergent_local_disk(monkeypatch):
    """
    THE killer property at unit level (VL-039 session goal). A valid envelope
    built against the authentic evaluator is honored by a target whose local
    evaluator hash diverges, because verify_envelope consults the fetched
    record for currency (Decision C / D-b). The contrast (no record_source)
    rejects on the same divergent disk.
    """
    interaction = _normalized_interaction()
    env = _build_valid_envelope(interaction=interaction)
    record = _published_record()

    monkeypatch.setattr(
        "IMPLEMENTATION.envelope._evaluator_sha256", lambda *a, **k: "0" * 64
    )

    bound = verify_envelope(env, interaction, TARGET_URL, record_source=record)
    assert bound["accepted"] is True
    assert bound["reason"] == ACCEPT_REASSERTED_AND_BOUND

    local = verify_envelope(env, interaction, TARGET_URL)
    assert local["accepted"] is False
    assert local["reason"] == REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED


def test_verify_envelope_refuses_forged_despite_divergent_local_disk(monkeypatch):
    """
    The other half of the killer property: independence from local disk must
    not weaken forgery detection. A tampered envelope (request_context
    mutated without re-hashing decision_sha256) still fails reassert() Row 2
    integrity (canon section 12.3/12.4 fail-closed), which is pure over the
    envelope and unaffected by record_source. Refused even with the authentic
    record and a divergent local disk.
    """
    env = _build_valid_envelope()
    env["request_context"]["AP"] = ["identity", "role", "admin"]  # tamper, no rehash
    record = _published_record()
    monkeypatch.setattr(
        "IMPLEMENTATION.envelope._evaluator_sha256", lambda *a, **k: "0" * 64
    )
    result = verify_envelope(env, _normalized_interaction(), TARGET_URL, record_source=record)
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_REASSERT_INVALIDATED


# ---------------------------------------------------------------------------
# Decision B-prime-1: the pinned-root anchor.
# ---------------------------------------------------------------------------


def test_anchor_accepts_authentic_record_bytes():
    """
    Decision B-prime-1. load_record_from_bytes returns the parsed record iff
    the fetched bytes hash to the pinned root. Authentic bytes + correct
    pinned root -> the record dict.
    """
    record = load_record_from_bytes(_published_bytes(), _pinned_root())
    assert isinstance(record, dict)
    assert record["evaluator_sha256"] == _published_record()["evaluator_sha256"]


def test_anchor_refuses_wrong_pinned_root():
    """
    Decision B-prime-1 fail-closed. Authentic bytes but a wrong pinned root
    (the target was configured with a different anchor) -> None. The target
    must not trust a record it cannot anchor.
    """
    assert load_record_from_bytes(_published_bytes(), "0" * 64) is None


def test_anchor_refuses_tampered_record_bytes():
    """
    Decision B-prime-1 fail-closed. A record whose bytes were altered in
    transit no longer hashes to the pinned root -> None, regardless that it
    is still valid JSON. This is the transport-integrity check the anchor
    provides (A5-class tampering on the record hop; artifact 08 threat
    model).
    """
    tampered = _published_bytes().replace(b"0.9.8.4", b"9.9.9.9")
    assert tampered != _published_bytes()
    assert load_record_from_bytes(tampered, _pinned_root()) is None


# ---------------------------------------------------------------------------
# End-to-end cross-host over a served publisher (in-process loopback model).
# The genuinely-two-process, genuinely-mutated-disk demonstration is the
# EVIDENCE runner EVIDENCE/proofs/g5_cross_host_001_runner.py (constraint k).
# ---------------------------------------------------------------------------


def test_cross_host_target_honors_routed_valid_call():
    """
    End-to-end: a publisher serves the authentic record; a cross-host target
    fetches it (via the served bytes), anchor-verifies, and honors a valid
    envelope whose currency is checked against the FETCHED record. The
    fetch is wired through the publisher TestClient so this stays
    deterministic and network-free in pytest.
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
    resp = client.post(
        "/act",
        json=interaction,
        headers={"X-Elyon-Sol-Envelope": canonical_json(env)},
    )
    assert resp.status_code == 200
    assert resp.json()["honored"] is True
    assert resp.json()["reason"] == ACCEPT_REASSERTED_AND_BOUND
    assert len(received) == 1


def test_cross_host_target_refuses_when_fetched_record_fails_anchor():
    """
    The anchor doing its job end-to-end (Decision E required case). The
    publisher serves bytes that do NOT hash to the target's pinned root
    (modeling a substituted/forged record on the wire). The target refuses
    with REF_TARGET_ANCHOR_MISMATCH and does not act, before any envelope
    currency check.
    """
    forged_record_bytes = _published_bytes().replace(b"0.9.8.4", b"6.6.6.6")
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
    resp = client.post(
        "/act",
        json=interaction,
        headers={"X-Elyon-Sol-Envelope": canonical_json(env)},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == REF_TARGET_ANCHOR_MISMATCH
    assert received == []
