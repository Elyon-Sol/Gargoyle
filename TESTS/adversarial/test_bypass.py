"""
Honest A1-bypass demonstration for Elyon-Sol (VL-037).

Adversary A1 (the declining caller) per
docs/restructure/08_enforcement_design.md section 4.4 and
docs/restructure/04_current_vs_claimed.md G4 ("The gate is opt-in. A
caller can hit the target directly and bypass it"). No delivery or
verification mechanism the gate provides closes A1, because the gate
never sees a call that never routes through it. A1 is closeable only by
a target-side policy that refuses any call lacking a verifiable
decision.

These are PASSING tests that assert the bypass exists; they are not
xfail. The first demonstrates reachability (a direct call lands at the
target with no envelope); the second shows the only available defense
(a target running the verifier would reject the un-attested call),
which is precisely why the verifier is necessary-but-not-sufficient:
it makes routed calls verifiable but cannot force a caller to route.

Per VL-037 opener Decision E. Ledger: VL-037.
"""

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from IMPLEMENTATION.verifier import (
    REF_VERIFY_ENVELOPE_ABSENT,
    verify_envelope,
)


# A minimal stand-in for an upstream target service. It records what it
# receives. It applies NO admission policy of its own - it is the naive
# target that A1 exploits.
target_app = FastAPI()
_received = []


@target_app.post("/target")
async def target(request: Request):
    body = await request.json()
    _received.append(body)
    return {"ok": True}


target_client = TestClient(target_app)


def test_a1_direct_to_target_reaches_target_with_no_envelope():
    """
    Artifact 08 section 4.4 / 04 G4: a caller that never routes through
    the PEP reaches the target directly. The forwarded body carries only
    the interaction; no envelope is present, and the gate has no
    mechanism to interpose on a call it never sees.

    This is the bypass, demonstrated honestly: the target receives the
    call and there is no decision artifact attached.
    """
    _received.clear()
    interaction = {
        "AP": ["identity", "role"],
        "OP": ["session", "request"],
        "context": {},
        "expected_manifest_version": "1.0",
        "expected_manifest_sha256": "0" * 64,
    }
    response = target_client.post("/target", json=interaction)

    assert response.status_code == 200
    # The target acted on the call ...
    assert len(_received) == 1
    # ... and nothing attests it came through the gate.
    assert "envelope" not in _received[0]


def test_a1_target_side_verifier_would_reject_unattested_call():
    """
    Artifact 08 section 4.4: A1 is closeable only by a target-side
    policy refusing un-attested calls. If the naive target above ran the
    verifier on the direct call, the (absent) envelope would be
    rejected. This documents the verifier as necessary-but-not-
    sufficient: it can equip a target to refuse A1, but it cannot compel
    the caller to route or compel the target to run it.

    The direct call carries no envelope (None); verify_envelope rejects
    with REF_VERIFY_ENVELOPE_ABSENT.
    """
    interaction = {
        "AP": ["identity", "role"],
        "OP": ["session", "request"],
        "context": {},
        "expected_manifest_version": "1.0",
        "expected_manifest_sha256": "0" * 64,
    }
    result = verify_envelope(None, interaction, "http://127.0.0.1:9000/target")
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_ENVELOPE_ABSENT
