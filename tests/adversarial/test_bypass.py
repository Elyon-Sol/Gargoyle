"""
The bypass Gargoyle cannot close by itself: a caller that never asks the
issuer for a receipt and calls the target directly.

Nothing on the issuer side can stop a call it never sees. The only defense
is a target that refuses any call without a verifiable receipt. These tests
pass on purpose: the first shows a naive target acting on a direct call with
no receipt, the second shows that a target running the verifier would refuse
it. The verifier is necessary, not sufficient: it lets a target refuse
unattested calls, but it cannot force callers or targets to use it.
"""

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from reference import reference_policy
from gargoyle.verifier import (
    REF_VERIFY_ENVELOPE_ABSENT,
    verify_envelope,
)


# A naive target: it records what it receives and applies no admission
# check of its own.
target_app = FastAPI()
_received = []


@target_app.post("/target")
async def target(request: Request):
    body = await request.json()
    _received.append(body)
    return {"ok": True}


target_client = TestClient(target_app)


def test_direct_to_target_reaches_target_with_no_envelope():
    """
    A caller that skips the issuer reaches a naive target directly: the target
    acts and nothing attests the call was authorized.
    """
    _received.clear()
    interaction = {"tool": "transfer", "args": {"amount": 5}, "principal": "agent-7"}
    response = target_client.post("/target", json=interaction)

    assert response.status_code == 200
    # The target acted on the call ...
    assert len(_received) == 1
    # ... and nothing attests the call was authorized.
    assert "envelope" not in _received[0]


def test_target_side_verifier_would_reject_unattested_call():
    """
    The same direct call checked by verify_envelope is refused with
    REF_VERIFY_ENVELOPE_ABSENT. The defense works only if the target runs it.
    """
    interaction = {"tool": "transfer", "args": {"amount": 5}, "principal": "agent-7"}
    result = verify_envelope(None, interaction, "http://127.0.0.1:9000/target",
                             pinned_public_keys={}, policy=reference_policy())
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_ENVELOPE_ABSENT
