"""Second review, finding 6: the state text an approver reads must be the
bytes the bound state hash names."""

import hashlib
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from gargoyle.issuer_service import REF_ISSUER_STATE_TEXT_MISMATCH, build_issuer_app
from gargoyle.jws import encode
from gargoyle.policy import ELIGIBLE, Decision
from gargoyle.state import describe, state_sha256, text_consistent

issuer, idp = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
PIN = {"policy_id": "p/1", "policy_sha256": "a" * 64}


class Hold:
    def pin(self): return PIN
    def decide(self, target_url, interaction): return Decision(ELIGIBLE, None, True)


def test_text_must_be_the_hashed_bytes():
    good = describe("C:\\proj\\a.md", "hello\n".encode("utf-8"))
    assert text_consistent(good) and text_consistent({k: v for k, v in good.items() if k != "text"})
    assert not text_consistent(dict(good, text="hello"))                       # a different text
    assert not text_consistent(dict(good, size=99))
    assert not text_consistent({"ref": "x", "sha256": None, "size": None, "text": "ghost"})   # text for a file that does not exist
    assert not text_consistent(dict(good, text="\udc80"))                      # not UTF-8 text at all
    # UTF-8 round-trips, so a text file's decoded content always passes.
    data = "caf\u00e9 \u2014 \U0001F600\n".encode("utf-8")
    assert text_consistent(describe("f", data))


def test_issuer_refuses_state_text_that_does_not_hash_to_the_state():
    c = TestClient(build_issuer_app(policy=Hold(), signing_key=issuer, key_id="issuer-1", idp_public_keys={"idp-1": idp.public_key()}))
    h = {"Authorization": "Bearer " + encode({"sub": "agent@contoso.com", "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())}, idp, "idp-1")}
    state = describe("C:\\proj\\a.md", b"old\n")
    body = {"target_url": "mcp://fs", "tool": "write_file", "args": {"path": "C:\\proj\\a.md", "content": "new"}, "state": state}
    r = c.post("/issue", json=body, headers=h).json()
    assert r["issued"] and r["envelope"]["request_context"]["state_sha256"] == state_sha256(state)
    forged = dict(state, text="what the approver should think is there\n")
    r = c.post("/issue", json=dict(body, state=forged), headers=h)
    assert r.status_code == 400 and r.json()["detail"]["reason"] == REF_ISSUER_STATE_TEXT_MISMATCH
    # The approver sees the verified text, never the forged one.
    listed = c.get("/pending", headers=h).json()["pending"]
    assert [x["state"]["text"] for x in listed] == ["old\n"]
