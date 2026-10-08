"""Gargoyle staging fixtures.

Same contract as the original `gate_signing` fixture (an ephemeral Ed25519
keypair per test, never written to disk) minus the gate module: the staged
tree has no pep.py, so nothing is monkeypatched. Tests that need a key ask
for `gate_signing` by name and sign with it directly.
"""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

GATE_TEST_KEY_ID = "gate-test-ed25519-001"


def pytest_configure(config):
    config.addinivalue_line("markers", "no_gate_key: no gate key configured (kept for marker compatibility).")


@pytest.fixture(autouse=True)
def _allow_private_targets(monkeypatch):
    monkeypatch.setenv("GARGOYLE_ALLOW_PRIVATE_TARGETS", "1")
    yield


@pytest.fixture
def gate_signing(request):
    if "no_gate_key" in request.keywords:
        yield None
        return
    priv = Ed25519PrivateKey.generate()
    yield {"public_key": priv.public_key(), "key_id": GATE_TEST_KEY_ID, "private_key": priv}
