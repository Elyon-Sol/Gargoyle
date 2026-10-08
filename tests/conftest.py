"""Shared test fixtures.

`gate_signing` gives a test an ephemeral Ed25519 issuer keypair, created per
test and never written to disk. Tests that need a key request it by name and
sign with it directly. The autouse fixture lets tests target loopback URLs.
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
