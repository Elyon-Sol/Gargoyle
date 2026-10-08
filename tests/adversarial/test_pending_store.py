"""Pending-approval stores: a hold is consumed exactly once, only for its own
decision, and only before it expires.

Two issuing-service instances are modeled as two call sites that do or do not
share a store. A wrong-decision consume returns False and burns nothing, so
a probe cannot destroy a legitimate hold. A multi-instance deployment without
a shared store refuses to start.
"""

from datetime import datetime, timezone, timedelta

import pytest

from gargoyle.pending_store import (
    InMemoryPendingApprovals,
    ExternalStorePendingApprovals,
    RedisPendingStore,
    PendingApprovals,
    PendingStore,
    pending_store_from_env,
)

DS_A = "decision-sha-A"
DS_B = "decision-sha-B"


# ---------------------------------------------------------------------------
# InMemoryPendingApprovals
# ---------------------------------------------------------------------------

def test_in_memory_consume_once_then_unknown():
    p = InMemoryPendingApprovals()
    p.issue("r1", DS_A)
    assert p.check_and_consume("r1", DS_A) is True     # first: honor
    assert p.check_and_consume("r1", DS_A) is False    # already consumed: refuse


def test_in_memory_unknown_request_refused():
    p = InMemoryPendingApprovals()
    assert p.check_and_consume("never-issued", DS_A) is False


def test_in_memory_wrong_decision_refused_and_not_consumed():
    # A consume bound to a DIFFERENT decision must fail AND leave the real slot.
    p = InMemoryPendingApprovals()
    p.issue("r1", DS_A)
    assert p.check_and_consume("r1", DS_B) is False     # mismatch: refuse
    assert p.check_and_consume("r1", DS_A) is True      # slot survived -> honor


# ---------------------------------------------------------------------------
# Separate sets miss a cross-instance consume; a shared store catches it
# ---------------------------------------------------------------------------

def test_separate_in_memory_sets_miss_cross_instance():
    # A hold issued on instance A is unknown to instance B's own set.
    a = InMemoryPendingApprovals()
    b = InMemoryPendingApprovals()
    a.issue("r1", DS_A)
    assert b.check_and_consume("r1", DS_A) is False     # B never saw it


def test_shared_in_memory_set_catches_cross_instance():
    shared = InMemoryPendingApprovals()
    shared.issue("r1", DS_A)                            # instance A issues
    assert shared.check_and_consume("r1", DS_A) is True # instance B consumes


# ---------------------------------------------------------------------------
# ExternalStorePendingApprovals over a fake shared store
# ---------------------------------------------------------------------------

class FakePendingStore:
    """In-memory stand-in for a cross-process store. One instance shared by every
    ExternalStorePendingApprovals models a single backend behind N processes.
    consume_if_matches is compare-AND-delete (a mismatch deletes nothing)."""

    def __init__(self):
        self._d = {}

    def put(self, request_id, decision_sha256, expiry, now):
        self._d[request_id] = decision_sha256

    def consume_if_matches(self, request_id, decision_sha256, now):
        if self._d.get(request_id) == decision_sha256:
            del self._d[request_id]
            return True
        return False


class RaisingPendingStore:
    def put(self, request_id, decision_sha256, expiry, now):
        pass

    def consume_if_matches(self, request_id, decision_sha256, now):
        raise ConnectionError("backend unreachable")


def test_external_store_consume_once_then_unknown():
    p = ExternalStorePendingApprovals(FakePendingStore())
    p.issue("r1", DS_A)
    assert p.check_and_consume("r1", DS_A) is True
    assert p.check_and_consume("r1", DS_A) is False


def test_external_store_shared_catches_cross_instance():
    store = FakePendingStore()
    a = ExternalStorePendingApprovals(store)            # process A
    b = ExternalStorePendingApprovals(store)            # process B
    a.issue("r1", DS_A)
    assert b.check_and_consume("r1", DS_A) is True      # shared -> visible
    assert a.check_and_consume("r1", DS_A) is False     # single-use across both


def test_external_store_wrong_decision_does_not_consume():
    store = FakePendingStore()
    a = ExternalStorePendingApprovals(store)
    a.issue("r1", DS_A)
    assert a.check_and_consume("r1", DS_B) is False      # mismatch
    assert a.check_and_consume("r1", DS_A) is True       # slot survived


def test_external_store_failure_propagates_fail_closed():
    p = ExternalStorePendingApprovals(RaisingPendingStore())
    with pytest.raises(ConnectionError):
        p.check_and_consume("r1", DS_A)


# ---------------------------------------------------------------------------
# RedisPendingStore: SET [EX] + Lua compare-and-delete, against a fake redis
# ---------------------------------------------------------------------------

class _FakeRedis:
    """Minimal in-memory Redis stand-in: SET (with optional ex) + EVAL of the
    compare-and-delete Lua (GET==ARGV -> DEL). One instance shared by N stores
    models a single Redis behind N processes."""

    def __init__(self):
        self._d = {}
        self.last_ex = "unset"

    def set(self, key, value, ex=None):
        self._d[key] = value if isinstance(value, bytes) else value.encode()
        self.last_ex = ex
        return True

    def eval(self, script, numkeys, key, arg):
        argb = arg if isinstance(arg, bytes) else arg.encode()
        if self._d.get(key) == argb:
            del self._d[key]
            return 1
        return 0


def test_redis_store_consume_once_then_unknown():
    p = ExternalStorePendingApprovals(RedisPendingStore(_FakeRedis()))
    p.issue("r1", DS_A)
    assert p.check_and_consume("r1", DS_A) is True
    assert p.check_and_consume("r1", DS_A) is False


def test_redis_store_shared_catches_cross_instance():
    shared = _FakeRedis()
    a = ExternalStorePendingApprovals(RedisPendingStore(shared))
    b = ExternalStorePendingApprovals(RedisPendingStore(shared))
    a.issue("r1", DS_A)
    assert b.check_and_consume("r1", DS_A) is True       # shared Redis -> visible
    assert a.check_and_consume("r1", DS_A) is False       # single-use across both


def test_redis_store_wrong_decision_leaves_entry():
    shared = _FakeRedis()
    a = ExternalStorePendingApprovals(RedisPendingStore(shared))
    a.issue("r1", DS_A)
    assert a.check_and_consume("r1", DS_B) is False        # Lua compare fails
    assert a.check_and_consume("r1", DS_A) is True         # entry survived


def test_redis_store_no_ttl_when_no_not_after():
    r = _FakeRedis()
    ExternalStorePendingApprovals(RedisPendingStore(r)).issue("r1", DS_A)
    assert r.last_ex is None


def test_redis_store_ttl_derived_from_not_after():
    r = _FakeRedis()
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    ExternalStorePendingApprovals(RedisPendingStore(r)).issue(
        "r1", DS_A, not_after=now + timedelta(seconds=90), now=now)
    assert r.last_ex == 90


# ---------------------------------------------------------------------------
# Implementations satisfy the protocols
# ---------------------------------------------------------------------------

def test_implementations_satisfy_protocols():
    assert isinstance(InMemoryPendingApprovals(), PendingApprovals)
    assert isinstance(ExternalStorePendingApprovals(FakePendingStore()), PendingApprovals)
    assert isinstance(FakePendingStore(), PendingStore)


# ---------------------------------------------------------------------------
# pending_store_from_env: default, and refusal to start multi-instance without a shared store
# ---------------------------------------------------------------------------

def test_from_env_defaults_to_in_memory(monkeypatch):
    monkeypatch.delenv("GARGOYLE_PENDING_REDIS_URL", raising=False)
    monkeypatch.delenv("GARGOYLE_REPLAY_MULTI_INSTANCE", raising=False)
    assert isinstance(pending_store_from_env(), InMemoryPendingApprovals)


def test_from_env_multi_instance_without_store_fails_closed(monkeypatch):
    # A declared multi-instance deployment with no shared pending store must
    # refuse at startup, not hand back a per-process set.
    monkeypatch.delenv("GARGOYLE_PENDING_REDIS_URL", raising=False)
    monkeypatch.setenv("GARGOYLE_REPLAY_MULTI_INSTANCE", "1")
    with pytest.raises(RuntimeError):
        pending_store_from_env()


def test_from_env_multi_instance_with_store_ok(monkeypatch):
    # With a shared store declared, the guard passes and a shared adapter is built.
    monkeypatch.setenv("GARGOYLE_PENDING_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("GARGOYLE_REPLAY_MULTI_INSTANCE", "1")
    # from_url imports redis lazily; stub it, since only the guard is under test.
    import gargoyle.pending_store as ps
    monkeypatch.setattr(ps.RedisPendingStore, "from_url",
                        classmethod(lambda cls, url: object()))
    out = ps.pending_store_from_env()
    assert isinstance(out, ExternalStorePendingApprovals)


# ---------------------------------------------------------------------------
# Hold TTL: an unexpired hold is honored, an expired one is refused and dropped,
# and expired holds are pruned so the set stays bounded.
# ---------------------------------------------------------------------------

def test_in_memory_expired_hold_refused_and_dropped():
    p = InMemoryPendingApprovals()
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    p.issue("r1", DS_A, not_after=t0 + timedelta(seconds=60), now=t0)
    assert p.check_and_consume("r1", DS_A, now=t0 + timedelta(seconds=60)) is False
    assert len(p) == 0  # dropped on the expired consume, not left behind


def test_in_memory_unexpired_hold_honored_once():
    p = InMemoryPendingApprovals()
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    p.issue("r1", DS_A, not_after=t0 + timedelta(seconds=60), now=t0)
    assert p.check_and_consume("r1", DS_A, now=t0 + timedelta(seconds=59)) is True
    assert p.check_and_consume("r1", DS_A, now=t0 + timedelta(seconds=59)) is False


def test_in_memory_issue_prunes_expired_holds():
    """Each unanswered hold is one entry; without pruning, anyone able to
    trigger holds grows the set forever. Issuing prunes everything expired."""
    p = InMemoryPendingApprovals()
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for i in range(50):
        p.issue(f"old-{i}", DS_A, not_after=t0 + timedelta(seconds=10), now=t0)
    assert len(p) == 50
    p.issue("new", DS_B, not_after=t0 + timedelta(seconds=70), now=t0 + timedelta(seconds=60))
    assert len(p) == 1
    assert p.check_and_consume("new", DS_B, now=t0 + timedelta(seconds=61)) is True


def test_in_memory_no_not_after_keeps_entry_until_consumed():
    p = InMemoryPendingApprovals()
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    p.issue("r1", DS_A, now=t0)
    assert p.check_and_consume("r1", DS_A, now=t0 + timedelta(days=365)) is True
