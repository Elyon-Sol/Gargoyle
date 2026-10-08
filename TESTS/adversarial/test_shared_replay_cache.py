"""
Shared-replay-cache seam tests
(docs/restructure/16_shared_replay_cache_spec.md, increment VL-076, B3).

These exercise IMPLEMENTATION/replay_cache.py - the seam that lets the in-window
exactly-once replay defense (VL-066) be backed by a cross-instance store instead
of the per-process inline `app.state.seen` dict in reference_target.py. The seam
is introduced with NO caller (build-then-wire); reference_target.py is unchanged,
so these tests drive the cache directly at the seam, simulating two target
"instances" as two call sites that share - or do not share - a cache.

The load-bearing properties:
- InMemoryReplayCache is behavior-identical to the VL-066 inline dict.
- Two SEPARATE in-memory caches MISS a cross-instance replay (the gap B3 names);
  ONE SHARED cache CATCHES it (the seam's point).
- ExternalStoreReplayCache over a shared store catches it across instances, and
  fails CLOSED (propagates) when the store cannot decide.
"""

from datetime import datetime, timezone, timedelta

import pytest

from IMPLEMENTATION.replay_cache import (
    InMemoryReplayCache,
    ExternalStoreReplayCache,
    ReplayCache,
    ReplayStore,
    RedisReplayStore,
    replay_cache_from_env,
)


def _future(seconds=3600):
    return datetime.now(timezone.utc) + timedelta(seconds=seconds)


def _past(seconds=3600):
    return datetime.now(timezone.utc) - timedelta(seconds=seconds)


# ---------------------------------------------------------------------------
# InMemoryReplayCache: behavior-identical to the VL-066 inline dict
# ---------------------------------------------------------------------------

def test_in_memory_honors_once_then_refuses_exact_replay():
    cache = InMemoryReplayCache()
    na = _future()
    assert cache.check_and_claim("d1", na) is True       # first sight: honor
    assert cache.check_and_claim("d1", na) is False      # exact replay: refuse


def test_in_memory_distinct_decision_ids_each_honored():
    cache = InMemoryReplayCache()
    na = _future()
    assert cache.check_and_claim("d1", na) is True
    assert cache.check_and_claim("d2", na) is True       # different id: honor


def test_in_memory_prunes_expired_entry_then_treats_reuse_as_fresh():
    # Mirrors VL-066: an entry past its not_after is pruned, so a later
    # re-presentation is "fresh" to the cache (freshness would independently
    # refuse it at the verifier - the cache is only the de-dup half).
    cache = InMemoryReplayCache()
    fixed_now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    expiry = fixed_now + timedelta(seconds=10)
    assert cache.check_and_claim("d1", expiry, now=fixed_now) is True
    later = expiry + timedelta(seconds=1)                # past not_after
    assert cache.check_and_claim("d1", expiry, now=later) is True   # pruned -> fresh


def test_in_memory_within_window_replay_still_refused():
    cache = InMemoryReplayCache()
    fixed_now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    expiry = fixed_now + timedelta(seconds=10)
    assert cache.check_and_claim("d1", expiry, now=fixed_now) is True
    still_in = fixed_now + timedelta(seconds=5)          # before not_after
    assert cache.check_and_claim("d1", expiry, now=still_in) is False


def test_in_memory_none_expiry_entry_is_retained_across_prune():
    # A decision with no parseable not_after stores expiry None; it must not be
    # pruned by time even when a sibling entry is pruned.
    cache = InMemoryReplayCache()
    fixed_now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    assert cache.check_and_claim("forever", None, now=fixed_now) is True
    assert cache.check_and_claim("ttl", fixed_now + timedelta(seconds=1),
                                 now=fixed_now) is True
    later = fixed_now + timedelta(seconds=100)           # prunes "ttl"
    assert cache.check_and_claim("ttl", None, now=later) is True       # pruned
    assert cache.check_and_claim("forever", None, now=later) is False  # retained


# ---------------------------------------------------------------------------
# The gap and the seam: separate caches MISS, a shared cache CATCHES
# ---------------------------------------------------------------------------

def test_separate_in_memory_caches_miss_cross_instance_replay():
    # The gap B3 names: two target processes, each its own in-process dict. The
    # same decision_id is honored once on EACH - replay crosses instances. This
    # is the contrast that pins the gap (cf. VL-074 test_byte_anchor_*).
    instance_a = InMemoryReplayCache()
    instance_b = InMemoryReplayCache()
    na = _future()
    assert instance_a.check_and_claim("d1", na) is True
    assert instance_b.check_and_claim("d1", na) is True   # honored AGAIN: gap


def test_shared_in_memory_cache_catches_cross_instance_replay():
    # The seam's point: one cache injected into both call sites -> exactly-once
    # across instances.
    shared = InMemoryReplayCache()
    na = _future()
    assert shared.check_and_claim("d1", na) is True       # instance A honors
    assert shared.check_and_claim("d1", na) is False      # instance B refuses


# ---------------------------------------------------------------------------
# ExternalStoreReplayCache: the cross-process adapter
# ---------------------------------------------------------------------------

class FakeSharedStore:
    """In-memory stand-in for a cross-process store (Redis SET NX EX). One
    instance shared by every ExternalStoreReplayCache models a single backend
    behind N target processes."""

    def __init__(self):
        self._d = {}

    def claim(self, decision_id, expiry, now):
        for k in [k for k, exp in self._d.items() if exp is not None and exp <= now]:
            del self._d[k]
        if decision_id in self._d:
            return False
        self._d[decision_id] = expiry
        return True


class RaisingStore:
    def claim(self, decision_id, expiry, now):
        raise ConnectionError("backend unreachable")


def test_external_store_honors_once_then_refuses_replay():
    cache = ExternalStoreReplayCache(FakeSharedStore())
    na = _future()
    assert cache.check_and_claim("d1", na) is True
    assert cache.check_and_claim("d1", na) is False


def test_external_store_shared_catches_cross_instance_replay():
    store = FakeSharedStore()
    instance_a = ExternalStoreReplayCache(store)          # target process A
    instance_b = ExternalStoreReplayCache(store)          # target process B
    na = _future()
    assert instance_a.check_and_claim("d1", na) is True
    assert instance_b.check_and_claim("d1", na) is False  # shared -> caught


def test_external_store_failure_propagates_fail_closed():
    # A store that cannot decide must NOT yield a silent honor: the exception
    # propagates to the caller's fail-closed try/except.
    cache = ExternalStoreReplayCache(RaisingStore())
    with pytest.raises(ConnectionError):
        cache.check_and_claim("d1", _future())


# ---------------------------------------------------------------------------
# Structural: both concrete caches satisfy the seam contract
# ---------------------------------------------------------------------------

def test_implementations_satisfy_replay_cache_protocol():
    assert isinstance(InMemoryReplayCache(), ReplayCache)
    assert isinstance(ExternalStoreReplayCache(FakeSharedStore()), ReplayCache)
    assert isinstance(FakeSharedStore(), ReplayStore)


# ---------------------------------------------------------------------------
# RedisReplayStore (the concrete cross-process store, VL-094 wiring)
# ---------------------------------------------------------------------------

class _FakeRedis:
    """Minimal in-memory stand-in for a Redis client (SET ... NX EX). One instance shared by N
    RedisReplayStore instances models a single Redis behind N target processes."""

    def __init__(self):
        self._d = {}

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self._d:
            return None          # key exists -> not set (a replay)
        self._d[key] = value
        return True


def test_redis_store_honor_once_then_refuse_replay():
    cache = ExternalStoreReplayCache(RedisReplayStore(_FakeRedis()))
    na = _future()
    assert cache.check_and_claim("d1", na) is True
    assert cache.check_and_claim("d1", na) is False


def test_redis_store_shared_catches_cross_instance_replay():
    shared = _FakeRedis()                                   # one Redis
    inst_a = ExternalStoreReplayCache(RedisReplayStore(shared))   # target process A
    inst_b = ExternalStoreReplayCache(RedisReplayStore(shared))   # target process B
    na = _future()
    assert inst_a.check_and_claim("d1", na) is True
    assert inst_b.check_and_claim("d1", na) is False       # shared store -> caught


def test_redis_store_none_expiry_sets_no_ttl():
    captured = {}

    class _R:
        def set(self, key, value, nx=False, ex=None):
            captured["ex"] = ex
            return True

    ExternalStoreReplayCache(RedisReplayStore(_R())).check_and_claim("d1", None)
    assert captured["ex"] is None                           # no TTL when no not_after


def test_redis_store_ttl_derived_from_expiry():
    captured = {}
    from datetime import datetime, timezone, timedelta

    class _R:
        def set(self, key, value, nx=False, ex=None):
            captured["ex"] = ex
            return True

    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    ExternalStoreReplayCache(RedisReplayStore(_R())).check_and_claim(
        "d1", now + timedelta(seconds=120), now=now)
    assert captured["ex"] == 120


def test_replay_cache_from_env_defaults_to_in_memory(monkeypatch):
    monkeypatch.delenv("ELYON_REPLAY_REDIS_URL", raising=False)
    assert isinstance(replay_cache_from_env(), InMemoryReplayCache)
