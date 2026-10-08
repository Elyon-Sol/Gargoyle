"""
Replay-cache TOCTOU concurrency test (external-review hardening, 2026-07).

Reviewer seam: "a TOCTOU in the replay cache." InMemoryReplayCache.check_and_claim
guards its prune+check+set with a threading.Lock (replay_cache.py R-01). The
existing seam tests are all sequential and never prove the lock holds under real
contention. This races many threads at ONE decision_id simultaneously and asserts
EXACTLY ONE honor - the single-use property under concurrency.
"""
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta

from IMPLEMENTATION.replay_cache import InMemoryReplayCache


def _future():
    return datetime.now(timezone.utc) + timedelta(hours=1)


def test_concurrent_double_spend_honored_exactly_once():
    cache = InMemoryReplayCache()
    na = _future()
    N = 64
    barrier = threading.Barrier(N)
    results = []
    lock = threading.Lock()

    def attempt():
        barrier.wait()  # release all threads at once -> maximal contention
        ok = cache.check_and_claim("same-decision", na)
        with lock:
            results.append(ok)

    with ThreadPoolExecutor(max_workers=N) as ex:
        for _ in range(N):
            ex.submit(attempt)

    assert results.count(True) == 1, f"expected exactly one honor, got {results.count(True)}"
    assert results.count(False) == N - 1


def test_concurrent_distinct_ids_all_honored():
    cache = InMemoryReplayCache()
    na = _future()
    N = 200
    results = []
    lock = threading.Lock()

    def attempt(i):
        ok = cache.check_and_claim(f"decision-{i}", na)
        with lock:
            results.append(ok)

    with ThreadPoolExecutor(max_workers=32) as ex:
        for i in range(N):
            ex.submit(attempt, i)

    assert results.count(True) == N
