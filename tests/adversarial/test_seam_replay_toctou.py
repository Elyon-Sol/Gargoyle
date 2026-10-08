"""
Replay cache under contention.

InMemoryReplayCache.check_and_claim holds a lock around prune, check and set.
This races many threads at one decision_id at once and asserts exactly one is
honored: single use holds under concurrency, not just sequentially.
"""
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta

from gargoyle.replay_cache import InMemoryReplayCache


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
