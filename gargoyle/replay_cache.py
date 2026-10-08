"""Replay caches: the single-use check executors run on each receipt's decision_id.

The contract is one atomic question per decision_id:

    check_and_claim(decision_id, not_after, *, now=None) -> bool

True means the id was unseen and is now claimed, so the caller may act.
False means it was already claimed, so the caller must refuse
(REF_VERIFY_REPLAY).

`not_after` is the receipt's already-parsed expiry: a timezone-aware datetime,
or None when the receipt carries no parseable not_after. Parsing the wire
string stays with the caller; this module stores only the parsed value.

Scope matters. An InMemoryReplayCache is per process, so N executor processes
each holding their own would honor the same receipt once each. A deployment
with more than one process or replica needs a shared store
(ExternalStoreReplayCache over RedisReplayStore); replay_cache_from_env()
refuses to start when told it is multi-instance without one.

Fail-closed: check_and_claim never returns True on doubt. A shared store that
cannot answer raises, and the caller's error handling turns that into a
refusal, never an action.
"""

import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Protocol, runtime_checkable


@runtime_checkable
class ReplayCache(Protocol):
    """Answers, atomically per decision_id, whether a receipt may be honored
    (newly claimed) or must be refused as a replay (already claimed)."""

    def check_and_claim(
        self,
        decision_id: str,
        not_after: Optional[datetime],
        *,
        now: Optional[datetime] = None,
    ) -> bool:  # pragma: no cover - structural contract
        ...


@runtime_checkable
class ReplayStore(Protocol):
    """The cross-process primitive an ExternalStoreReplayCache delegates to: one
    atomic claim shared by every executor process. Maps onto Redis
    `SET decision_id 1 NX EX <ttl>`, Memcached `add`, or an INSERT against a
    unique key. Returns True iff decision_id was newly claimed."""

    def claim(
        self,
        decision_id: str,
        expiry: Optional[datetime],
        now: datetime,
    ) -> bool:  # pragma: no cover - structural contract
        ...


def _utcnow(now: Optional[datetime]) -> datetime:
    return now if now is not None else datetime.now(timezone.utc)


class InMemoryReplayCache:
    """Process-local replay cache.

    On each claim: drop every entry whose expiry has passed (`<= now`), refuse
    a decision_id still present, else record it and honor. An entry with no
    expiry is never dropped by time and lives as long as the process.

    One instance shared by every call site in a process enforces single use
    within that process. It cannot enforce it across processes; use
    ExternalStoreReplayCache for that.
    """

    def __init__(self) -> None:
        self._seen: Dict[str, Optional[datetime]] = {}
        # Prune, check and set must be one atomic step. Callers such as the
        # ext-authz sidecar run checks on a thread pool, so without the lock two
        # threads could both see an id as unclaimed and honor the same receipt twice.
        self._lock = threading.Lock()

    def check_and_claim(
        self,
        decision_id: str,
        not_after: Optional[datetime],
        *,
        now: Optional[datetime] = None,
    ) -> bool:
        current = _utcnow(now)
        seen = self._seen
        with self._lock:
            for k in [k for k, exp in seen.items() if exp is not None and exp <= current]:
                del seen[k]
            if decision_id in seen:
                return False
            seen[decision_id] = not_after
            return True


class ExternalStoreReplayCache:
    """Cross-process replay cache: delegates the atomic claim to a shared
    ReplayStore, so single use holds across every executor instance.

    Holds no state itself; expiry is the store's job (Redis EX, a TTL column).
    A store that raises on `claim` propagates the exception, so the caller
    refuses rather than honors on an undecidable claim."""

    def __init__(self, store: ReplayStore) -> None:
        self._store = store

    def check_and_claim(
        self,
        decision_id: str,
        not_after: Optional[datetime],
        *,
        now: Optional[datetime] = None,
    ) -> bool:
        current = _utcnow(now)
        return self._store.claim(decision_id, not_after, current)


class RedisReplayStore:
    """A ReplayStore backed by Redis `SET key 1 NX EX <ttl>`.

    One Redis shared by N executor instances makes the claim global: an id
    claimed on any instance is refused on every other. The client is injected
    (build one with `from_url`) so tests can use a fake, and `redis` is imported
    lazily so it stays an optional dependency.

    `claim` returns True iff the key was newly set. The TTL is `expiry - now`,
    at least 1 s (on the honor path the receipt is still fresh, so expiry is
    after now). A None expiry sets no EX, matching InMemoryReplayCache keeping
    such entries."""

    def __init__(self, client: Any, key_prefix: str = "gargoyle:replay:") -> None:
        self._client = client
        self._prefix = key_prefix

    @classmethod
    def from_url(cls, url: str, key_prefix: str = "gargoyle:replay:") -> "RedisReplayStore":
        import redis  # lazy: not a hard dependency

        return cls(redis.Redis.from_url(url), key_prefix=key_prefix)

    def claim(
        self,
        decision_id: str,
        expiry: Optional[datetime],
        now: datetime,
    ) -> bool:
        key = self._prefix + decision_id
        if expiry is not None:
            ttl = max(1, int((expiry - now).total_seconds()))
            ok = self._client.set(key, b"1", nx=True, ex=ttl)
        else:
            ok = self._client.set(key, b"1", nx=True)
        return bool(ok)


def replay_cache_from_env():
    """The replay cache a deployed executor uses. With GARGOYLE_REPLAY_REDIS_URL
    set: a shared ExternalStoreReplayCache over Redis. Otherwise a per-process
    InMemoryReplayCache, which is only correct for a single instance."""
    import os

    url = os.environ.get("GARGOYLE_REPLAY_REDIS_URL")
    if url:
        return ExternalStoreReplayCache(RedisReplayStore.from_url(url))
    # A per-process cache cannot enforce single use across processes or replicas.
    # A deployment that declares itself multi-instance without a shared store fails
    # closed here, rather than silently giving each process its own cache that would
    # each honor the same receipt once.
    if os.environ.get("GARGOYLE_REPLAY_MULTI_INSTANCE", "").strip().lower() in ("1", "true", "yes"):
        raise RuntimeError(
            "GARGOYLE_REPLAY_MULTI_INSTANCE is set but GARGOYLE_REPLAY_REDIS_URL is not: a per-process "
            "InMemoryReplayCache cannot enforce single-use across processes/replicas. Set "
            "GARGOYLE_REPLAY_REDIS_URL (a shared store) or unset GARGOYLE_REPLAY_MULTI_INSTANCE."
        )
    return InMemoryReplayCache()
