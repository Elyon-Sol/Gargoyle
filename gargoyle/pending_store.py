"""Pending-approval stores: the hold half of human approval.

When a policy marks a call requires_approval, the issuing service holds it
and hands back an approval_request_id bound to the receipt's
decision_sha256. When the human-signed grant comes back, the binding is
consumed exactly once. This module stores those bindings:

    issue(request_id, decision_sha256, *, not_after=None, now=None) -> None
    check_and_consume(request_id, decision_sha256, *, now=None) -> bool

True means the request was pending and bound to this decision; it is now
consumed and the call may proceed. False means unknown, expired, or bound to
a different decision; refuse (REF_APPROVAL_REQUEST_UNKNOWN). On the False
path nothing is consumed, so a probe with the wrong decision cannot burn a
legitimate pending slot (compare-and-delete, never delete-then-compare).

Holds should carry a not_after (GARGOYLE_PENDING_HOLD_TTL_SECONDS, default
3600). Both stores enforce it: the in-memory set refuses and prunes expired
holds, the Redis store sets an EX. Without it an unanswered hold would stay
consumable forever, and anyone able to trigger holds could grow the set
without bound.

Scope: a per-process set cannot keep a hold global across replicas. A hold
issued on one instance would be unknown to another, and single consume
would hold only per process, so the same request could be consumed once on
each instance. pending_store_from_env() refuses to start when told it is
multi-instance without a shared store.

Fail-closed: check_and_consume never returns True on doubt. A shared store
that cannot answer raises, and the caller turns that into a refusal.
"""

import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Protocol, runtime_checkable


@runtime_checkable
class PendingApprovals(Protocol):
    """Record a hold's request -> decision binding, then consume it exactly
    once for the same decision."""

    def issue(
        self, request_id: str, decision_sha256: str, *,
        not_after: Optional[datetime] = None, now: Optional[datetime] = None,
    ) -> None:  # pragma: no cover - structural contract
        ...

    def check_and_consume(
        self, request_id: str, decision_sha256: str, *,
        now: Optional[datetime] = None,
    ) -> bool:  # pragma: no cover - structural contract
        ...


@runtime_checkable
class PendingStore(Protocol):
    """The cross-process primitive an ExternalStorePendingApprovals delegates to.
    `put` records request_id -> decision_sha256 with an optional expiry.
    `consume_if_matches` atomically deletes and returns True iff the stored
    value equals decision_sha256; a mismatch deletes nothing. Maps onto Redis
    SET plus a Lua GET-compare-DEL, or an UPDATE ... WHERE value=? RETURNING."""

    def put(
        self, request_id: str, decision_sha256: str,
        expiry: Optional[datetime], now: datetime,
    ) -> None:  # pragma: no cover - structural contract
        ...

    def consume_if_matches(
        self, request_id: str, decision_sha256: str, now: datetime,
    ) -> bool:  # pragma: no cover - structural contract
        ...


def _utcnow(now: Optional[datetime]) -> datetime:
    return now if now is not None else datetime.now(timezone.utc)


class InMemoryPendingApprovals:
    """Process-local pending set: a dict behind a lock, so get, compare,
    expire and delete happen as one atomic step.

    A hold is refused once `now >= not_after`, and expired entries are pruned
    on every issue(), so the set never holds more than the holds issued
    within one TTL. `not_after=None` keeps an entry until consumed, for
    callers that manage lifetime themselves.

    Correct for one process only; ExternalStorePendingApprovals is the
    cross-process path (its Redis backing applies the same not_after as an
    EX)."""

    def __init__(self) -> None:
        self._d: Dict[str, tuple] = {}  # request_id -> (decision_sha256, expiry|None)
        self._lock = threading.Lock()

    def _prune_expired(self, now: datetime) -> None:
        expired = [rid for rid, (_, exp) in self._d.items()
                   if exp is not None and now >= exp]
        for rid in expired:
            del self._d[rid]

    def issue(
        self, request_id: str, decision_sha256: str, *,
        not_after: Optional[datetime] = None, now: Optional[datetime] = None,
    ) -> None:
        current = _utcnow(now)
        with self._lock:
            self._prune_expired(current)
            self._d[request_id] = (decision_sha256, not_after)

    def check_and_consume(
        self, request_id: str, decision_sha256: str, *,
        now: Optional[datetime] = None,
    ) -> bool:
        current = _utcnow(now)
        with self._lock:
            entry = self._d.get(request_id)
            if entry is None:
                return False
            ds, exp = entry
            if exp is not None and current >= exp:
                del self._d[request_id]  # expired: gone, whatever the decision
                return False
            if ds != decision_sha256:
                return False
            del self._d[request_id]
            return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._d)


class ExternalStorePendingApprovals:
    """Cross-process pending set over a shared PendingStore: issue is visible
    on every instance and consume is exactly once across them. Holds no
    state; a store that raises propagates, so the caller refuses."""

    def __init__(self, store: PendingStore) -> None:
        self._store = store

    def issue(
        self, request_id: str, decision_sha256: str, *,
        not_after: Optional[datetime] = None, now: Optional[datetime] = None,
    ) -> None:
        self._store.put(request_id, decision_sha256, not_after, _utcnow(now))

    def check_and_consume(
        self, request_id: str, decision_sha256: str, *,
        now: Optional[datetime] = None,
    ) -> bool:
        return self._store.consume_if_matches(request_id, decision_sha256, _utcnow(now))


class RedisPendingStore:
    """A PendingStore backed by Redis. `put` is SET <prefix><request_id>
    <decision_sha256> [EX <ttl>]. `consume_if_matches` runs an atomic Lua
    compare-and-delete, so concurrent consumes succeed at most once and a
    wrong-decision probe deletes nothing:

        if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end

    The client is injected (build one with `from_url`) and `redis` is imported
    lazily, so it stays optional. TTL is `expiry - now`, at least 1 s; a None
    expiry sets no EX, matching InMemoryPendingApprovals."""

    _CONSUME_LUA = (
        "if redis.call('GET', KEYS[1]) == ARGV[1] "
        "then return redis.call('DEL', KEYS[1]) else return 0 end"
    )

    def __init__(self, client: Any, key_prefix: str = "gargoyle:pending:") -> None:
        self._client = client
        self._prefix = key_prefix

    @classmethod
    def from_url(cls, url: str, key_prefix: str = "gargoyle:pending:") -> "RedisPendingStore":
        import redis  # lazy: not a hard dependency

        return cls(redis.Redis.from_url(url), key_prefix=key_prefix)

    def put(
        self, request_id: str, decision_sha256: str,
        expiry: Optional[datetime], now: datetime,
    ) -> None:
        key = self._prefix + request_id
        if expiry is not None:
            ttl = max(1, int((expiry - now).total_seconds()))
            self._client.set(key, decision_sha256, ex=ttl)
        else:
            self._client.set(key, decision_sha256)

    def consume_if_matches(
        self, request_id: str, decision_sha256: str, now: datetime,
    ) -> bool:
        key = self._prefix + request_id
        res = self._client.eval(self._CONSUME_LUA, 1, key, decision_sha256)
        return bool(res)


def pending_store_from_env() -> PendingApprovals:
    """The pending set a deployed issuing service uses. With
    GARGOYLE_PENDING_REDIS_URL set: a shared store, so holds are global.
    Otherwise a per-process InMemoryPendingApprovals.

    Declaring GARGOYLE_REPLAY_MULTI_INSTANCE without a shared store fails at
    startup, rather than giving each replica its own set that would consume
    the same approval_request_id once each."""
    import os

    url = os.environ.get("GARGOYLE_PENDING_REDIS_URL")
    if url:
        return ExternalStorePendingApprovals(RedisPendingStore.from_url(url))
    if os.environ.get("GARGOYLE_REPLAY_MULTI_INSTANCE", "").strip().lower() in ("1", "true", "yes"):
        raise RuntimeError(
            "GARGOYLE_REPLAY_MULTI_INSTANCE is set but GARGOYLE_PENDING_REDIS_URL is not: a per-process "
            "pending-approval set cannot keep the 202 slot global across instances (a 202 issued on "
            "one replica is unknown to another, and single-consume holds only per-process). Set "
            "GARGOYLE_PENDING_REDIS_URL (a shared store) or unset GARGOYLE_REPLAY_MULTI_INSTANCE."
        )
    return InMemoryPendingApprovals()
