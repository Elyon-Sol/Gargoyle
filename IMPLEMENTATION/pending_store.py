"""
Shared pending-approval-set seam (Feature 1 residual R2; [FIX H4]/[FIX H3] under
horizontal scale). docs/design/governance_layer_design.md section 1.4.

MIRRORS IMPLEMENTATION/replay_cache.py as a SIBLING seam. The gate-side
pending-request set - the 202 hold's `approval_request_id -> decision_sha256`
binding, consumed exactly once when the approved grant returns - lives today as
the in-process `_PendingApprovals` dict in pep.py (VL-115). A horizontally-scaled
gate keeps N independent dicts, so:
  - a 202 issued on instance A is UNKNOWN to instance B (the approved resubmit
    fails REF_APPROVAL_REQUEST_UNKNOWN - availability break), and
  - worse for [FIX H3]/[FIX H4]: the 202 slot's single-consume is only
    per-process, so the same approval_request_id could be consumed once on EACH
    instance.
A single SHARED store closes both: an issue on any instance is visible on every
instance, and check_and_consume is a GLOBAL atomic compare-and-delete.

The seam:
    issue(request_id, decision_sha256, *, not_after=None, now=None) -> None
    check_and_consume(request_id, decision_sha256, *, now=None) -> bool

True  = request_id was pending AND bound to decision_sha256 -> CONSUMED (honor).
False = unknown request_id OR bound to a DIFFERENT decision  -> refuse
        (REF_APPROVAL_REQUEST_UNKNOWN at the pep boundary). On the False path
        NOTHING is consumed - a wrong-decision probe must not burn a legitimate
        pending slot (compare-AND-delete, never delete-then-compare).

InMemoryPendingApprovals is the single-instance default (pending_store_from_env()
returns it when no shared store is configured). Since 2026-10-07 every hold
carries a not_after: pep issues each 202 with a hold TTL
(ELYON_PENDING_HOLD_TTL_SECONDS, default 3600) and both stores enforce it - the
in-memory set refuses and prunes expired holds, the Redis store sets an EX - so
an unanswered hold neither stays consumable nor accumulates without bound.

Fail-closed (canon section 9): check_and_consume never returns True on doubt; a
backing store that cannot decide raises through to pep's fail-closed handler
rather than honoring an undecidable consume.

R-02 (the cross-model finding reused from replay_cache.py): a per-process pending
set CANNOT keep the 202 slot global across replicas. A deployment that declares
itself horizontally scaled (ELYON_REPLAY_MULTI_INSTANCE) without a shared pending
store fails closed at startup rather than silently handing each replica a
per-process set.
"""

import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Protocol, runtime_checkable


@runtime_checkable
class PendingApprovals(Protocol):
    """The seam contract: record a 202 hold's request->decision binding, then
    consume it exactly once for the SAME decision."""

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
    `put` records request_id -> decision_sha256 (optional expiry). `consume_if_matches`
    atomically deletes-and-returns-True IFF the stored value equals decision_sha256
    (compare-and-delete; a mismatch deletes nothing). Maps onto Redis SET + a Lua
    GET-compare-DEL, or an UPDATE ... WHERE value=? RETURNING."""

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
    """Process-local pending set (a lock + a dict). issue() records the binding
    with an optional expiry; check_and_consume() honors exactly once, only for
    the SAME decision, and only while the hold is unexpired (the get/compare/
    expire/delete is serialized so it is atomic).

    Hold TTL (2026-10-07, VL-154 open item): the pre-R2 dict had no TTL, so a
    202 hold stayed consumable forever and the set grew without bound (one
    entry per unanswered 202 - an unauthenticated caller can mint those at
    will). With `not_after`, a hold is refused once `now >= not_after` and
    expired entries are pruned on every issue(), so the set is bounded by the
    holds issued inside one TTL. pep always passes a not_after
    (ELYON_PENDING_HOLD_TTL_SECONDS); `not_after=None` keeps an entry until
    consumed, for callers that manage lifetime themselves.

    Injected as a SINGLE shared instance it closes the cross-instance gap
    in-process; a true cross-PROCESS store is the ExternalStorePendingApprovals
    path (its Redis backing applies the same not_after as an EX)."""

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
    """Cross-process pending set: delegates to an injected shared PendingStore, so
    issue is global and consume is exactly-once across instances. Holds no state;
    a store that raises propagates (fail-closed - pep refuses rather than honors
    on an undecidable consume)."""

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
    """A cross-process PendingStore backed by Redis. `put` = SET <prefix><request_id>
    <decision_sha256> [EX <ttl>]. `consume_if_matches` runs an atomic Lua
    compare-and-delete so a concurrent double-consume succeeds at most once and a
    wrong-decision probe deletes nothing:

        if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end

    The redis client is INJECTED (build via `from_url`); `redis` is imported lazily
    so it is not a hard dependency of the gate. TTL is `expiry - now` (>= 1s); a
    None expiry sets no EX (parity with InMemoryPendingApprovals retaining the
    entry until consumed)."""

    _CONSUME_LUA = (
        "if redis.call('GET', KEYS[1]) == ARGV[1] "
        "then return redis.call('DEL', KEYS[1]) else return 0 end"
    )

    def __init__(self, client: Any, key_prefix: str = "elyon:pending:") -> None:
        self._client = client
        self._prefix = key_prefix

    @classmethod
    def from_url(cls, url: str, key_prefix: str = "elyon:pending:") -> "RedisPendingStore":
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
    """Build the pending-approval set a deployed gate uses, from the environment.
    With `ELYON_PENDING_REDIS_URL` set, a SHARED
    ExternalStorePendingApprovals(RedisPendingStore) keeps the 202 slot global;
    otherwise a per-instance InMemoryPendingApprovals (the bare default, so a
    single-instance gate is unchanged).

    R-02 declare-or-fail guard (reused from replay_cache_from_env): a gate that
    declares ELYON_REPLAY_MULTI_INSTANCE without a shared pending store cannot keep
    the 202 slot global -> it FAILS CLOSED at startup rather than handing each
    replica a per-process set that consumes the same approval_request_id once
    each. Single-instance (no flag) is unchanged."""
    import os

    url = os.environ.get("ELYON_PENDING_REDIS_URL")
    if url:
        return ExternalStorePendingApprovals(RedisPendingStore.from_url(url))
    if os.environ.get("ELYON_REPLAY_MULTI_INSTANCE", "").strip().lower() in ("1", "true", "yes"):
        raise RuntimeError(
            "ELYON_REPLAY_MULTI_INSTANCE is set but ELYON_PENDING_REDIS_URL is not: a per-process "
            "pending-approval set cannot keep the 202 slot global across instances (a 202 issued on "
            "one replica is unknown to another, and single-consume holds only per-process). Set "
            "ELYON_PENDING_REDIS_URL (a shared store) or unset ELYON_REPLAY_MULTI_INSTANCE."
        )
    return InMemoryPendingApprovals()
