"""
Shared-replay-cache seam (docs/restructure/16_shared_replay_cache_spec.md,
increment VL-076, artifact 13 Phase B step B3).

Purpose: give the in-window exactly-once replay defense built at VL-066 a seam,
so the per-decision de-dup that lives today as the inline `app.state.seen` dict
in reference_target.py can instead be backed by a CROSS-INSTANCE store. A
horizontally-scaled deployment running N target processes keeps N independent
in-process dicts, so a `decision_id` can be honored once on each instance -
replay survives across instances. A single shared cache closes that gap.

The seam is one atomic question, per decision_id:

    check_and_claim(decision_id, not_after, *, now=None) -> bool

True  = decision_id was not seen and is now claimed -> the caller may HONOR.
False = decision_id was already claimed            -> the caller must REFUSE
                                                       (REF_VERIFY_REPLAY).

`not_after` is the already-parsed expiry of the decision: a timezone-aware
datetime, or None when the decision carries no parseable not_after. Parsing the
wire `not_after` string into a datetime stays at the CALL site (the target),
mirroring the VL-066 code; this module is format-agnostic and stores only the
parsed expiry.

Build-then-wire (the project discipline since VL-025; the transport seam VL-039
was wired only at VL-060): this module has NO callers at the commit that
introduces it. reference_target.py is NOT changed here. Wiring the target to take
an injected `replay_cache` - defaulting to a fresh InMemoryReplayCache, which
reproduces today's inline-dict behavior exactly - is a later increment with its
own VL.

No new canonical invariant (canon section 14): replay defense is the acting
party's stateful concern, not a canonical invariant (verify_envelope stays pure
and does not emit REF_VERIFY_REPLAY - VL-066). This seam only changes WHERE the
seen-set lives (process-local dict vs shared store); it never touches WHAT the
gate decides or WHAT the target verifies.

Fail-closed (canon section 9): check_and_claim never returns True on doubt. True
is reserved for a positively-fresh, positively-claimed decision_id. An external
store that cannot decide (a backend error) raises through to the target's
existing per-request try/except, which maps it to a refusal - the call is NOT
honored on an undecidable claim.
"""

import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Protocol, runtime_checkable


@runtime_checkable
class ReplayCache(Protocol):
    """The seam contract. An implementation answers, atomically per decision_id,
    whether this decision may be honored (newly claimed) or must be refused as a
    replay (already claimed)."""

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
    """The cross-process primitive an ExternalStoreReplayCache delegates to. A
    single atomic claim, shared by every target process. Maps directly onto a
    real backend: Redis `SET decision_id 1 NX EX <ttl>`, Memcached `add`, or an
    INSERT against a unique key. Returns True iff decision_id was newly claimed
    (not already present)."""

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
    """Process-local replay cache - behavior-identical to the VL-066 inline
    `app.state.seen` dict in reference_target.py.

    On each claim: prune every entry whose expiry is non-None and has passed
    (`<= now`), then refuse (return False) a decision_id still present, else
    record `decision_id -> not_after` and honor (return True). An entry with a
    None expiry (no parseable not_after) is never pruned by time and is retained
    until the process drops it.

    Constructed fresh per process and injected as the default, this reproduces
    today's behavior exactly - the load-bearing property the future wiring step
    relies on. Injected as a SINGLE shared instance across call sites, it closes
    the cross-instance replay gap in-process (a true cross-PROCESS store is the
    ExternalStoreReplayCache path).
    """

    def __init__(self) -> None:
        self._seen: Dict[str, Optional[datetime]] = {}
        # R-01: prune+check+set below is a check-then-set that must be atomic. The
        # ext-authz sidecar runs check() via run_in_threadpool, so two threads can
        # both observe a decision_id absent before either claims it - a concurrent
        # single-use bypass (a replayed token honored twice). Serialize it.
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
    """Cross-process replay cache: delegates the atomic claim to an injected
    shared store (a ReplayStore). Because the store is shared by every target
    process, the claim is global and exactly-once holds across instances.

    The adapter holds no state of its own; the prune/TTL discipline lives in the
    backing store (Redis EX, a TTL column, etc.). A store that raises on `claim`
    propagates the exception (fail-closed: the caller refuses rather than honors
    on an undecidable claim)."""

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
    """A cross-process `ReplayStore` backed by Redis `SET key 1 NX EX <ttl>` (VL-094, wiring B3).

    One Redis shared by N target instances makes the claim global: a decision_id claimed on any
    instance is refused on every other. The redis client is INJECTED (build via `from_url`) so this
    is testable against a fake without a real Redis, and `redis` is imported lazily so it is not a
    hard dependency of the gate.

    `claim` maps to `SET <prefix><decision_id> 1 NX EX <ttl>`: returns True iff the key was newly
    set (a fresh claim), False if it already existed (a replay). The TTL is `expiry - now` (bounded
    below by 1s; on the honor path the decision is already fresh, so expiry > now); a None expiry
    sets no EX (the no-temporal-bound case, parity with InMemoryReplayCache retaining it)."""

    def __init__(self, client: Any, key_prefix: str = "elyon:replay:") -> None:
        self._client = client
        self._prefix = key_prefix

    @classmethod
    def from_url(cls, url: str, key_prefix: str = "elyon:replay:") -> "RedisReplayStore":
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
    """Build the replay cache a deployed executor uses, from the environment. With
    `ELYON_REPLAY_REDIS_URL` set, a SHARED `ExternalStoreReplayCache(RedisReplayStore)` for
    cross-instance exactly-once; otherwise a per-instance `InMemoryReplayCache` (the bare default,
    so a single-instance deployment is unchanged)."""
    import os

    url = os.environ.get("ELYON_REPLAY_REDIS_URL")
    if url:
        return ExternalStoreReplayCache(RedisReplayStore.from_url(url))
    # R-02 (cross-model finding): a per-process InMemoryReplayCache CANNOT enforce
    # single-use across processes/replicas. A deployment that runs >1 worker/replica
    # must declare ELYON_REPLAY_MULTI_INSTANCE=1; declaring it WITHOUT a shared store
    # fails closed here rather than silently handing out per-process caches that each
    # honor the same token once. Single-instance (no flag) is unchanged.
    if os.environ.get("ELYON_REPLAY_MULTI_INSTANCE", "").strip().lower() in ("1", "true", "yes"):
        raise RuntimeError(
            "ELYON_REPLAY_MULTI_INSTANCE is set but ELYON_REPLAY_REDIS_URL is not: a per-process "
            "InMemoryReplayCache cannot enforce single-use across processes/replicas. Set "
            "ELYON_REPLAY_REDIS_URL (a shared store) or unset ELYON_REPLAY_MULTI_INSTANCE."
        )
    return InMemoryReplayCache()
