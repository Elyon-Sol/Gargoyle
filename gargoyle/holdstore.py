"""Persistent issuer state: holds, grants, declines and plans survive a restart.

The issuing service keeps little state, but what it keeps is what a human
is in the middle of acting on. In a lab the service was restarted a dozen
times in two days and each restart dropped the holds in flight; the
middleware then reported a timeout and the assistant retried. A client's
approver would see a card that did nothing. This module backs each of the
service's maps with a SQLite table (standard library, one file, one
process), so a restart changes nothing a person can see. With no path the
store is in memory, which is what the tests use.

Dict semantics are kept on purpose: the service code reads as before,
and a value is written back on assignment, never by mutating what a read
returned.
"""

import json
import sqlite3
import threading
from collections.abc import MutableMapping, MutableSet
from typing import Any, Iterator, Optional

ENV_HOLDS_PATH = "GARGOYLE_HOLDS_PATH"


class HoldStore:
    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or ":memory:"
        self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._lock = threading.RLock()
        with self._lock:
            self._db.execute("PRAGMA journal_mode=WAL") if self.path != ":memory:" else None
            self._db.execute("CREATE TABLE IF NOT EXISTS kv (ns TEXT NOT NULL, k TEXT NOT NULL, v TEXT NOT NULL, PRIMARY KEY (ns, k))")

    def dict(self, ns: str) -> "PersistentDict":
        return PersistentDict(self, ns)

    def set(self, ns: str) -> "PersistentSet":
        return PersistentSet(self, ns)

    # ---- primitives ----
    def _get(self, ns: str, k: str) -> Any:
        with self._lock:
            row = self._db.execute("SELECT v FROM kv WHERE ns=? AND k=?", (ns, k)).fetchone()
        return json.loads(row[0]) if row else None

    def _has(self, ns: str, k: str) -> bool:
        with self._lock:
            return self._db.execute("SELECT 1 FROM kv WHERE ns=? AND k=?", (ns, k)).fetchone() is not None

    def _put(self, ns: str, k: str, v: Any) -> None:
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO kv (ns, k, v) VALUES (?, ?, ?)", (ns, k, json.dumps(v, sort_keys=True)))

    def _delete(self, ns: str, k: str) -> bool:
        with self._lock:
            cur = self._db.execute("DELETE FROM kv WHERE ns=? AND k=?", (ns, k))
            return cur.rowcount > 0

    def _keys(self, ns: str) -> list:
        with self._lock:
            return [r[0] for r in self._db.execute("SELECT k FROM kv WHERE ns=? ORDER BY rowid", (ns,)).fetchall()]

    def _count(self, ns: str) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM kv WHERE ns=?", (ns,)).fetchone()[0]

    def close(self) -> None:
        with self._lock:
            self._db.close()


class PersistentDict(MutableMapping):
    def __init__(self, store: HoldStore, ns: str) -> None:
        self._s, self._ns = store, ns

    def __getitem__(self, k: str) -> Any:
        if not self._s._has(self._ns, k):
            raise KeyError(k)
        return self._s._get(self._ns, k)

    def __setitem__(self, k: str, v: Any) -> None:
        self._s._put(self._ns, k, v)

    def __delitem__(self, k: str) -> None:
        if not self._s._delete(self._ns, k):
            raise KeyError(k)

    def __contains__(self, k: object) -> bool:
        return isinstance(k, str) and self._s._has(self._ns, k)

    def __iter__(self) -> Iterator[str]:
        return iter(self._s._keys(self._ns))

    def __len__(self) -> int:
        return self._s._count(self._ns)


class PersistentSet(MutableSet):
    def __init__(self, store: HoldStore, ns: str) -> None:
        self._s, self._ns = store, ns

    def __contains__(self, k: object) -> bool:
        return isinstance(k, str) and self._s._has(self._ns, k)

    def __iter__(self) -> Iterator[str]:
        return iter(self._s._keys(self._ns))

    def __len__(self) -> int:
        return self._s._count(self._ns)

    def add(self, k: str) -> None:
        self._s._put(self._ns, k, True)

    def discard(self, k: str) -> None:
        self._s._delete(self._ns, k)
