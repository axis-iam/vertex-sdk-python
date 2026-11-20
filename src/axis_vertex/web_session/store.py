"""Atomic host-session ports and an explicitly selected, bounded RAM provider.

Sync and async hosts implement separate ports. CAS includes rotation so a logout
or late framework save cannot create a child identity from a stale snapshot.
"""

from __future__ import annotations

import copy
import json
import math
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from threading import Event, RLock, Thread
from typing import Protocol, runtime_checkable

from axis_vertex.errors import IamConfigError

from .models import Record, StoreError


@dataclass(frozen=True, slots=True)
class StoreCapabilities:
    atomic: bool
    shared: bool
    persistent: bool
    server_side: bool = True


@runtime_checkable
class AsyncSessionStore(Protocol):
    capabilities: StoreCapabilities

    async def read(self, key: str) -> Record | None: ...
    async def create(self, record: Record) -> None: ...
    async def compare_exchange(self, key: str, version: int, replacement: Record) -> None: ...
    async def invalidate(self, key: str) -> bool: ...


@runtime_checkable
class SyncSessionStore(Protocol):
    capabilities: StoreCapabilities

    def read_sync(self, key: str) -> Record | None: ...
    def create_sync(self, record: Record) -> None: ...
    def compare_exchange_sync(self, key: str, version: int, replacement: Record) -> None: ...
    def invalidate_sync(self, key: str) -> bool: ...


class AsyncFromSyncStore:
    """Explicit bridge for the SDK's persistent sync runner, never ASGI handlers.

    This adapter must only be used by SyncServerSession. It deliberately performs
    sync IO on that caller's synchronous thread, not an application event loop.
    """

    def __init__(self, store: SyncSessionStore):
        self.store = store
        self.capabilities = store.capabilities

    async def read(self, key: str) -> Record | None:
        return self.store.read_sync(key)

    async def create(self, record: Record) -> None:
        self.store.create_sync(record)

    async def compare_exchange(self, key: str, version: int, replacement: Record) -> None:
        self.store.compare_exchange_sync(key, version, replacement)

    async def invalidate(self, key: str) -> bool:
        return self.store.invalidate_sync(key)


class MemorySessionStore:
    """Single-process, thread/coroutine-safe, volatile store; no implicit fallback.

    Each operation copies and bounds a record while holding an instance lock.
    It performs no blocking IO in its async methods. Close joins the cleanup
    thread and clears credentials; closed operations report CLOSED, not ABSENT.
    """

    capabilities = StoreCapabilities(atomic=True, shared=False, persistent=False)

    def __init__(
        self,
        *,
        max_sessions: int = 10000,
        max_prelogins: int = 1000,
        max_record_bytes: int = 65536,
        cleanup_interval: float = 60,
        clock: Callable[[], float] = time.time,
    ):
        if any(
            type(n) is not int or n <= 0 for n in (max_sessions, max_prelogins, max_record_bytes)
        ):
            raise IamConfigError("memory capacities must be positive integers")
        if not math.isfinite(cleanup_interval) or cleanup_interval <= 0:
            raise IamConfigError("cleanup interval must be positive and finite")
        self._max_sessions, self._max_prelogins = max_sessions, max_prelogins
        self._max_bytes = max_record_bytes
        self._clock = clock
        self._records: dict[str, Record] = {}
        self._lock = RLock()
        self._closed = False
        self._stop = Event()
        self._thread = Thread(
            target=self._cleanup, args=(cleanup_interval,), daemon=True, name="axis-session-cleanup"
        )
        self._thread.start()

    def _cleanup(self, interval: float) -> None:
        while not self._stop.wait(interval):
            with self._lock:
                if not self._closed:
                    self._purge()

    def _check(self) -> None:
        if self._closed:
            raise StoreError("CLOSED")

    def _purge(self) -> None:
        now = self._clock()
        for key in list(self._records):
            r = self._records[key]
            if min(r.absolute_expires_at, r.idle_expires_at) <= now:
                del self._records[key]

    def _snapshot(self, record: Record) -> Record:
        try:
            size = len(json.dumps(asdict(record), allow_nan=False).encode())
        except (ValueError, TypeError):
            raise IamConfigError("session records must be finite JSON data") from None
        if size > self._max_bytes:
            raise StoreError("CAPACITY")
        if (
            record.schema_version != 1
            or record.version < 0
            or not all(
                math.isfinite(n)
                for n in (
                    record.created_at,
                    record.absolute_expires_at,
                    record.idle_expires_at,
                    record.lease_until,
                )
            )
        ):
            raise IamConfigError("invalid session record")
        return copy.deepcopy(record)

    def _capacity(self, kind: str, exclude: str | None = None) -> None:
        session = kind == "session"
        count = sum(
            (r.kind == "session") == session for k, r in self._records.items() if k != exclude
        )
        if count >= (self._max_sessions if session else self._max_prelogins):
            raise StoreError("CAPACITY")

    def read_sync(self, key: str) -> Record | None:
        with self._lock:
            self._check()
            self._purge()
            record = self._records.get(key)
            return copy.deepcopy(record) if record is not None else None

    def create_sync(self, record: Record) -> None:
        with self._lock:
            self._check()
            self._purge()
            if record.key in self._records:
                raise StoreError("CONFLICT")
            self._capacity(record.kind)
            self._records[record.key] = self._snapshot(record)

    def compare_exchange_sync(self, key: str, version: int, replacement: Record) -> None:
        with self._lock:
            self._check()
            self._purge()
            old = self._records.get(key)
            if old is None:
                raise StoreError("ABSENT")
            if old.version != version or replacement.version != version + 1:
                raise StoreError("CONFLICT")
            if old.operation is not None and old.intent and old.lease_until <= self._clock():
                del self._records[key]
                raise StoreError("ABSENT")
            rotation = old.kind == "prelogin" and replacement.kind == "session"
            if rotation and (not old.intent or old.operation is None or replacement.key == key):
                raise IamConfigError("authentication rotation requires a live consumed operation")
            if (
                not rotation
                and (
                    replacement.created_at != old.created_at
                    or replacement.absolute_expires_at > old.absolute_expires_at
                )
            ) or replacement.owner != old.owner:
                raise IamConfigError("immutable session binding changed")
            if replacement.key != key and replacement.key in self._records:
                raise StoreError("CONFLICT")
            self._capacity(replacement.kind, exclude=key)
            saved = self._snapshot(replacement)
            del self._records[key]
            self._records[saved.key] = saved

    def invalidate_sync(self, key: str) -> bool:
        with self._lock:
            self._check()
            # Capture/clear even an expired record; callers may still revoke an owned RT.
            return self._records.pop(key, None) is not None

    async def read(self, key: str) -> Record | None:
        return self.read_sync(key)

    async def create(self, record: Record) -> None:
        self.create_sync(record)

    async def compare_exchange(self, key: str, version: int, replacement: Record) -> None:
        self.compare_exchange_sync(key, version, replacement)

    async def invalidate(self, key: str) -> bool:
        return self.invalidate_sync(key)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._records.clear()
        self._stop.set()
        self._thread.join()

    async def aclose(self) -> None:
        self.close()
