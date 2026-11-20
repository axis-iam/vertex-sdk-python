from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor

import pytest

from axis_vertex.errors import IamConfigError
from axis_vertex.web_session import MemorySessionStore, Record, StoreError
from axis_vertex.web_session.models import random_id


def test_memory_ttl_capacity_copy_isolation_cleanup_and_close() -> None:
    now = [1.0]
    store = MemorySessionStore(max_prelogins=1, max_sessions=1, clock=lambda: now[0])
    try:
        r = Record(random_id(), 'prelogin', 1, 10, 10, data={'nested': {'secret': 'controlled'}})
        store.create_sync(r)
        r.data['nested']['secret'] = 'outside'
        snapshot = store.read_sync(r.key)
        assert snapshot.data['nested']['secret'] == 'controlled'
        snapshot.data['nested']['secret'] = 'mutated snapshot'
        assert store.read_sync(r.key).data['nested']['secret'] == 'controlled'
        with pytest.raises(StoreError) as e:
            store.create_sync(Record(random_id(), 'prelogin', 1, 20, 20))
        assert e.value.outcome == 'CAPACITY'
        now[0] = 11
        assert store.read_sync(r.key) is None
        store.create_sync(Record(random_id(), 'prelogin', 11, 20, 20))
    finally:
        store.close()
    assert not store._thread.is_alive() and not store._records
    with pytest.raises(StoreError) as e:
        store.read_sync(r.key)
    assert e.value.outcome == 'CLOSED'


def test_memory_single_consumer_cas_terminal_fence_and_immutable_deadline() -> None:
    store = MemorySessionStore()
    import time
    now = time.time()
    r = Record(random_id(), 'prelogin', now, now+60, now+60)
    store.create_sync(r)
    def consume(_: int) -> str:
        candidate = copy.deepcopy(r)
        candidate.version += 1
        candidate.operation = random_id()
        try:
            store.compare_exchange_sync(r.key, r.version, candidate)
            return 'winner'
        except StoreError as error:
            return error.outcome
    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(consume, range(16)))
        assert results.count('winner') == 1
        current = store.read_sync(r.key)
        invalid = copy.deepcopy(current)
        invalid.absolute_expires_at += 1
        invalid.version += 1
        with pytest.raises(IamConfigError):
            store.compare_exchange_sync(current.key, current.version, invalid)
        store.invalidate_sync(r.key)
        current.version += 1
        with pytest.raises(StoreError) as e:
            store.compare_exchange_sync(r.key, current.version - 1, current)
        assert e.value.outcome == 'ABSENT'
    finally:
        store.close()


def test_memory_record_size_bounds_and_restart_loss() -> None:
    store = MemorySessionStore(max_record_bytes=600)
    import time
    now = time.time()
    try:
        with pytest.raises(StoreError) as e:
            store.create_sync(Record(random_id(),
                'prelogin',
                now,
                now+60,
                now+60,
                data={'large':'x'*1000}))
        assert e.value.outcome == 'CAPACITY'
        r = Record(random_id(), 'prelogin', now, now+60, now+60)
        store.create_sync(r)
        store.close()
        restarted = MemorySessionStore()
        try:
            assert restarted.read_sync(r.key) is None
        finally:
            restarted.close()
    finally:
        store.close()
