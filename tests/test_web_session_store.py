from __future__ import annotations

import asyncio
from multiprocessing.managers import BaseManager

import httpx
import pytest
from bff_fixture import Fixture

from axis_vertex.web_session import (
    MemorySessionStore,
    ServerSession,
    SessionError,
    StoreCapabilities,
    StoreError,
    SyncServerSession,
)
from axis_vertex.web_session.models import text


class SharedFixtureOwner(MemorySessionStore):
    """Controlled process-external atomic port; not a production backend claim."""
    def __init__(self, now: float):
        self.now_value = now
        self.sends = 0
        super().__init__(clock=self.now)

    def now(self) -> float:
        return self.now_value

    def advance(self, delta: float) -> None:
        self.now_value += delta

    def mark_send(self) -> None:
        self.sends += 1

    def send_count(self) -> int:
        return self.sends


class SharedFixturePort:
    capabilities = StoreCapabilities(atomic=True, shared=True, persistent=False)

    def __init__(self, owner):
        self.owner = owner

    def read_sync(self, key):
        return self.owner.read_sync(key)

    def create_sync(self, record):
        self.owner.create_sync(record)

    def compare_exchange_sync(self, key, version, replacement):
        self.owner.compare_exchange_sync(key, version, replacement)

    def invalidate_sync(self, key):
        return self.owner.invalidate_sync(key)


class SharedFixtureManager(BaseManager):
    pass


SharedFixtureManager.register("store", SharedFixtureOwner)


@pytest.mark.asyncio
async def test_total_budget_presend_claim_expiry_is_safe_to_retry() -> None:
    from dataclasses import replace

    f = Fixture()
    try:
        cookie = await f.hosted()
        f.now += 280
        original = f.store.compare_exchange
        acquired = []

        async def slow_before_intent(key, version, replacement):
            if replacement.intent:
                acquired.append(True)
                await asyncio.sleep(1)
            await original(key, version, replacement)

        f.store.compare_exchange = slow_before_intent
        core = ServerSession(
            replace(f.config, auth_budget=.02), f.store,
            http_client=f.http, clock=lambda: f.now,
        )
        with pytest.raises(SessionError, match="IAM_UNAVAILABLE") as error:
            await core.require_session(cookie)
        assert error.value.status == 503 and acquired == [True]
        record = await f.store.read(cookie)
        assert record is not None and record.operation is not None and not record.intent
        assert len(f.forms) == 1
        # The claim has not sent: after its bounded lease it can safely be reacquired.
        f.store.compare_exchange = original
        f.now += 16
        assert "profile" in await f.session.require_session(cookie)
        assert len(f.forms) == 2
    finally:
        await f.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["validity", "refresh_sent"])
async def test_caller_cancellation_remains_cancelled_with_stage_correct_state(stage) -> None:
    f = Fixture()
    entered = asyncio.Event()
    try:
        cookie = await f.hosted()
        if stage == "refresh_sent":
            f.now += 280

        async def slow(request):
            target = "/oauth2/token" if stage == "refresh_sent" else "/validity"
            if request.url.path.endswith(target):
                entered.set()
                await asyncio.Event().wait()
            return f.handle(request)

        async with httpx.AsyncClient(transport=httpx.MockTransport(slow)) as upstream:
            core = ServerSession(f.config, f.store, http_client=upstream, clock=lambda: f.now)
            pending = asyncio.create_task(core.require_session(cookie))
            await entered.wait()
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
            assert (await f.store.read(cookie) is None) == (stage == "refresh_sent")
    finally:
        await f.close()


@pytest.mark.asyncio
async def test_unrelated_timeout_is_not_mapped_as_sdk_budget_expiry() -> None:
    f = Fixture()
    try:
        cookie = await f.hosted()

        async def unrelated_provider_timeout(key):
            raise TimeoutError("provider-specific unrelated timeout")

        f.store.read = unrelated_provider_timeout
        with pytest.raises(TimeoutError, match="provider-specific unrelated timeout"):
            await f.session.require_session(cookie)
    finally:
        await f.close()


def _crash_after_refresh_send(config, owner, cookie):
    import os

    def disconnect(request):
        assert request.url.path == "/oauth2/token"
        owner.mark_send()
        os._exit(0)  # Deliberate fixture process loss after persisted intent and send.

    core = SyncServerSession(
        config, SharedFixturePort(owner), clock=owner.now,
        sync_http_client_factory=lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(disconnect)),
    )
    core.run(core.session(cookie))


@pytest.mark.asyncio
async def test_process_loss_after_send_and_shared_lease_expiry_never_replays() -> None:
    import multiprocessing
    from dataclasses import replace
    # The manager owns the atomic store; SDK processes share only its explicit port.
    manager = SharedFixtureManager(ctx=multiprocessing.get_context("spawn"))
    manager.start()
    fixture = Fixture()
    try:
        cookie = await fixture.hosted()
        record = await fixture.store.read(cookie)
        owner = manager.store(fixture.now)
        owner.create_sync(record)
        owner.advance(280)
        config = replace(fixture.config, replicas=2)
        child = multiprocessing.get_context("spawn").Process(
            target=_crash_after_refresh_send, args=(config, owner, cookie))
        child.start()
        await asyncio.to_thread(child.join, 10)
        assert not child.is_alive() and child.exitcode == 0
        assert owner.send_count() == 1
        core = SyncServerSession(
            config, SharedFixturePort(owner), clock=owner.now,
            sync_http_client_factory=lambda: httpx.AsyncClient(
                transport=httpx.MockTransport(fixture.handle)),
        )
        try:
            with pytest.raises(SessionError, match="SESSION_ACTION_PENDING"):
                await asyncio.to_thread(core.run, core.session(cookie))
            owner.advance(16)
            with pytest.raises(SessionError, match="REFRESH_UNCERTAIN"):
                await asyncio.to_thread(core.run, core.session(cookie))
            assert owner.read_sync(cookie) is None and owner.send_count() == 1
            assert len(fixture.forms) == 1  # Only original code exchange in parent.
        finally:
            await asyncio.to_thread(core.close)
        owner.close()
    finally:
        await fixture.close()
        manager.shutdown()

@pytest.mark.asyncio
async def test_refresh_exclusive_before_send_and_logout_fences_late_commit() -> None:
    f = Fixture()
    sent, release = asyncio.Event(), asyncio.Event()
    async def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == '/oauth2/token':
            sent.set()
            await release.wait()
        return f.handle(request)
    try:
        cookie = await f.hosted()
        snapshot = await f.store.read(cookie)
        assert snapshot is not None
        f.now += 280
        http = httpx.AsyncClient(transport=httpx.MockTransport(handle))
        core = ServerSession(f.config, f.store, http_client=http, clock=lambda: f.now)
        pending = asyncio.create_task(core.session(cookie))
        await sent.wait()
        with pytest.raises(SessionError, match='SESSION_ACTION_PENDING'):
            await core.session(cookie)
        intent = await f.store.read(cookie)
        assert intent is not None and intent.intent and intent.operation is not None
        out = await f.session.logout(cookie, f.config.origin, snapshot.csrf)
        assert out.body['local'] == 'INVALIDATED'
        release.set()
        with pytest.raises(SessionError):
            await pending
        assert await f.store.read(cookie) is None
        assert len(f.forms) == 2  # one code exchange, exactly one refresh send
        await http.aclose()
    finally:
        release.set()
        await f.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['timeout', 'cancel', 'lease', 'commit'])
async def test_sent_refresh_unknown_or_commit_failure_never_replays(failure: str) -> None:
    f = Fixture()
    try:
        cookie = await f.hosted()
        f.now += 280
        async def handle(request: httpx.Request) -> httpx.Response:
            if request.url.path == '/oauth2/token':
                if failure == 'timeout':
                    raise httpx.ReadTimeout('secret body must never leak', request=request)
                if failure == 'cancel':
                    raise asyncio.CancelledError
                if failure == 'lease':
                    f.now += 16
            return f.handle(request)
        http = httpx.AsyncClient(transport=httpx.MockTransport(handle))
        core = ServerSession(f.config, f.store, http_client=http, clock=lambda: f.now)
        original = f.store.compare_exchange
        if failure == 'commit':
            async def fail_commit(key: str, version: int, replacement: object) -> None:
                if replacement.kind == 'session' and replacement.operation is None:
                    raise StoreError('UNAVAILABLE')
                await original(key, version, replacement)
            f.store.compare_exchange = fail_commit
        with pytest.raises((SessionError, asyncio.CancelledError)):
            await core.session(cookie)
        assert await f.store.read(cookie) is None
        count = len(f.forms)
        with pytest.raises(SessionError):
            await core.session(cookie)
        assert len(f.forms) == count
        await http.aclose()
    finally:
        await f.close()


@pytest.mark.asyncio
async def test_known_pre_send_failure_releases_but_expired_intent_never_sends() -> None:
    f = Fixture()
    try:
        cookie = await f.hosted()
        f.now += 280
        async def offline(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError('do not disclose', request=request)
        http = httpx.AsyncClient(transport=httpx.MockTransport(offline))
        core = ServerSession(f.config, f.store, http_client=http, clock=lambda: f.now)
        with pytest.raises(SessionError) as e:
            await core.session(cookie)
        assert e.value.status == 503
        r = await f.store.read(cookie)
        assert r is not None and r.operation is None and not r.intent
        assert len(f.forms) == 1
        held = await f.session._acquire(r)
        await f.session._intent(held)
        f.now += 16
        with pytest.raises(SessionError, match='REFRESH_UNCERTAIN'):
            await f.session.session(cookie)
        assert len(f.forms) == 1 and await f.store.read(cookie) is None
        await http.aclose()
    finally:
        await f.close()


@pytest.mark.asyncio
async def test_refresh_received_then_oidc_dependency_failure_never_restores_old_rt() -> None:
    f = Fixture()
    try:
        cookie = await f.hosted()
        f.now += 280
        f.fail_path = "/.well-known/openid-configuration"
        with pytest.raises(SessionError, match="REFRESH_UNCERTAIN"):
            await f.session.session(cookie)
        assert len(f.forms) == 2 and await f.store.read(cookie) is None
        with pytest.raises(SessionError):
            await f.session.session(cookie)
        assert len(f.forms) == 2
    finally:
        await f.close()


@pytest.mark.asyncio
async def test_refresh_does_not_extend_absolute_bound_and_no_rt_reauthorizes() -> None:
    f = Fixture()
    try:
        cookie = await f.hosted()
        before = await f.store.read(cookie)
        f.now += 280
        await f.session.session(cookie)
        after = await f.store.read(cookie)
        assert before.created_at == after.created_at
        assert before.absolute_expires_at == after.absolute_expires_at
        f.rt = False
        cookie = await f.hosted()
        count = len(f.forms)
        f.now += 301
        with pytest.raises(SessionError, match='SESSION_INVALIDATED'):
            await f.session.session(cookie)
        assert len(f.forms) == count
    finally:
        await f.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('expired,rt,remote',
    [(False,
    True,
    'SESSION_REVOKED'),
    (False,
    False,
    'SESSION_REVOKED'),
    (True,
    True,
    'REFRESH_FAMILY_REVOKED'),
    (True,
    False,
    'NOT_ATTEMPTED')])
async def test_logout_credential_scope_no_implicit_refresh(expired: bool,
    rt: bool,
    remote: str) -> None:
    f = Fixture()
    f.rt = rt
    try:
        cookie = await f.hosted()
        r = await f.store.read(cookie)
        if expired:
            f.now += 301
        before = len(f.forms)
        result = await f.session.logout(cookie, f.config.origin, r.csrf)
        assert result.body == {'local':'INVALIDATED',
            'cookie':'CLEARED',
            'remote':remote,
            'sso':'NOT_REQUESTED'}
        assert result.clear_cookie and len(f.forms) == before
        assert await f.store.read(cookie) is None
    finally:
        await f.close()


@pytest.mark.asyncio
async def test_logout_storage_and_remote_failures_are_reported_separately() -> None:
    f = Fixture()
    try:
        cookie = await f.hosted()
        r = await f.store.read(cookie)
        original = f.store.invalidate
        async def unavailable(key: str) -> bool:
            raise StoreError('UNAVAILABLE')
        f.store.invalidate = unavailable
        result = await f.session.logout(cookie, f.config.origin, r.csrf)
        assert result.status == 503 and result.body['local'] == 'UNCONFIRMED'
        assert result.body['remote'] == 'SESSION_REVOKED'
        f.store.invalidate = original
        f.fail_path = '/api/v1/auth/logout'
        result = await f.session.logout(cookie, f.config.origin, r.csrf)
        assert result.status == 503 and result.body['local'] == 'INVALIDATED'
        assert result.body['remote'] == 'UNCONFIRMED'
    finally:
        await f.close()


def test_explicit_sync_runtime_reused_and_store_port() -> None:
    f = Fixture()
    core = f.sync()
    try:
        one = core.run(core.bootstrap(None))
        runner = core._runtime._runner
        two = core.run(core.bootstrap(None))
        assert core._runtime._runner is runner and one.cookie != two.cookie
        r = core.run(core.store.read(text(one.cookie)))
        assert r is not None
        assert f.store.read_sync(r.key).csrf == r.csrf
    finally:
        core.close()
        f.store.close()


@pytest.mark.asyncio
async def test_sync_channel_rejects_active_event_loop() -> None:
    f = Fixture()
    core = f.sync()
    try:
        with pytest.raises(RuntimeError, match='active event loop'):
            core.run(core.bootstrap(None))
    finally:
        await asyncio.to_thread(core.close)
        await f.close()
