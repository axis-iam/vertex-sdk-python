from __future__ import annotations

import asyncio

import httpx
import pytest
from bff_fixture import Fixture
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient
from starlette.middleware.sessions import SessionMiddleware

from axis_vertex.fastapi.web_session import (
    WebSessionMiddleware,
    require_web_session,
    session_router,
    web_session_from_request,
)
from axis_vertex.web_session.models import obj, text


@pytest.mark.asyncio
@pytest.mark.parametrize("entry", ["dependency", "middleware", "both"])
@pytest.mark.parametrize("cached", [False, True])
async def test_business_writes_require_current_cookie_origin_csrf_fastapi(entry, cached) -> None:
    f = Fixture()
    calls = []
    try:
        cookie = await f.hosted()
        view = (await f.session.session(cookie)).body
        csrf = text(view["csrfToken"])
        app = FastAPI()
        if entry in {"middleware", "both"}:
            app.add_middleware(WebSessionMiddleware, session=f.session, paths=("/write",))
        if cached:
            @app.middleware("http")
            async def cached_identity(request, call_next):
                request.state.axis_web_session = view
                return await call_next(request)
        dependencies = [] if entry == "middleware" else [Depends(require_web_session(f.session))]

        @app.api_route("/write", methods=["GET", "HEAD", "OPTIONS", "POST", "PATCH", "DELETE"],
                       dependencies=dependencies)
        async def write():
            calls.append(True)
            return {"ok": True}

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
            base_url=f.config.origin, cookies={f.config.cookie_name: cookie}) as client:
            invalid = [
                {}, {"X-CSRF-Token": csrf},
                {"Origin": "https://foreign.example", "X-CSRF-Token": csrf},
                {"Origin": f.config.origin + "/", "X-CSRF-Token": csrf},
                {"Origin": f.config.origin},
                {"Origin": f.config.origin, "X-CSRF-Token": "wrong"},
            ]
            for method in ("POST", "PATCH", "DELETE"):
                for headers in invalid:
                    before = len(calls)
                    response = await client.request(method, "/write", headers=headers)
                    assert response.status_code == 403
                    assert "SESSION_CSRF_INVALID" in response.text
                    assert "controlled-" not in response.text
                    assert response.headers["cache-control"] == "no-store"
                    assert len(calls) == before
                assert (await client.request(method, "/write", headers={
                    "Origin": f.config.origin, "X-CSRF-Token": csrf})).status_code == 200
            for method in ("GET", "HEAD", "OPTIONS"):
                assert (await client.request(method, "/write")).status_code == 200
            assert len(calls) == 6
            record = await f.store.read(cookie)
            previous_version = record.version
            record.version += 1
            record.csrf = "n" * 43
            await f.store.compare_exchange(cookie, previous_version, record)
            assert (await client.post("/write", headers={
                "Origin": f.config.origin, "X-CSRF-Token": csrf})).status_code == 403
            assert (await client.post("/write", headers={
                "Origin": f.config.origin, "X-CSRF-Token": record.csrf})).status_code == 200
            client.cookies.clear()
            assert (await client.post("/write", headers={
                "Origin": f.config.origin, "X-CSRF-Token": csrf})).status_code == 401
            assert len(calls) == 7
    finally:
        await f.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("entry", ["dependency", "middleware"])
@pytest.mark.parametrize("stage", ["validity", "refresh_sent"])
async def test_fastapi_business_auth_budget_returns_sanitized_503(entry, stage) -> None:
    from dataclasses import replace

    from axis_vertex.web_session import ServerSession

    f = Fixture()
    entered, business_calls = [], []
    try:
        cookie = await f.hosted()
        if stage == "refresh_sent":
            f.now += 280

        async def slow(request):
            target = "/oauth2/token" if stage == "refresh_sent" else "/validity"
            if request.url.path.endswith(target):
                entered.append(request.url.path)
                await asyncio.sleep(1)
            return f.handle(request)

        async with httpx.AsyncClient(transport=httpx.MockTransport(slow)) as upstream:
            core = ServerSession(
                replace(f.config, auth_budget=.02, upstream_timeout=2),
                f.store, http_client=upstream, clock=lambda: f.now,
            )
            app = FastAPI()
            if entry == "middleware":
                app.add_middleware(WebSessionMiddleware, session=core, paths=("/documents",))
                dependencies = []
            else:
                dependencies = [Depends(require_web_session(core, "documents:read"))]

            @app.get("/documents", dependencies=dependencies)
            async def documents():
                business_calls.append(True)
                return {"ok": True}

            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                base_url=f.config.origin, cookies={f.config.cookie_name: cookie},
            ) as client:
                response = await client.get("/documents")
                assert response.status_code == 503
                error = response.json()
                if entry == "dependency":
                    error = error["detail"]
                assert error["error"] == error["message"] == "IAM_UNAVAILABLE"
                assert error["status"] == 503
                assert response.headers["cache-control"] == "no-store"
                assert "controlled-" not in response.text and "Traceback" not in response.text
                assert not business_calls and len(entered) == 1
                record = await f.store.read(cookie)
                assert (record is None) == (stage == "refresh_sent")
                if stage == "refresh_sent":
                    assert (await client.get("/documents")).status_code == 401
                    assert len(entered) == 1
    finally:
        await f.close()


def application(f: Fixture) -> FastAPI:
    app = FastAPI()
    app.add_middleware(WebSessionMiddleware, session=f.session, paths=("/documents",))
    app.add_middleware(SessionMiddleware,
        secret_key='unrelated-host-test-session',
        session_cookie='host-session')
    app.include_router(session_router(f.session))
    @app.get('/documents', dependencies=[Depends(require_web_session(f.session, 'documents:read'))])
    async def documents(request: Request) -> dict[str, object]:
        first = web_session_from_request(request)
        assert web_session_from_request(request) is first
        return {'user': obj(first['profile'])['id']}
    @app.post('/documents',
        dependencies=[Depends(require_web_session(f.session,
        'documents:write'))])
    async def write() -> dict[str, bool]:
        return {'ok': True}
    @app.get('/host')
    async def host(request: Request) -> dict[str, object]:
        request.session['unrelated'] = 'preserved'
        return {'host': request.session['unrelated']}
    return app


def test_fastapi_real_router_hosted_csrf_context_permissions_and_cookie() -> None:
    f = Fixture()
    try:
        with TestClient(application(f), base_url=f.config.origin) as client:
            assert client.get('/auth/login', follow_redirects=False).status_code == 401
            bootstrap = client.get('/auth/session/bootstrap')
            assert bootstrap.status_code == 200
            cookie = client.cookies[f.config.cookie_name]
            header = bootstrap.headers['set-cookie']
            assert all(x in header for x in ['HttpOnly','Secure','SameSite=lax','Path=/'])
            assert bootstrap.headers['cache-control'] == 'no-store'
            assert client.post('/auth/session/login', json={}).status_code == 403
            assert client.get('/auth/callback?state=a&state=b&code=c').status_code == 400
            hosted = client.get('/auth/login', follow_redirects=False)
            assert hosted.status_code == 302
            assert 'code_challenge_method=S256' in hosted.headers['location']
            r = f.store.read_sync(cookie)
            f.nonce = text(r.data['nonce'])
            callback = client.get('/auth/callback',
                params={'code':'controlled-code',
                'state':r.data['oauth_state']},
                follow_redirects=False)
            assert callback.status_code == 302 and callback.headers['location'] == '/'
            assert callback.headers['referrer-policy'] == 'no-referrer'
            assert client.cookies[f.config.cookie_name] != cookie
            before = sum(path.endswith('/validity') for _,path in f.calls)
            assert client.get('/documents').json() == {'user':f.subject}
            assert sum(path.endswith('/validity') for _,path in f.calls) == before+1
            assert client.post('/documents').status_code == 403
            assert client.get('/documents',
                headers={'Authorization':'Bearer invalid'}).status_code == 401
            view = client.get('/auth/session').json()
            logout = client.post('/auth/session/logout',
                json={},
                headers={'Origin':f.config.origin,
                'X-CSRF-Token':view['csrfToken']})
            assert logout.json()['local'] == 'INVALIDATED'
            assert 'Max-Age=0' in logout.headers['set-cookie']
            assert client.get('/documents').status_code == 401
    finally:
        asyncio.run(f.close())


def test_fastapi_custom_mfa_and_unrelated_session_late_save_cannot_revive() -> None:
    f = Fixture()
    f.mfa = True
    try:
        with TestClient(application(f), base_url=f.config.origin) as client:
            client.get('/host')
            host_cookie = client.cookies['host-session']
            b = client.get('/auth/session/bootstrap').json()
            headers = {'Origin':f.config.origin,'X-CSRF-Token':b['csrfToken']}
            assert client.post('/auth/session/login',
                json={},
                headers=headers).json()['state'] == 'AUTHENTICATING'
            assert client.post('/auth/session/login/authenticate',
                json={'method':'PASSWORD',
                'identifier':{'kind':'EMAIL',
                'value':'reader@example.test'},
                'password':'valid'},
                headers=headers).json()['state']=='MFA_REQUIRED'
            assert client.post('/auth/session/login/mfa',
                json={'method':'TOTP',
                'code':'123456'},
                headers=headers).json()['nextAction']=='complete'
            assert client.post('/auth/session/login/complete',
                json={},
                headers=headers).json()['state']=='AUTHENTICATED'
            identity_cookie = client.cookies[f.config.cookie_name]
            view = client.get('/auth/session').json()
            stale_native_cookie = client.cookies['host-session']
            client.post('/auth/session/logout',
                json={},
                headers={'Origin':f.config.origin,
                'X-CSRF-Token':view['csrfToken']})
            client.cookies.set('host-session', stale_native_cookie, domain='app.example.test')
            assert client.get('/host').json() == {'host':'preserved'}
            client.cookies.set(f.config.cookie_name, identity_cookie, domain='app.example.test')
            assert client.get('/documents').status_code == 401
            assert client.cookies['host-session'] == host_cookie
    finally:
        asyncio.run(f.close())


@pytest.mark.asyncio
async def test_fastapi_asgi_async_store_never_uses_sync_provider_and_is_request_local() -> None:
    from axis_vertex.web_session import ServerSession
    from axis_vertex.web_session.store import StoreCapabilities
    f = Fixture()
    class AsyncOnly:
        capabilities = StoreCapabilities(True, False, False)
        async def read(self, key):
            return await f.store.read(key)
        async def create(self, r):
            return await f.store.create(r)
        async def compare_exchange(self, key, version, r):
            return await f.store.compare_exchange(key,version,r)
        async def invalidate(self,key):
            return await f.store.invalidate(key)
    f.session = ServerSession(f.config, AsyncOnly(), http_client=f.http, clock=lambda:f.now)
    try:
        cookie = await f.hosted()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=application(f)),
            base_url=f.config.origin) as client:
            client.cookies.set(f.config.cookie_name,cookie)
            assert (await client.get('/documents')).status_code == 200
            client.cookies.clear()
            assert (await client.get('/documents')).status_code == 401
    finally:
        await f.close()


@pytest.mark.asyncio
async def test_starlette_late_automatic_save_after_logout_cannot_restore_identity() -> None:
    f = Fixture()
    entered, release = asyncio.Event(), asyncio.Event()
    app = application(f)

    @app.get("/late", dependencies=[Depends(require_web_session(f.session))])
    async def late(request: Request) -> dict[str, bool]:
        request.session["cart"] = "late-preserved"
        entered.set()
        await release.wait()
        return {"ok": True}

    try:
        cookie = await f.hosted()
        view = (await f.session.session(cookie)).body
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=f.config.origin
        ) as client:
            client.cookies.set(f.config.cookie_name, cookie)
            pending = asyncio.create_task(client.get("/late"))
            await entered.wait()
            logout = await client.post(
                "/auth/session/logout", json={},
                headers={"Origin": f.config.origin, "X-CSRF-Token": text(view["csrfToken"])},
            )
            assert logout.json()["local"] == "INVALIDATED"
            release.set()
            response = await pending
            assert response.status_code == 200
            assert "host-session=" in response.headers["set-cookie"]
            assert f.config.cookie_name not in response.headers["set-cookie"]
            assert await f.store.read(cookie) is None
            # Even explicitly replaying the old auth Cookie after the late native save fails.
            client.cookies.clear()
            client.cookies.set(f.config.cookie_name, cookie)
            assert (await client.get("/documents")).status_code == 401
    finally:
        release.set()
        await f.close()
