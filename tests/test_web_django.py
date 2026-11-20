from __future__ import annotations

import asyncio
import sys
import types

import django
import pytest
from django.conf import settings
from django.http import HttpRequest, JsonResponse
from django.test import AsyncClient, Client, RequestFactory, override_settings
from django.urls import path

if not settings.configured:
    settings.configure(SECRET_KEY='isolated-bff-test', ALLOWED_HOSTS=['*'], DEFAULT_CHARSET='utf-8',
        INSTALLED_APPS=[], ROOT_URLCONF=__name__)
    django.setup()

from bff_fixture import Fixture  # noqa: E402

from axis_vertex.django.web_session import (  # noqa: E402
    WebSessionMiddleware,
    async_session_middleware,
    require_async_web_session,
    require_web_session,
    session_urls,
    web_session_from_request,
)
from axis_vertex.web_session.models import obj, text  # noqa: E402


@pytest.mark.asyncio
@pytest.mark.parametrize("channel", ["sync", "async"])
@pytest.mark.parametrize("cached", [False, True])
async def test_business_writes_require_current_cookie_origin_csrf_django(channel, cached) -> None:
    f = Fixture()
    calls = []
    core = f.sync() if channel == "sync" else f.session
    module = types.ModuleType("isolated_bff_business_csrf_" + channel + str(cached))
    try:
        cookie = await f.hosted()
        view = (await f.session.session(cookie)).body
        csrf = text(view["csrfToken"])
        if channel == "sync":
            @require_web_session(core)
            def guarded(request):
                calls.append(True)
                return JsonResponse({"ok": True})

            def endpoint(request):
                if cached:
                    request.axis_web_session = view
                return guarded(request)
        else:
            @require_async_web_session(core)
            async def guarded(request):
                calls.append(True)
                return JsonResponse({"ok": True})

            async def endpoint(request):
                if cached:
                    request.axis_web_session = view
                return await guarded(request)

        module.urlpatterns = [path("write", endpoint)]
        sys.modules[module.__name__] = module
        with override_settings(ROOT_URLCONF=module.__name__, MIDDLEWARE=[]):
            client = Client() if channel == "sync" else AsyncClient()
            client.cookies[f.config.cookie_name] = cookie

            async def send(method, headers):
                args = {"secure": True, **headers}
                if channel == "sync":
                    return await asyncio.to_thread(client.generic, method, "/write", **args)
                return await client.generic(method, "/write", secure=True, headers={
                    key.removeprefix("HTTP_").replace("_", "-"): value
                    for key, value in headers.items()
                })

            invalid = [
                {}, {"HTTP_X_CSRF_TOKEN": csrf},
                {"HTTP_ORIGIN": "https://foreign.example", "HTTP_X_CSRF_TOKEN": csrf},
                {"HTTP_ORIGIN": f.config.origin + "/", "HTTP_X_CSRF_TOKEN": csrf},
                {"HTTP_ORIGIN": f.config.origin},
                {"HTTP_ORIGIN": f.config.origin, "HTTP_X_CSRF_TOKEN": "wrong"},
            ]
            for method in ("POST", "PATCH", "DELETE"):
                for headers in invalid:
                    before = len(calls)
                    response = await send(method, headers)
                    assert response.status_code == 403
                    assert response.json()["error"] == "SESSION_CSRF_INVALID"
                    assert response["Cache-Control"] == "no-store"
                    assert b"controlled-" not in response.content
                    assert len(calls) == before
                assert (await send(method, {"HTTP_ORIGIN": f.config.origin,
                    "HTTP_X_CSRF_TOKEN": csrf})).status_code == 200
            for method in ("GET", "HEAD", "OPTIONS"):
                assert (await send(method, {})).status_code == 200
            assert len(calls) == 6
            record = await f.store.read(cookie)
            previous_version = record.version
            record.version += 1
            record.csrf = "n" * 43
            await f.store.compare_exchange(cookie, previous_version, record)
            assert (await send("POST", {"HTTP_ORIGIN": f.config.origin,
                "HTTP_X_CSRF_TOKEN": csrf})).status_code == 403
            assert (await send("POST", {"HTTP_ORIGIN": f.config.origin,
                "HTTP_X_CSRF_TOKEN": record.csrf})).status_code == 200
            client.cookies.clear()
            assert (await send("POST", {"HTTP_ORIGIN": f.config.origin,
                "HTTP_X_CSRF_TOKEN": csrf})).status_code == 401
            assert len(calls) == 7
    finally:
        if channel == "sync":
            await asyncio.to_thread(core.close)
        await f.close()
        sys.modules.pop(module.__name__, None)


def test_business_write_sdk_and_native_django_csrf_both_required() -> None:
    from django.middleware.csrf import get_token

    f = Fixture()
    core = f.sync()
    calls = []
    module = types.ModuleType("isolated_bff_native_business_csrf")
    try:
        cookie = asyncio.run(f.hosted())
        csrf = f.store.read_sync(cookie).csrf

        def native_token(request):
            return JsonResponse({"native": get_token(request)})

        @require_web_session(core)
        def write(request):
            calls.append(True)
            return JsonResponse({"ok": True})

        module.urlpatterns = [path("native", native_token), path("write", write)]
        sys.modules[module.__name__] = module
        with override_settings(ROOT_URLCONF=module.__name__,
            MIDDLEWARE=["django.middleware.csrf.CsrfViewMiddleware"]):
            client = Client(enforce_csrf_checks=True)
            client.cookies[f.config.cookie_name] = cookie
            native = client.get("/native", secure=True).json()["native"]
            headers = {"HTTP_ORIGIN": f.config.origin, "HTTP_HOST": "app.example.test",
                       "HTTP_X_CSRF_TOKEN": csrf, "HTTP_X_CSRFTOKEN": native}
            assert client.post("/write", secure=True, **headers).status_code == 200
            headers["HTTP_X_CSRF_TOKEN"] = "wrong"
            response = client.post("/write", secure=True, **headers)
            assert response.status_code == 403
            assert response.json()["error"] == "SESSION_CSRF_INVALID"
            headers["HTTP_X_CSRF_TOKEN"] = csrf
            headers.pop("HTTP_X_CSRFTOKEN")
            assert client.post("/write", secure=True, **headers).status_code == 403
            assert calls == [True]
    finally:
        core.close()
        asyncio.run(f.close())
        sys.modules.pop(module.__name__, None)


@pytest.mark.parametrize("stage", ["validity", "refresh_sent"])
def test_django_sync_business_auth_budget_returns_sanitized_503(stage) -> None:
    from dataclasses import replace

    import httpx

    from axis_vertex.web_session import SyncServerSession

    f = Fixture()
    entered, business_calls = [], []
    core = None
    module = types.ModuleType("isolated_python_bff_sync_budget_urls")
    try:
        cookie = asyncio.run(f.hosted())
        if stage == "refresh_sent":
            f.now += 280

        async def slow(request):
            target = "/oauth2/token" if stage == "refresh_sent" else "/validity"
            if request.url.path.endswith(target):
                entered.append(request.url.path)
                await asyncio.sleep(1)
            return f.handle(request)

        core = SyncServerSession(
            replace(f.config, auth_budget=.02, upstream_timeout=2), f.store,
            sync_http_client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(slow)),
            clock=lambda: f.now,
        )

        @require_web_session(core, "documents:read")
        def documents(request):
            business_calls.append(True)
            return JsonResponse({"ok": True})

        module.urlpatterns = [path("documents", documents)]
        sys.modules[module.__name__] = module
        with override_settings(ROOT_URLCONF=module.__name__, MIDDLEWARE=[]):
            client = Client(raise_request_exception=False)
            client.cookies[f.config.cookie_name] = cookie
            response = client.get("/documents", secure=True)
            assert response.status_code == 503
            error = response.json()
            assert error["error"] == error["message"] == "IAM_UNAVAILABLE"
            assert error["status"] == 503
            assert response["Cache-Control"] == "no-store"
            assert b"controlled-" not in response.content and b"Traceback" not in response.content
            assert not business_calls and len(entered) == 1
            assert (f.store.read_sync(cookie) is None) == (stage == "refresh_sent")
            if stage == "refresh_sent":
                assert client.get("/documents", secure=True).status_code == 401
                assert len(entered) == 1
    finally:
        if core is not None:
            core.close()
        asyncio.run(f.close())
        sys.modules.pop(module.__name__, None)


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["validity", "refresh_sent"])
async def test_django_async_business_auth_budget_returns_sanitized_503(stage) -> None:
    from dataclasses import replace

    import httpx

    from axis_vertex.web_session import ServerSession

    f = Fixture()
    entered, business_calls = [], []
    module = types.ModuleType("isolated_python_bff_async_budget_urls")
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
                replace(f.config, auth_budget=.02, upstream_timeout=2), f.store,
                http_client=upstream, clock=lambda: f.now,
            )

            @require_async_web_session(core, "documents:read")
            async def documents(request):
                business_calls.append(True)
                return JsonResponse({"ok": True})

            module.urlpatterns = [path("documents", documents)]
            sys.modules[module.__name__] = module
            with override_settings(ROOT_URLCONF=module.__name__, MIDDLEWARE=[]):
                client = AsyncClient(raise_request_exception=False)
                client.cookies[f.config.cookie_name] = cookie
                response = await client.get("/documents", secure=True)
                assert response.status_code == 503
                error = response.json()
                assert error["error"] == error["message"] == "IAM_UNAVAILABLE"
                assert error["status"] == 503
                assert response["Cache-Control"] == "no-store"
                assert b"controlled-" not in response.content
                assert b"Traceback" not in response.content
                assert not business_calls and len(entered) == 1
                assert (await f.store.read(cookie) is None) == (stage == "refresh_sent")
                if stage == "refresh_sent":
                    assert (await client.get("/documents", secure=True)).status_code == 401
                    assert len(entered) == 1
    finally:
        await f.close()
        sys.modules.pop(module.__name__, None)


def test_django_urls_sync_hosted_csrf_guards_and_signed_host_session_is_not_auth_store() -> None:
    f = Fixture()
    core = f.sync()
    module = types.ModuleType('isolated_python_bff_urls')
    @require_web_session(core, 'documents:read')
    def documents(request: HttpRequest) -> JsonResponse:
        first = web_session_from_request(request)
        assert first is web_session_from_request(request)
        return JsonResponse({'user': obj(first['profile'])['id']})
    @require_web_session(core, 'documents:write')
    def write(request: HttpRequest) -> JsonResponse:
        return JsonResponse({'ok':True})
    def host(request: HttpRequest) -> JsonResponse:
        request.session['cart'] = 'preserved'
        return JsonResponse({'cart':request.session['cart']})
    module.urlpatterns = [*session_urls(core),
        path('documents',
        documents),
        path('write',
        write),
        path('host',
        host)]
    sys.modules[module.__name__]=module
    module.auth_middleware = lambda next_handler: WebSessionMiddleware(
        next_handler, core, paths=("/documents",))
    try:
        with override_settings(ROOT_URLCONF=module.__name__,
            SESSION_ENGINE='django.contrib.sessions.backends.signed_cookies',

            MIDDLEWARE=['django.contrib.sessions.middleware.SessionMiddleware',
                'django.middleware.csrf.CsrfViewMiddleware',
                module.__name__ + ".auth_middleware"]):
            client=Client(enforce_csrf_checks=True)
            assert client.get('/documents',secure=True).status_code==401
            assert client.get('/auth/login',secure=True).status_code==401
            client.get('/host',secure=True)
            host_cookie=client.cookies['sessionid'].value
            bootstrap=client.get('/auth/session/bootstrap',secure=True)
            assert bootstrap.status_code==200
            cookie=client.cookies[f.config.cookie_name].value
            assert bootstrap.cookies[f.config.cookie_name]['httponly']
            assert bootstrap.cookies[f.config.cookie_name]['secure']
            assert client.post('/auth/session/login',
                {},
                content_type='application/json',
                secure=True).status_code==403
            assert client.get('/auth/callback?state=a&state=b',secure=True).status_code==400
            response=client.get('/auth/login',secure=True)
            assert response.status_code==302
            r=f.store.read_sync(cookie)
            f.nonce=text(r.data['nonce'])
            callback=client.get('/auth/callback',
                {'code':'controlled-code',
                'state':r.data['oauth_state']},
                secure=True)
            assert callback.status_code==302 and callback['Location']=='/'
            assert callback['Referrer-Policy']=='no-referrer'
            identity_cookie=client.cookies[f.config.cookie_name].value
            before=sum(p.endswith('/validity') for _,p in f.calls)
            assert client.get('/documents',secure=True).json()=={'user':f.subject}
            assert sum(p.endswith('/validity') for _,p in f.calls)==before+1
            assert client.get('/write',secure=True).status_code==403
            assert client.get('/documents',
                secure=True,
                HTTP_AUTHORIZATION='Bearer bad').status_code==401
            view=client.get('/auth/session',secure=True).json()
            logout=client.post('/auth/session/logout',
                {},
                content_type='application/json',
                secure=True,

                HTTP_ORIGIN=f.config.origin,HTTP_X_CSRF_TOKEN=view['csrfToken'])
            assert logout.json()['local']=='INVALIDATED'
            assert logout.cookies[f.config.cookie_name]['max-age']==0
            client.cookies['sessionid']=host_cookie
            assert client.get('/host',secure=True).json()=={'cart':'preserved'}
            client.cookies[f.config.cookie_name]=identity_cookie
            assert client.get('/documents',secure=True).status_code==401
    finally:
        core.close()
        asyncio.run(f.close())
        del sys.modules[module.__name__]


def test_django_custom_real_views_mfa_registration_and_reset() -> None:
    f=Fixture()
    f.mfa=True
    core=f.sync()
    module=types.ModuleType('isolated_python_bff_custom_urls')
    module.urlpatterns=session_urls(core)
    sys.modules[module.__name__]=module
    try:
        with override_settings(ROOT_URLCONF=module.__name__):
            client=Client()
            b=client.get('/auth/session/bootstrap',secure=True).json()
            headers={'secure':True,'HTTP_ORIGIN':f.config.origin,'HTTP_X_CSRF_TOKEN':b['csrfToken']}
            def post(suffix,body):
                return client.post('/auth/'+suffix,body,content_type='application/json',**headers)
            assert post('session/login',{}).json()['state']=='AUTHENTICATING'
            assert post('session/login/authenticate',
                {'method':'PASSWORD',
                'identifier':{'kind':'EMAIL',
                'value':'reader@example.test'},
                'password':'valid'}).json()['state']=='MFA_REQUIRED'
            assert post('session/login/mfa',
                {'method':'TOTP',
                'code':'123456'}).json()['nextAction']=='complete'
            result=post('session/login/complete',{})
            assert result.status_code==200 and 'profile' in result.json()
            view=client.get('/auth/session',secure=True).json()
            headers['HTTP_X_CSRF_TOKEN']=view['csrfToken']
            post('session/logout',{})
            b=client.get('/auth/session/bootstrap',secure=True).json()
            headers['HTTP_X_CSRF_TOKEN']=b['csrfToken']
            ref=post('registration',
                {'identifier':{'kind':'EMAIL',
                'value':'reader@example.test'},
                'password':'valid'}).json()['registrationId']
            assert post('registration/'+ref+'/complete',
                {'code':'123456'}).json()['status']=='COMPLETED'
            assert post('password-reset/request',{'email':'reader@example.test'}).status_code==204
            assert post('password-reset/complete',
                {'token':'controlled-reset',
                'newPassword':'valid'}).status_code==204
    finally:
        core.close()
        asyncio.run(f.close())
        del sys.modules[module.__name__]


@pytest.mark.asyncio
async def test_django_async_routes_context_and_no_sync_loop_wrapper() -> None:
    f=Fixture()
    module=types.ModuleType('isolated_python_bff_async_urls')
    @require_async_web_session(f.session,'documents:read')
    async def view(request: HttpRequest) -> JsonResponse:
        return JsonResponse({'user':obj(web_session_from_request(request)['profile'])['id']})
    module.urlpatterns=[*session_urls(f.session),path('documents',view)]
    module.auth_middleware = async_session_middleware(f.session, paths=("/documents",))
    sys.modules[module.__name__]=module
    try:
        cookie=await f.hosted()
        with override_settings(
            ROOT_URLCONF=module.__name__, MIDDLEWARE=[module.__name__ + ".auth_middleware"]
        ):
            client=AsyncClient()
            client.cookies[f.config.cookie_name]=cookie
            assert (await client.get('/documents',secure=True)).json()=={'user':f.subject}
            client.cookies.clear()
            assert (await client.get('/documents',secure=True)).status_code==401
            assert (await client.get('/auth/session/bootstrap',secure=True)).status_code==200
    finally:
        await f.close()
        del sys.modules[module.__name__]


def test_django_late_automatic_session_save_is_fenced_after_logout() -> None:
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    f = Fixture()
    core = f.sync()
    entered, release = Event(), Event()
    module = types.ModuleType("isolated_python_bff_late_urls")

    @require_web_session(core)
    def late(request: HttpRequest) -> JsonResponse:
        request.session["cart"] = "late-preserved"
        entered.set()
        assert release.wait(10)
        return JsonResponse({"ok": True})

    module.urlpatterns = [*session_urls(core), path("late", late)]
    sys.modules[module.__name__] = module
    try:
        cookie = asyncio.run(f.hosted())
        csrf = f.store.read_sync(cookie).csrf
        with override_settings(
            ROOT_URLCONF=module.__name__,
            SESSION_ENGINE="django.contrib.sessions.backends.signed_cookies",
            MIDDLEWARE=["django.contrib.sessions.middleware.SessionMiddleware"],
        ), ThreadPoolExecutor(max_workers=1) as pool:
            old_client = Client()
            old_client.cookies[f.config.cookie_name] = cookie
            pending = pool.submit(old_client.get, "/late", secure=True)
            assert entered.wait(10)
            main = Client()
            main.cookies[f.config.cookie_name] = cookie
            result = main.post(
                "/auth/session/logout", {}, content_type="application/json", secure=True,
                HTTP_ORIGIN=f.config.origin, HTTP_X_CSRF_TOKEN=csrf,
            )
            assert result.json()["local"] == "INVALIDATED"
            release.set()
            response = pending.result(timeout=10)
            assert "sessionid" in response.cookies
            assert f.config.cookie_name not in response.cookies
            assert f.store.read_sync(cookie) is None
            factory = RequestFactory()
            request = factory.get("/protected")
            request.COOKIES[f.config.cookie_name] = cookie
            assert late(request).status_code == 401
    finally:
        release.set()
        core.close()
        asyncio.run(f.close())
        del sys.modules[module.__name__]
