"""Framework-independent Hosted/custom session lifecycle with fenced operations."""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import hmac
import inspect
import time
from collections.abc import Callable, Coroutine
from typing import Literal
from urllib.parse import quote, urlencode, urlsplit

import httpx

from axis_vertex._sync_runtime import SyncRuntime
from axis_vertex.errors import IamConfigError
from axis_vertex.permissions import PermissionKey, has_permission

from .capabilities import parse_capabilities
from .models import (
    JsonObject,
    Record,
    SessionConfig,
    SessionError,
    SessionResult,
    StoreError,
    epoch,
    exact,
    integer,
    obj,
    parse_view,
    random_id,
    text,
    timestamp,
    uuid_text,
)
from .protocol import SessionProtocol
from .store import AsyncFromSyncStore, AsyncSessionStore, SyncSessionStore


class ServerSession:
    """Explicit async server_session core. Pass one application-owned store instance.

    Caller owns injected HTTP and store lifetimes. ``aclose`` closes SDK-owned HTTP.
    Authentication getters never call this core implicitly.
    """

    def __init__(
        self,
        config: SessionConfig,
        store: AsyncSessionStore,
        *,
        http_client: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.time,
    ):
        if not isinstance(store, AsyncSessionStore):
            raise IamConfigError("an explicit async session provider is required")
        if not all(inspect.iscoroutinefunction(getattr(store, name)) for name in (
            "read", "create", "compare_exchange", "invalidate"
        )):
            raise IamConfigError("async provider operations must be native async methods")
        c = store.capabilities
        if not c.atomic or not c.server_side or (config.replicas > 1 and not c.shared):
            raise IamConfigError("provider lacks required server-side atomic/shared coordination")
        if isinstance(store, AsyncFromSyncStore) and type(self) is ServerSession:
            raise IamConfigError("sync provider bridge is only supported by SyncServerSession")
        self.config, self.store, self.clock = config, store, clock
        self._owned_http = http_client is None
        self._http = http_client if http_client is not None else httpx.AsyncClient()

    def _protocol(self) -> SessionProtocol:
        return SessionProtocol(self.config, self._http, self.clock)

    async def aclose(self) -> None:
        if self._owned_http:
            await self._http.aclose()

    async def _load(self, key: str | None, kind: str | None = None) -> Record:
        if key is None:
            raise SessionError("SESSION_REQUIRED", 401)
        if len(key) != 43:
            raise SessionError("SESSION_INVALIDATED", 401)
        r = await self.store.read(key)
        if r is None or r.kind == "terminal" or (kind is not None and r.kind != kind):
            raise SessionError("SESSION_INVALIDATED", 401)
        if min(r.absolute_expires_at, r.idle_expires_at) <= self.clock():
            await self.store.invalidate(key)
            raise SessionError("SESSION_INVALIDATED", 401)
        return r

    def csrf(self, record: Record, origin: str | None, csrf: str | None) -> None:
        if (
            origin != self.config.origin
            or csrf is None
            or not hmac.compare_digest(record.csrf, csrf)
        ):
            raise SessionError("SESSION_CSRF_INVALID", 403)

    async def _save(self, old: Record, new: Record) -> Record:
        new.version = old.version + 1
        await self.store.compare_exchange(old.key, old.version, new)
        return new

    async def _acquire(self, r: Record) -> Record:
        if r.operation is not None:
            if r.lease_until > self.clock():
                raise SessionError("SESSION_ACTION_PENDING", 409)
            if r.intent:
                await self.store.invalidate(r.key)
                raise SessionError(
                    "REFRESH_UNCERTAIN" if r.kind == "session" else "AUTH_EXCHANGE_UNCERTAIN", 401
                )
        new = copy.deepcopy(r)
        new.operation, new.lease_until, new.intent = (
            random_id(),
            self.clock() + self.config.lease,
            False,
        )
        return await self._save(r, new)

    async def _intent(self, r: Record) -> Record:
        new = copy.deepcopy(r)
        new.intent = True
        return await self._save(r, new)

    async def _release(self, r: Record) -> Record:
        new = copy.deepcopy(r)
        new.operation, new.intent, new.lease_until = None, False, 0
        return await self._save(r, new)

    def view(self, r: Record) -> JsonObject:
        v: JsonObject = {
            "state": r.data.get("state", "PRELOGIN"),
            "expiresAt": timestamp(min(r.absolute_expires_at, r.idle_expires_at)),
            "csrfToken": r.csrf,
        }
        if r.kind == "session":
            v.update(
                state="AUTHENTICATED",
                owner=r.owner,
                version=r.version,
                profile=copy.deepcopy(r.data["profile"]),
                permissions=copy.deepcopy(r.data["permissions"]),
            )
        else:
            for k in ("nextAction", "challengeExpiresAt", "cooldownSeconds", "authorizationUrl"):
                if k in r.data:
                    v[k] = r.data[k]
        return parse_view(v)

    async def bootstrap(self, key: str | None) -> SessionResult:
        if key is not None:
            existing = await self.store.read(key)
            if existing is not None:
                return await self.session(key)
        now = self.clock()
        r = Record(
            random_id(),
            "prelogin",
            now,
            now + min(self.config.prelogin_ttl, 600),
            now + min(self.config.prelogin_ttl, 600),
        )
        await self.store.create(r)
        return SessionResult(self.view(r), cookie=r.key)

    async def hosted_login(self, key: str | None, return_path: str = "/") -> SessionResult:
        if return_path not in self.config.return_paths:
            raise SessionError("VALIDATION_ERROR")
        r = await self._load(key, "prelogin")
        if r.data.get("state") is not None:
            raise SessionError("SESSION_ACTION_PENDING", 409)
        new = copy.deepcopy(r)
        verifier = random_id()
        new.data = {
            "state": "AUTHENTICATING",
            "oauth_state": random_id(),
            "verifier": verifier,
            "nonce": random_id(),
            "return_path": return_path,
            "mode": "HOSTED",
        }
        r = await self._save(r, new)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )
        url = (
            self.config.issuer
            + "/oauth2/authorize?"
            + urlencode(
                {
                    "response_type": "code",
                    "client_id": self.config.client_id,
                    "redirect_uri": self.config.callback_uri,
                    "scope": " ".join(self.config.scopes),
                    "state": text(r.data["oauth_state"]),
                    "nonce": text(r.data["nonce"]),
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                }
            )
        )
        return SessionResult({}, status=302, location=url)

    async def _finish(self, r: Record, code: str) -> SessionResult:
        r = await self._intent(r)
        try:
            credentials = await self._protocol().exchange(
                code, text(r.data["verifier"]), text(r.data["nonce"])
            )
            now = self.clock()
            session = Record(
                random_id(),
                "session",
                now,
                now + self.config.absolute_ttl,
                now + self.config.idle_ttl,
                owner=r.owner,
                version=r.version + 1,
            )
            await self._protocol().identity(credentials, session)
            session.data["oidc_nonce"] = r.data["nonce"]
            await self.store.compare_exchange(r.key, r.version, session)
            return SessionResult(self.view(session), cookie=session.key)
        except BaseException:
            # Code send or local commit may have happened: never re-exchange.
            await asyncio.shield(self.store.invalidate(r.key))
            raise

    async def callback(self, key: str | None, query: JsonObject) -> SessionResult:
        r = await self._load(key, "prelogin")
        if not isinstance(query.get("state"), str) or not hmac.compare_digest(
            text(r.data.get("oauth_state")), text(query["state"])
        ):
            raise SessionError("CALLBACK_BINDING_INVALID", 400)
        if set(query) == {"code", "state"}:
            code = text(query["code"])
            r = await self._acquire(r)
            result = await self._finish(r, code)
            result.status, result.location = 302, text(r.data.get("return_path", "/"))
            result.body = {}
            return result
        if set(query) == {"error", "state"}:
            text(query["error"])
            await self.store.invalidate(r.key)
            raise SessionError("AUTHENTICATION_CANCELLED", 401)
        if (
            set(query) == {"kind", "auth_transaction_id", "state"}
            and query["kind"] == "AUTH_CONTINUATION"
        ):
            t = obj(r.data.get("transaction"))
            if query["auth_transaction_id"] != t["transactionId"]:
                raise SessionError("CALLBACK_BINDING_INVALID")
            held = await self._acquire(r)
            try:
                view = await self._protocol().transaction("GET", t)
                self._transaction_view(held, view)
                await self._release(held)
                return SessionResult({}, status=302, location=text(r.data.get("return_path", "/")))
            except SessionError:
                await self.store.invalidate(r.key)
                raise
        raise SessionError("VALIDATION_ERROR")

    def _transaction_view(
        self, r: Record, v: JsonObject, *,
        response_kind: Literal["view", "created", "challenge"] = "view",
    ) -> None:
        required = {"transactionId", "expiresAt", "nextAction"}
        if response_kind == "view":
            required.add("state")
        elif response_kind == "created":
            required.add("controlSecret")
        else:
            required.update({"challengeExpiresAt", "cooldownSeconds"})
        exact(v, required)
        t = obj(r.data["transaction"])
        if uuid_text(v.get("transactionId")) != t["transactionId"]:
            raise SessionError("SESSION_BINDING_INVALID", 401)
        expires = epoch(v.get("expiresAt"))
        if expires <= self.clock():
            raise SessionError("SESSION_INVALIDATED", 401)
        state = (
            "AUTHENTICATING" if response_kind == "created"
            else text(r.data["state"]) if response_kind == "challenge"
            else text(v["state"])
        )
        action = text(v.get("nextAction"))
        pairs = {
            "AUTHENTICATING": "authenticate",
            "AWAITING_PROVIDER": "authorize",
            "MFA_REQUIRED": "mfa",
            "AUTHENTICATED": "complete",
            "COMPLETED": "none",
            "CANCELLED": "none",
            "EXPIRED": "none",
            "REJECTED": "none",
        }
        if pairs.get(state) != action:
            raise SessionError("IAM_RESPONSE_INVALID", 502)
        if state == "MFA_REQUIRED":
            expires = min(expires, self.clock() + 300)
        r.absolute_expires_at = min(r.absolute_expires_at, expires)
        r.idle_expires_at = min(r.idle_expires_at, expires)
        r.data.update(state=state, nextAction=action)
        for k in ("challengeExpiresAt", "cooldownSeconds"):
            r.data.pop(k, None)
            if k in v:
                r.data[k] = v[k]
        self.view(r)

    async def login_action(
        self, key: str | None, action: str, body: JsonObject, origin: str | None, csrf: str | None
    ) -> SessionResult:
        r = await self._load(key, "prelogin")
        self.csrf(r, origin, csrf)
        self._validate_action(action, body)
        r = await self._acquire(r)
        try:
            if action == "start":
                if r.data.get("mode") is not None:
                    raise SessionError("SESSION_ACTION_PENDING", 409)
                verifier = random_id()
                r.data.update(
                    mode="CUSTOM",
                    oauth_state=random_id(),
                    nonce=random_id(),
                    verifier=verifier,
                    return_path="/",
                )
                challenge = (
                    base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
                    .decode()
                    .rstrip("=")
                )
                r = await self._intent(r)
                created = await self._protocol().request(
                    "POST",
                    "/api/v1/auth/transactions",
                    body={
                        "client_id": self.config.client_id,
                        "entryMode": "CUSTOM",
                        "redirect_uri": self.config.callback_uri,
                        "scope": " ".join(self.config.scopes),
                        "state": r.data["oauth_state"],
                        "nonce": r.data["nonce"],
                        "code_challenge": challenge,
                        "code_challenge_method": "S256",
                    },
                )
                r.data["transaction"] = {
                    "transactionId": uuid_text(created.get("transactionId")),
                    "controlSecret": text(created.get("controlSecret")),
                }
                self._transaction_view(r, created, response_kind="created")
            else:
                t = obj(r.data.get("transaction"))
                if action == "magic":
                    identifier = obj(r.data.get("identifier"))
                    if (
                        identifier.get("kind") != "EMAIL"
                        or body["transactionId"] != t["transactionId"]
                        or (body["state"] != r.data["oauth_state"])
                    ):
                        raise SessionError("CALLBACK_BINDING_INVALID")
                    action, body = (
                        "authenticate",
                        {
                            "method": "EMAIL_MAGIC_LINK",
                            "identifier": identifier,
                            "proof": body["proof"],
                        },
                    )
                if action == "complete" and r.data.get("state") != "AUTHENTICATED":
                    raise SessionError("SESSION_ACTION_PENDING", 409)
                if action == "mfa" and r.data.get("state") != "MFA_REQUIRED":
                    raise SessionError("SESSION_ACTION_PENDING", 409)
                if action in {"authenticate", "challenges"}:
                    r.data["identifier"] = body["identifier"]
                r = await self._intent(r)
                suffix = {
                    "authenticate": "/authenticate",
                    "challenges": "/challenges",
                    "authorize": "/authorize",
                    "mfa": "/mfa",
                    "complete": "/complete",
                    "cancel": "/cancel",
                }[action]
                wire = await self._protocol().transaction(
                    "POST", t, suffix, body, text(r.operation)
                )
                if action == "complete":
                    exact(wire, {"kind", "code", "state", "expiresIn"})
                    if (
                        wire["kind"] != "authorization_code"
                        or wire["state"] != r.data["oauth_state"]
                    ):
                        raise SessionError("CALLBACK_BINDING_INVALID")
                    integer(wire["expiresIn"])
                    return await self._finish(r, text(wire["code"]))
                if action == "authorize":
                    exact(wire, {"authorizationUrl", "expiresAt"})
                    url = text(wire.get("authorizationUrl"))
                    if urlsplit(url).scheme != "https" and not (
                        self.config.allow_loopback_http and url.startswith(self.config.issuer + "/")
                    ):
                        raise SessionError("IAM_RESPONSE_INVALID", 502)
                    r.data.update(
                        state="AWAITING_PROVIDER", nextAction="authorize", authorizationUrl=url
                    )
                    r.absolute_expires_at = min(r.absolute_expires_at, epoch(wire.get("expiresAt")))
                else:
                    self._transaction_view(
                        r, wire, response_kind="challenge" if action == "challenges" else "view"
                    )
                if action == "cancel" or r.data.get("state") in {
                    "EXPIRED",
                    "REJECTED",
                    "CANCELLED",
                }:
                    result = SessionResult(self.view(r), clear_cookie=True)
                    await self.store.invalidate(r.key)
                    return result
            r = await self._release(r)
            return SessionResult(self.view(r))
        except SessionError as exc:
            if exc.status < 500 and exc.code not in {
                "AUTH_EXCHANGE_UNCERTAIN",
                "REFRESH_UNCERTAIN",
            }:
                try:
                    await self._release(r)
                except StoreError as store_error:
                    if store_error.outcome not in {"ABSENT", "CONFLICT"}:
                        raise
            else:
                await self.store.invalidate(r.key)
            raise
        except asyncio.CancelledError:
            await asyncio.shield(self.store.invalidate(r.key))
            raise

    def _validate_action(self, action: str, body: JsonObject) -> None:
        if action in {"start", "complete", "cancel"}:
            exact(body, set())
        elif action in {"authenticate", "challenges"}:
            method = text(body.get("method"), 32)
            if method not in {"PASSWORD", "EMAIL_OTP", "SMS_OTP", "EMAIL_MAGIC_LINK"} or (
                action == "challenges" and method == "PASSWORD"
            ):
                raise SessionError("VALIDATION_ERROR")
            required = {"method", "identifier"}
            if action == "authenticate":
                required.add("password" if method == "PASSWORD" else "proof")
                text(
                    body.get("password" if method == "PASSWORD" else "proof"),
                    1024 if method == "PASSWORD" else 128,
                )
            exact(body, required)
            self._identifier(body["identifier"])
        elif action == "authorize":
            exact(body, {"providerId"}, {"registrationGrantToken", "registrationAccessCode"})
            uuid_text(body["providerId"])
            if "registrationGrantToken" in body and "registrationAccessCode" in body:
                raise SessionError("VALIDATION_ERROR")
            for k in body.keys() - {"providerId"}:
                text(body[k], 128 if k == "registrationAccessCode" else 2048)
        elif action == "mfa":
            exact(body, {"method", "code"})
            if text(body["method"], 32) not in {"TOTP", "RECOVERY_CODE"}:
                raise SessionError("VALIDATION_ERROR")
            text(body["code"], 128)
        elif action == "magic":
            exact(body, {"transactionId", "state", "proof"})
            uuid_text(body["transactionId"])
            text(body["state"], 512)
            text(body["proof"], 128)
        else:
            raise SessionError("VALIDATION_ERROR")

    @staticmethod
    def _identifier(value: object) -> None:
        v = obj(value)
        exact(v, {"kind", "value"}, {"region"})
        if text(v["kind"], 32) not in {"EMAIL", "USERNAME", "PHONE"}:
            raise SessionError("VALIDATION_ERROR")
        text(v["value"])
        if v.get("region") is not None:
            text(v["region"], 10)

    async def session(self, key: str | None) -> SessionResult:
        budget = asyncio.timeout(self.config.auth_budget)
        try:
            async with budget:
                return await self._session(key)
        except TimeoutError:
            if not budget.expired():
                raise
            # Only our deadline is mapped. Caller cancellation and unrelated
            # exceptions retain their native semantics; refresh cleanup has run.
            raise SessionError("IAM_UNAVAILABLE", 503) from None

    async def _session(self, key: str | None) -> SessionResult:
        if key is None:
            return await self.bootstrap(None)
        r = await self._load(key)
        if r.kind != "session":
            return SessionResult(self.view(r))
        try:
            expiry = r.data.get("access_expires_at")
            if not isinstance(expiry, (float, int)):
                raise SessionError("SESSION_INVALIDATED", 401)
            if expiry <= self.clock() + self.config.refresh_skew:
                if r.data.get("refresh_token") is None:
                    if expiry <= self.clock():
                        raise SessionError("SESSION_INVALIDATED", 401)
                else:
                    r = await self._refresh(r)
                    expiry = r.data["access_expires_at"]
            if r.operation is not None:
                if r.lease_until <= self.clock() and r.intent:
                    raise SessionError("REFRESH_UNCERTAIN", 401)
                raise SessionError("SESSION_ACTION_PENDING", 409)
            v = await self._protocol().validity(
                text(r.data["access_token"], 65536), obj(r.data["profile"])
            )
            updated = copy.deepcopy(r)
            updated.absolute_expires_at = min(r.absolute_expires_at, epoch(v["expiresAt"]))
            updated.idle_expires_at = min(
                r.absolute_expires_at,
                self.clock() + self.config.idle_ttl,
                epoch(v["idleExpiresAt"]),
            )
            if not isinstance(expiry, (float, int)):
                raise SessionError("SESSION_INVALIDATED", 401)
            updated.data["access_expires_at"] = min(float(expiry), epoch(v["accessExpiresAt"]))
            r = await self._save(r, updated)
            return SessionResult(self.view(r))
        except SessionError as exc:
            if exc.status == 401:
                await self.store.invalidate(r.key)
            raise

    async def require_session(self, key: str | None, permission: str | None = None) -> JsonObject:
        if key is None:
            raise SessionError("SESSION_REQUIRED", 401)
        result = await self.session(key)
        if "profile" not in result.body:
            raise SessionError("SESSION_REQUIRED", 401)
        self.check_permission(result.body, permission)
        return result.body

    @staticmethod
    def check_permission(view: JsonObject, permission: str | None) -> None:
        if permission is not None:
            p = obj(view["permissions"])
            values = p["permissions"]
            if not isinstance(values, list) or ":" not in permission:
                raise SessionError("FORBIDDEN", 403)
            resource, action = permission.split(":", 1)
            if not has_permission(PermissionKey(resource, action), values):
                raise SessionError("FORBIDDEN", 403)

    async def _refresh(self, r: Record) -> Record:
        r = await self._acquire(r)
        r = await self._intent(r)
        token_received = False
        try:
            body = await self._protocol().request(
                "POST",
                "/oauth2/token",
                form={
                    "grant_type": "refresh_token",
                    "refresh_token": text(r.data["refresh_token"], 65536),
                },
                uncertain="REFRESH_UNCERTAIN",
            )
            token_received = True
            credentials = self._protocol().credentials(body, openid=False)
            if body.get("id_token") is not None:
                subject = await self._protocol().verify_id_token(
                    text(body["id_token"], 65536), text(r.data["oidc_nonce"])
                )
                if subject != obj(r.data["profile"])["id"]:
                    raise SessionError("SESSION_BINDING_INVALID", 401)
            new = copy.deepcopy(r)
            new.data.update(credentials.mapping())
            new.operation, new.intent, new.lease_until = None, False, 0
            return await self._save(r, new)
        except SessionError as exc:
            if exc.code == "IAM_UNAVAILABLE" and not token_received:
                await self._release(r)  # Transport proved it did not send.
            else:
                await self.store.invalidate(r.key)
                if token_received and exc.status >= 500:
                    raise SessionError("REFRESH_UNCERTAIN", 401) from None
            raise
        except BaseException:
            await asyncio.shield(self.store.invalidate(r.key))
            raise

    async def logout(self, key: str | None, origin: str | None, csrf: str | None) -> SessionResult:
        r = None if key is None else await self.store.read(key)
        if r is None:
            raise SessionError("SESSION_CSRF_INVALID", 403)
        self.csrf(r, origin, csrf)
        result: JsonObject = {
            "local": "NOT_FOUND",
            "cookie": "CLEARED",
            "remote": "NOT_ATTEMPTED",
            "sso": "NOT_REQUESTED",
        }
        try:
            result["local"] = "INVALIDATED" if await self.store.invalidate(r.key) else "NOT_FOUND"
        except StoreError:
            result["local"] = "UNCONFIRMED"
        if r.kind == "session":
            try:
                expiry = r.data.get("access_expires_at")
                rt = r.data.get("refresh_token")
                if isinstance(expiry, (int, float)) and expiry > self.clock():
                    await self._protocol().request(
                        "POST",
                        "/api/v1/auth/logout",
                        bearer=text(r.data["access_token"], 65536),
                        body={} if rt is None else {"refresh_token": text(rt, 65536)},
                        empty=True,
                    )
                    result["remote"] = "SESSION_REVOKED"
                elif rt is not None:
                    await self._protocol().request(
                        "POST",
                        "/oauth2/revoke",
                        form={"token": text(rt, 65536), "token_type_hint": "refresh_token"},
                        empty=True,
                    )
                    result["remote"] = "REFRESH_FAMILY_REVOKED"
            except SessionError:
                result["remote"] = "UNCONFIRMED"
        failed = result["local"] == "UNCONFIRMED" or result["remote"] == "UNCONFIRMED"
        return SessionResult(result, clear_cookie=True, status=503 if failed else 200)

    async def capabilities(self, policy: bool = False) -> SessionResult:
        suffix = "auth-policy" if policy else "auth-methods"
        wire = await self._protocol().request(
            "GET", "/api/v1/apps/" + quote(self.config.client_id, safe="") + "/" + suffix
        )
        parsed = parse_capabilities(
            "AuthPolicyPublicResponse" if policy else "AuthMethodsPublicResponse", wire
        )
        if not policy and parsed["clientId"] != self.config.client_id:
            raise SessionError("SESSION_BINDING_INVALID", 401)
        return SessionResult(parsed)

    async def registration(
        self,
        key: str | None,
        action: str,
        body: JsonObject,
        origin: str | None,
        csrf: str | None,
        ref: str | None = None,
    ) -> SessionResult:
        r = await self._load(key, "prelogin")
        if action != "get":
            self.csrf(r, origin, csrf)
        if action == "start":
            exact(
                body,
                {"identifier", "password"},
                {
                    "uiLocales",
                    "registrationGrantToken",
                    "registrationAccessCode",
                    "organizationInvitationToken",
                },
            )
            self._identifier(body["identifier"])
            text(body["password"], 128)
            if "registrationGrantToken" in body and "registrationAccessCode" in body:
                raise SessionError("VALIDATION_ERROR")
            for k in body.keys() - {"identifier", "password"}:
                text(body[k], 128 if k == "registrationAccessCode" else 2048)
        elif action == "complete":
            exact(body, {"code"})
            if len(text(body["code"], 6)) != 6:
                raise SessionError("VALIDATION_ERROR")
        else:
            exact(body, set())
            if action not in {"get", "challenges", "cancel"}:
                raise SessionError("VALIDATION_ERROR")
        r = await self._acquire(r)
        try:
            registrations = obj(r.data.get("registrations", {}))
            headers: dict[str, str] = {"Registration-Client": self.config.client_id}
            if action == "start":
                ref = random_id()
                headers["Idempotency-Key"] = text(r.operation)
                wire = await self._protocol().request(
                    "POST",
                    "/api/v1/auth/signup",
                    body={**body, "client_id": self.config.client_id},
                    headers=headers,
                )
            else:
                if ref is None or ref not in registrations:
                    raise SessionError("VALIDATION_ERROR")
                binding = obj(registrations[ref])
                path = "/api/v1/auth/signup/operations/" + quote(
                    text(binding["registrationId"]), safe=""
                )
                if action == "get":
                    headers["Registration-Control"] = text(binding["controlSecret"])
                    wire = await self._protocol().request("GET", path, headers=headers)
                else:
                    wire = await self._protocol().request(
                        "POST",
                        path + "/" + action,
                        body={**body, "controlSecret": binding["controlSecret"]},
                        headers=headers,
                    )
            exact(
                wire,
                {
                    "registrationId",
                    "status",
                    "expiresAt",
                    "nextAction",
                    "controlSecret",
                    "nextChallengeAt",
                },
            )
            uuid_text(wire["registrationId"])
            text(wire["status"])
            text(wire["nextAction"])
            epoch(wire["expiresAt"])
            if wire["nextChallengeAt"] is not None:
                epoch(wire["nextChallengeAt"])
            if action == "start":
                registrations[text(ref)] = {
                    "registrationId": wire["registrationId"],
                    "controlSecret": wire["controlSecret"],
                }
            r.data["registrations"] = registrations
            await self._release(r)
            safe = {k: v for k, v in wire.items() if k != "controlSecret"}
            safe["registrationId"] = ref
            return SessionResult(
                safe,
                status=202
                if wire["status"] == "PENDING_VERIFICATION"
                else 201
                if action == "start"
                else 200,
            )
        except BaseException:
            await asyncio.shield(self.store.invalidate(r.key))
            raise

    async def password_reset(
        self,
        key: str | None,
        complete: bool,
        body: JsonObject,
        origin: str | None,
        csrf: str | None,
    ) -> SessionResult:
        r = await self._load(key, "prelogin")
        self.csrf(r, origin, csrf)
        if complete:
            exact(body, {"token", "newPassword"})
            text(body["token"])
            text(body["newPassword"], 128)
            await self._protocol().request(
                "POST",
                "/api/v1/auth/password/reset",
                body=body,
                headers={"Password-Reset-Client": self.config.client_id},
                empty=True,
            )
        else:
            exact(body, {"email"})
            text(body["email"], 320)
            payload: JsonObject = {**body, "client_id": self.config.client_id}
            if self.config.password_reset_redirect is not None:
                payload["redirect_uri"] = self.config.password_reset_redirect
            await self._protocol().request(
                "POST", "/api/v1/auth/password/forgot", body=payload, empty=True
            )
        return SessionResult({}, status=204)


class SyncServerSession(ServerSession):
    """Explicit sync channel, one persistent instance-owned runner/HTTP pool."""

    def __init__(
        self,
        config: SessionConfig,
        store: SyncSessionStore,
        *,
        sync_http_client_factory: Callable[[], httpx.AsyncClient] | None = None,
        clock: Callable[[], float] = time.time,
    ):
        if not isinstance(store, SyncSessionStore):
            raise IamConfigError("an explicit sync session provider is required")
        super().__init__(config, AsyncFromSyncStore(store), clock=clock)
        self._runtime = SyncRuntime(sync_http_client_factory or httpx.AsyncClient, self._http)

    def _protocol(self) -> SessionProtocol:
        return SessionProtocol(self.config, self._runtime.select_http(self._http), self.clock)

    def run[T](self, coroutine: Coroutine[None, None, T]) -> T:
        return self._runtime.run(coroutine)

    def close(self) -> None:
        if not self._http.is_closed:
            self.run(self._http.aclose())
        self._runtime.close()
