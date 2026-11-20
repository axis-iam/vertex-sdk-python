"""Confidential WEB transport. No OAuth token retries and no upstream error bodies."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import quote, urlsplit

import httpx
import jwt

from axis_vertex.current_user import CurrentUser

from .models import (
    JsonObject,
    Record,
    SessionConfig,
    SessionError,
    epoch,
    integer,
    obj,
    parse_view,
    text,
    timestamp,
)


@dataclass(slots=True, repr=False)
class Credentials:
    access_token: str
    refresh_token: str | None
    expires_at: float
    id_token: str | None = field(default=None, repr=False)
    subject: str | None = None

    def mapping(self) -> JsonObject:
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "access_expires_at": self.expires_at,
        }


class SessionProtocol:
    def __init__(
        self, config: SessionConfig, http: httpx.AsyncClient, clock: Callable[[], float] = time.time
    ):
        self.config, self.http, self.clock = config, http, clock

    async def request(
        self,
        method: str,
        path: str,
        *,
        body: JsonObject | None = None,
        bearer: str | None = None,
        headers: dict[str, str] | None = None,
        form: dict[str, str] | None = None,
        uncertain: str | None = None,
        empty: bool = False,
    ) -> JsonObject:
        h = {"Accept": "application/json", **(headers or {})}
        if bearer is not None:
            h["Authorization"] = "Bearer " + bearer
        try:
            async with asyncio.timeout(self.config.upstream_timeout):
                response = await self.http.request(
                    method,
                    self.config.issuer + path,
                    json=body,
                    data=form,
                    headers=h,
                    timeout=self.config.upstream_timeout,
                    auth=httpx.BasicAuth(self.config.client_id, self.config.client_secret)
                    if form is not None
                    else None,
                    follow_redirects=False,
                )
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout):
            # Definitely no request sent by this transport.
            raise SessionError("IAM_UNAVAILABLE", 503) from None
        except (httpx.RequestError, TimeoutError):
            raise SessionError(uncertain or "IAM_UNAVAILABLE", 401 if uncertain else 503) from None
        if response.status_code >= 500:
            raise SessionError(uncertain or "IAM_UNAVAILABLE", 401 if uncertain else 503)
        if response.status_code == 429:
            retry = response.headers.get("Retry-After", "")
            delay = (
                int(retry) if retry.isascii() and retry.isdecimal() and len(retry) <= 5 else None
            )
            if delay is not None and not 0 <= delay <= 86400:
                delay = None
            raise SessionError("RATE_LIMITED", 429, retry_after=delay)
        if response.is_error:
            code = "IAM_REQUEST_REJECTED"
            try:
                wire = obj(response.json())
                candidate = wire.get("error")
                if isinstance(candidate, str) and candidate in {
                    "invalid_grant",
                    "invalid_client",
                    "invalid_request",
                    "VALIDATION_ERROR",
                    "UNAUTHORIZED",
                    "FORBIDDEN",
                    "AUTHENTICATION_FAILED",
                    "RATE_LIMITED",
                }:
                    code = candidate
            except (ValueError, SessionError):
                pass  # Error text/body is intentionally never retained or chained.
            raise SessionError(code, response.status_code)
        if empty:
            return {}
        try:
            return obj(response.json())
        except (ValueError, SessionError):
            raise SessionError(
                uncertain or "IAM_RESPONSE_INVALID", 401 if uncertain else 502
            ) from None

    def credentials(self, value: JsonObject, *, openid: bool) -> Credentials:
        try:
            access = text(value.get("access_token"), 65536)
            if value.get("token_type") != "Bearer":
                raise SessionError("VALIDATION_ERROR")
            ttl = integer(value.get("expires_in"), 1)
            if "scope" in value and not isinstance(value["scope"], str):
                raise SessionError("VALIDATION_ERROR")
            refresh = value.get("refresh_token")
            rt = None if refresh is None else text(refresh, 65536)
            identity = value.get("id_token")
            it = text(identity, 65536) if openid else None
            return Credentials(access, rt, self.clock() + ttl, it)
        except SessionError:
            raise SessionError("TOKEN_RESPONSE_INVALID", 401) from None

    async def exchange(self, code: str, verifier: str, nonce: str) -> Credentials:
        body = await self.request(
            "POST",
            "/oauth2/token",
            form={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.config.callback_uri,
                "code_verifier": verifier,
            },
            uncertain="AUTH_EXCHANGE_UNCERTAIN",
        )
        credentials = self.credentials(body, openid=True)
        credentials.subject = await self.verify_id_token(text(credentials.id_token, 65536), nonce)
        return credentials

    async def verify_id_token(self, token: str, nonce: str) -> str:
        try:
            discovery = await self.request("GET", "/.well-known/openid-configuration")
            if discovery.get("issuer") != self.config.issuer:
                raise ValueError
            jwks_uri = text(discovery.get("jwks_uri"))
            # Discovery does not grant arbitrary network access.
            if urlsplit(jwks_uri).netloc != urlsplit(
                self.config.issuer
            ).netloc or not jwks_uri.startswith(self.config.issuer + "/"):
                raise ValueError
            allowed = discovery.get("id_token_signing_alg_values_supported")
            header = jwt.get_unverified_header(token)
            alg = header.get("alg")
            if alg not in {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256"} or (
                not isinstance(allowed, list) or alg not in allowed
            ):
                raise ValueError
            jwks = await self.request("GET", jwks_uri[len(self.config.issuer) :])
            keys = jwks.get("keys")
            if not isinstance(keys, list):
                raise ValueError
            matches = [
                obj(k)
                for k in keys
                if obj(k).get("kid") == header.get("kid")
                and obj(k).get("use", "sig") == "sig"
                and obj(k).get("alg", alg) == alg
            ]
            if len(matches) != 1:
                raise ValueError
            key = jwt.PyJWK.from_dict(matches[0], algorithm=alg)
            claims = jwt.decode(
                token,
                key.key,
                algorithms=[alg],
                issuer=self.config.issuer,
                audience=self.config.client_id,
                options={"require": ["iss", "aud", "sub", "exp", "iat", "nonce"]},
            )
            if claims.get("nonce") != nonce or not isinstance(claims.get("sub"), str):
                raise ValueError
            aud = claims.get("aud")
            if (
                isinstance(aud, list)
                and len(aud) > 1
                and claims.get("azp") != self.config.client_id
            ) or ("azp" in claims and claims["azp"] != self.config.client_id):
                raise ValueError
            return str(claims["sub"])
        except (jwt.PyJWTError, ValueError, KeyError, TypeError):
            raise SessionError("ID_TOKEN_INVALID", 401) from None

    async def identity(self, credentials: Credentials, record: Record) -> JsonObject:
        profile = await self.request("GET", "/api/v1/auth/me", bearer=credentials.access_token)
        try:
            user = CurrentUser.from_mapping(profile)
        except ValueError:
            raise SessionError("IAM_RESPONSE_INVALID", 502) from None
        if user.authentication_context.client_id != self.config.client_id or (
            credentials.subject is not None and user.id != credentials.subject
        ):
            raise SessionError("SESSION_BINDING_INVALID", 401)
        permissions = await self.request(
            "GET", "/api/v1/auth/me/permissions", bearer=credentials.access_token
        )
        c = user.authentication_context
        if (
            permissions.get("applicationId") != c.application_id
            or permissions.get("organizationId") != c.organization_id
        ):
            raise SessionError("SESSION_BINDING_INVALID", 401)
        view: JsonObject = {
            "state": "AUTHENTICATED",
            "expiresAt": timestamp(record.absolute_expires_at),
            "csrfToken": record.csrf,
            "owner": record.owner,
            "version": record.version,
            "profile": profile,
            "permissions": permissions,
        }
        parse_view(view)
        validity = await self.validity(credentials.access_token, profile)
        record.absolute_expires_at = min(record.absolute_expires_at, epoch(validity["expiresAt"]))
        record.idle_expires_at = min(record.idle_expires_at, epoch(validity["idleExpiresAt"]))
        credentials.expires_at = min(credentials.expires_at, epoch(validity["accessExpiresAt"]))
        record.data = {**credentials.mapping(), "profile": profile, "permissions": permissions}
        return view

    async def validity(self, access: str, profile: JsonObject) -> JsonObject:
        v = await self.request("GET", "/api/v1/auth/session/validity", bearer=access)
        c = obj(profile["authenticationContext"])
        for key in ("sessionId", "clientId", "applicationId"):
            if not isinstance(v.get(key), str) or v[key] != c[key]:
                raise SessionError("SESSION_BINDING_INVALID", 401)
        for key in ("expiresAt", "idleExpiresAt", "accessExpiresAt"):
            if epoch(v.get(key)) <= self.clock():
                raise SessionError("SESSION_INVALIDATED", 401)
        return v

    async def transaction(
        self,
        method: str,
        transaction: JsonObject,
        suffix: str = "",
        body: JsonObject | None = None,
        action_id: str | None = None,
    ) -> JsonObject:
        headers = {"Authentication-Transaction": text(transaction["controlSecret"])}
        if action_id is not None:
            headers["Idempotency-Key"] = action_id
        return await self.request(
            method,
            "/api/v1/auth/transactions/"
            + quote(text(transaction["transactionId"]), safe="")
            + suffix,
            body=body,
            headers=headers,
        )
