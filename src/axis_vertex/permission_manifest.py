"""Server-only Permission Manifest synchronization helpers."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal, cast

import httpx

PERMISSIONS_SYNC_SCOPE = "permissions:sync"
PermissionManifestMode = Literal["validate", "upsert"]
PermissionManifestStartupMode = Literal[
    "DISABLED", "CI_VALIDATE", "DEPLOYMENT_UPSERT", "DEVELOPMENT_STARTUP"
]
PermissionManifestFailurePolicy = Literal["FAIL_FAST", "CONTINUE"]

_MANIFEST_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_REVISION = re.compile(r"^[A-Za-z0-9._:@/+~-]{1,128}$")
_SEGMENT = re.compile(r"^[a-z0-9_-]{1,128}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDEMPOTENCY = re.compile(r"^[\x21-\x7e]{8,128}$")
_RETRY_STATUSES = {408, 429, 502, 503, 504}
_OPERATIONS = {"CREATE", "UPDATE", "UNCHANGED", "RESURRECT", "CONFLICT"}
_REASONS = {
    "DECLARATION_ACCEPTED",
    "MANUAL_COLLISION",
    "LEGACY_CODE_UNATTRIBUTED",
    "CODE_OWNER_COLLISION",
}
_DRIFT_KINDS = {
    "MANUAL_COLLISION",
    "LEGACY_CODE_UNATTRIBUTED",
    "CODE_OWNER_COLLISION",
    "ABSENT_DECLARATION",
}


@dataclass(frozen=True, slots=True)
class PermissionManifestDeclaration:
    resource: str
    action: str
    name: str
    description: str | None = None

    @property
    def key(self) -> str:
        return f"{self.resource}:{self.action}"


@dataclass(frozen=True, slots=True)
class PermissionManifest:
    manifest_id: str
    revision: str
    permissions: tuple[PermissionManifestDeclaration, ...]


@dataclass(frozen=True, slots=True)
class PreparedPermissionManifest:
    mode: PermissionManifestMode
    manifest_id: str
    revision: str
    fingerprint: str
    permissions: tuple[PermissionManifestDeclaration, ...]

    def to_json(self) -> dict[str, object]:
        return {
            "mode": self.mode,
            "manifestId": self.manifest_id,
            "revision": self.revision,
            "fingerprint": self.fingerprint,
            "permissions": [
                {
                    "resource": item.resource,
                    "action": item.action,
                    "name": item.name,
                    "description": item.description,
                }
                for item in self.permissions
            ],
        }


@dataclass(frozen=True, slots=True)
class PermissionManifestItem:
    key: str
    operation: str
    reason: str


@dataclass(frozen=True, slots=True)
class PermissionManifestDrift:
    key: str
    kind: str
    source: str


@dataclass(frozen=True, slots=True)
class PermissionManifestCounts:
    created: int
    updated: int
    unchanged: int
    resurrected: int
    conflict: int
    drift: int


@dataclass(frozen=True, slots=True)
class PermissionManifestResult:
    mode: PermissionManifestMode
    manifest_id: str
    revision: str
    fingerprint: str
    applied: bool
    results: tuple[PermissionManifestItem, ...]
    drift: tuple[PermissionManifestDrift, ...]
    counts: PermissionManifestCounts


@dataclass(frozen=True, slots=True)
class PermissionManifestClientConfig:
    issuer_endpoint: str
    portal_api_endpoint: str
    client_id: str
    client_secret: str
    timeout: float = 5.0
    token_skew_seconds: float = 30.0
    max_retries: int = 2
    max_retry_delay: float = 5.0
    observer: Callable[[PermissionManifestObservation], None] | None = None


@dataclass(frozen=True, slots=True)
class PermissionManifestObservation:
    mode: PermissionManifestMode
    outcome: Literal["SUCCESS", "ERROR"]
    status: int
    duration_seconds: float


@dataclass(frozen=True, slots=True)
class PermissionManifestContinueEvent:
    mode: Literal["DEVELOPMENT_STARTUP"]
    outcome: Literal["CONTINUED"]
    status: int
    code: str


@dataclass(frozen=True, slots=True)
class PermissionManifestStartupResult:
    network_attempted: bool
    continued: bool
    result: PermissionManifestResult | None


@dataclass(frozen=True, slots=True)
class PermissionManifestStartupOptions:
    mode: PermissionManifestStartupMode = "DISABLED"
    failure_policy: PermissionManifestFailurePolicy | None = None
    idempotency_key: str | None = None
    on_continue_error: Callable[[PermissionManifestContinueEvent], None] | None = None


class PermissionManifestError(Exception):
    """Typed V2 protocol or transport error."""

    def __init__(
        self,
        message: str,
        status_code: int = 0,
        code: str = "",
        *,
        correlation_id: str | None = None,
        retry_after_seconds: int | None = None,
        body: object = None,
    ) -> None:
        self.status_code = status_code
        self.code = code
        self.correlation_id = correlation_id
        self.retry_after_seconds = retry_after_seconds
        self.body = body
        super().__init__(message)


def prepare_permission_manifest(
    manifest: PermissionManifest, mode: PermissionManifestMode
) -> PreparedPermissionManifest:
    if mode not in ("validate", "upsert"):
        raise ValueError("permission manifest mode must be validate or upsert")
    if not _MANIFEST_ID.fullmatch(manifest.manifest_id):
        raise ValueError("permission manifest manifest_id is invalid")
    if not _REVISION.fullmatch(manifest.revision):
        raise ValueError("permission manifest revision is invalid")
    if len(manifest.permissions) > 1000:
        raise ValueError("permission manifest permissions must contain at most 1000 declarations")
    permissions = tuple(
        sorted(
            (_validate_declaration(item) for item in manifest.permissions),
            key=lambda item: item.key,
        )
    )
    if any(
        left.key == right.key for left, right in zip(permissions, permissions[1:], strict=False)
    ):
        raise ValueError("permission manifest contains a duplicate permission key")
    return PreparedPermissionManifest(
        mode, manifest.manifest_id, manifest.revision, _fingerprint(permissions), permissions
    )


def permission_declaration_revision(declaration: PermissionManifestDeclaration) -> str:
    return hashlib.sha256(_canonical_declaration(_validate_declaration(declaration))).hexdigest()


class PermissionManifestClient:
    """Confidential M2M client for permission manifests."""

    def __init__(
        self,
        config: PermissionManifestClientConfig,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        issuer = _endpoint(config.issuer_endpoint, "issuer_endpoint")
        portal = _endpoint(config.portal_api_endpoint, "portal_api_endpoint")
        if not config.client_id.strip() or not config.client_secret.strip():
            raise ValueError("permission manifest client_id and client_secret are required")
        if (
            config.timeout <= 0
            or config.timeout > 5
            or config.token_skew_seconds < 0
            or config.max_retries < 0
            or config.max_retry_delay <= 0
        ):
            raise ValueError(
                "permission manifest timing configuration is invalid or exceeds five seconds"
            )
        self.config = PermissionManifestClientConfig(
            issuer,
            portal,
            config.client_id.strip(),
            config.client_secret.strip(),
            config.timeout,
            config.token_skew_seconds,
            config.max_retries,
            config.max_retry_delay,
            config.observer,
        )
        self._http = http_client or httpx.AsyncClient(timeout=config.timeout)
        self._owns_http = http_client is None
        self._token: tuple[str, float] | None = None

    async def validate(self, manifest: PermissionManifest) -> PermissionManifestResult:
        return await self._command(
            prepare_permission_manifest(manifest, "validate"), "/open/v1/permission-manifests:sync"
        )

    async def upsert(
        self, manifest: PermissionManifest, idempotency_key: str
    ) -> PermissionManifestResult:
        _require_idempotency_key(idempotency_key)
        return await self._command(
            prepare_permission_manifest(manifest, "upsert"),
            "/open/v1/permission-manifests:sync",
            idempotency_key,
        )

    def clear_token_cache(self) -> None:
        self._token = None

    async def close(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def _command(
        self, prepared: PreparedPermissionManifest, path: str, idempotency_key: str | None = None
    ) -> PermissionManifestResult:
        budget = _CommandBudget()
        started = time.monotonic()
        try:
            async with asyncio.timeout(15):
                result = await self._send(prepared, path, idempotency_key, budget)
            if self.config.observer is not None:
                self.config.observer(
                    PermissionManifestObservation(
                        prepared.mode, "SUCCESS", 200, time.monotonic() - started
                    )
                )
            return result
        except TimeoutError as cause:
            error = PermissionManifestError(
                "permission manifest command budget exhausted", code="COMMAND_TIMEOUT"
            )
            if self.config.observer is not None:
                self.config.observer(
                    PermissionManifestObservation(
                        prepared.mode, "ERROR", 0, time.monotonic() - started
                    )
                )
            raise error from cause
        except Exception as error:
            if self.config.observer is not None:
                status = error.status_code if isinstance(error, PermissionManifestError) else 0
                self.config.observer(
                    PermissionManifestObservation(
                        prepared.mode, "ERROR", status, time.monotonic() - started
                    )
                )
            raise

    async def _send(
        self,
        prepared: PreparedPermissionManifest,
        path: str,
        idempotency_key: str | None,
        budget: _CommandBudget,
    ) -> PermissionManifestResult:
        token = await self._machine_token(budget)
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if idempotency_key is not None:
            headers["Idempotency-Key"] = idempotency_key
        response = await self._request(
            "POST",
            f"{self.config.portal_api_endpoint}{path}",
            headers=headers,
            json=prepared.to_json(),
            budget=budget,
        )
        body = _parse_json(response)
        if response.status_code >= 400:
            raise _protocol_error(response, body)
        return _parse_result(body, prepared)

    async def _machine_token(self, budget: _CommandBudget) -> str:
        if self._token is not None and self._token[1] > time.monotonic():
            return self._token[0]
        response = await self._request(
            "POST",
            f"{self.config.issuer_endpoint}/oauth2/token",
            auth=(self.config.client_id, self.config.client_secret),
            data={"grant_type": "client_credentials", "scope": PERMISSIONS_SYNC_SCOPE},
            budget=budget,
        )
        body = _parse_token_json(response)
        if response.status_code >= 400:
            raise _token_protocol_error(response, body)
        if not isinstance(body, Mapping):
            raise PermissionManifestError(
                "invalid exact-scope machine token response",
                response.status_code,
                "INVALID_TOKEN_RESPONSE",
            )
        payload = body
        token_type = payload.get("token_type")
        expires_in = payload.get("expires_in")
        scope = payload.get("scope")
        if (
            not isinstance(payload.get("access_token"), str)
            or not payload["access_token"]
            or not isinstance(token_type, str)
            or token_type.lower() != "bearer"
            or not isinstance(expires_in, int)
            or isinstance(expires_in, bool)
            or expires_in <= 0
            or scope != PERMISSIONS_SYNC_SCOPE
        ):
            raise PermissionManifestError(
                "invalid exact-scope machine token response",
                response.status_code,
                "INVALID_TOKEN_RESPONSE",
            )
        access_token = cast(str, payload["access_token"])
        self._token = (
            access_token,
            time.monotonic() + max(0.0, expires_in - self.config.token_skew_seconds),
        )
        return self._token[0]

    async def _request(
        self, method: str, url: str, *, budget: _CommandBudget, **kwargs: Any
    ) -> httpx.Response:
        last_error: Exception | None = None
        for attempt in range(self.config.max_retries + 1):
            budget.consume()
            try:
                async with asyncio.timeout(5):
                    response = await self._http.request(method, url, **kwargs)
                if (
                    response.status_code not in _RETRY_STATUSES
                    or attempt == self.config.max_retries
                    or budget.exhausted
                ):
                    return response
                retry_after = _parse_retry_after(response.headers.get("Retry-After"))
                await asyncio.sleep(
                    min(
                        self.config.max_retry_delay,
                        float(retry_after if retry_after is not None else 0.25 * (2**attempt)),
                    )
                )
            except (
                TimeoutError,
                httpx.TimeoutException,
                httpx.NetworkError,
                httpx.RemoteProtocolError,
            ) as error:
                last_error = error
                if attempt == self.config.max_retries or budget.exhausted:
                    break
                await asyncio.sleep(min(self.config.max_retry_delay, 0.25 * (2**attempt)))
        raise PermissionManifestError(
            "permission manifest transport failed", code="TRANSPORT_ERROR", body=last_error
        )


@dataclass(slots=True)
class _CommandBudget:
    attempts: int = 3

    @property
    def exhausted(self) -> bool:
        return self.attempts == 0

    def consume(self) -> None:
        if self.attempts == 0:
            raise PermissionManifestError(
                "permission manifest command budget exhausted", code="COMMAND_TIMEOUT"
            )
        self.attempts -= 1


async def run_permission_manifest_startup(
    client: PermissionManifestClient,
    manifest: PermissionManifest,
    options: PermissionManifestStartupOptions | None = None,
) -> PermissionManifestStartupResult:
    effective = options or PermissionManifestStartupOptions()
    if effective.mode == "DISABLED":
        return PermissionManifestStartupResult(False, False, None)
    if effective.mode == "DEVELOPMENT_STARTUP" and effective.failure_policy not in (
        "FAIL_FAST",
        "CONTINUE",
    ):
        raise ValueError("DEVELOPMENT_STARTUP requires explicit failure_policy")
    if (
        effective.mode == "DEVELOPMENT_STARTUP"
        and effective.failure_policy == "CONTINUE"
        and effective.on_continue_error is None
    ):
        raise ValueError("DEVELOPMENT_STARTUP with CONTINUE requires on_continue_error")
    if effective.mode == "DEPLOYMENT_UPSERT" and effective.idempotency_key is None:
        raise ValueError("DEPLOYMENT_UPSERT requires idempotency_key")
    if effective.mode == "DEVELOPMENT_STARTUP" and effective.idempotency_key is None:
        raise ValueError("DEVELOPMENT_STARTUP requires idempotency_key")
    try:
        if effective.mode == "CI_VALIDATE":
            return PermissionManifestStartupResult(True, False, await client.validate(manifest))
        if effective.mode in ("DEPLOYMENT_UPSERT", "DEVELOPMENT_STARTUP"):
            return PermissionManifestStartupResult(
                True,
                False,
                await client.upsert(manifest, cast(str, effective.idempotency_key)),
            )
        raise ValueError("unknown permission manifest startup mode")
    except Exception as error:
        if effective.mode != "DEVELOPMENT_STARTUP" or effective.failure_policy == "FAIL_FAST":
            raise
        cast(Callable[[PermissionManifestContinueEvent], None], effective.on_continue_error)(
            PermissionManifestContinueEvent(
                "DEVELOPMENT_STARTUP",
                "CONTINUED",
                error.status_code if isinstance(error, PermissionManifestError) else 0,
                error.code if isinstance(error, PermissionManifestError) else "UNEXPECTED_ERROR",
            )
        )
        return PermissionManifestStartupResult(True, True, None)


def _validate_declaration(value: PermissionManifestDeclaration) -> PermissionManifestDeclaration:
    if not _SEGMENT.fullmatch(value.resource) or not _SEGMENT.fullmatch(value.action):
        raise ValueError("permission manifest contains an invalid concrete permission key")
    _validate_text(value.name, 128, "name")
    if value.description is not None:
        _validate_text(value.description, 512, "description")
    for field, text in (
        ("resource", value.resource),
        ("action", value.action),
        ("name", value.name),
        ("description", value.description),
    ):
        if text is not None and (not text.isascii() and unicodedata.normalize("NFC", text) != text):
            raise ValueError(f"permission manifest {field} must already be NFC")
    return value


def _validate_text(value: str, maximum: int, field: str) -> None:
    if (
        not value
        or _utf16_length(value) > maximum
        or value.strip() != value
        or any(_is_iso_control(character) or _is_surrogate(character) for character in value)
    ):
        raise ValueError(f"permission manifest {field} is invalid")


def _utf16_length(value: str) -> int:
    return len(value.encode("utf-16-le", errors="surrogatepass")) // 2


def _is_iso_control(value: str) -> bool:
    codepoint = ord(value)
    return codepoint <= 0x1F or 0x7F <= codepoint <= 0x9F


def _is_surrogate(value: str) -> bool:
    return 0xD800 <= ord(value) <= 0xDFFF


def _canonical_declaration(value: PermissionManifestDeclaration) -> bytes:
    return json.dumps(
        {
            "action": value.action,
            "description": value.description,
            "name": value.name,
            "resource": value.resource,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()


def _fingerprint(permissions: tuple[PermissionManifestDeclaration, ...]) -> str:
    canonical = (
        b'{"permissions":['
        + b",".join(_canonical_declaration(item) for item in permissions)
        + b"]}"
    )
    return hashlib.sha256(canonical).hexdigest()


def _endpoint(value: str, field: str) -> str:
    if not value.strip():
        raise ValueError(f"permission manifest {field} is required")
    return value.strip().rstrip("/")


def _require_idempotency_key(value: str) -> None:
    if not _IDEMPOTENCY.fullmatch(value):
        raise ValueError("Idempotency-Key must be 8-128 visible ASCII characters")


def _parse_json(response: httpx.Response) -> object:
    try:
        return json.loads(response.text, object_pairs_hook=_reject_duplicate_members)
    except (ValueError, TypeError) as error:
        raise PermissionManifestError(
            "IAM returned malformed JSON",
            response.status_code,
            "INVALID_JSON_RESPONSE",
            body=response.text,
        ) from error


def _parse_token_json(response: httpx.Response) -> object:
    try:
        return json.loads(response.text, object_pairs_hook=_reject_duplicate_members)
    except (ValueError, TypeError):
        raise PermissionManifestError(
            "IAM token endpoint returned malformed JSON",
            response.status_code,
            "INVALID_JSON_RESPONSE",
        ) from None


def _reject_duplicate_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member {key}")
        result[key] = value
    return result


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise PermissionManifestError(
            f"{name} must be an object", code="INVALID_MANIFEST_RESPONSE", body=value
        )
    return value


def _protocol_error(response: httpx.Response, body: object) -> PermissionManifestError:
    if not isinstance(body, Mapping):
        return PermissionManifestError(
            "invalid permission manifest error response",
            response.status_code,
            "INVALID_ERROR_RESPONSE",
        )
    payload = body
    if (
        not _exact_keys(
            payload, {"status", "error", "message", "timestamp", "details", "correlationId"}
        )
        or payload.get("status") != response.status_code
        or not all(
            isinstance(payload.get(field), str) and payload[field]
            for field in ("error", "message", "timestamp")
        )
        or (
            payload.get("correlationId") is not None
            and not isinstance(payload.get("correlationId"), str)
        )
    ):
        return PermissionManifestError(
            "invalid permission manifest error response",
            response.status_code,
            "INVALID_ERROR_RESPONSE",
        )
    return PermissionManifestError(
        cast(str, payload["message"]),
        response.status_code,
        cast(str, payload["error"]),
        correlation_id=cast(str, payload["correlationId"])
        if payload.get("correlationId")
        else None,
        retry_after_seconds=_parse_retry_after(response.headers.get("Retry-After")),
        body=body,
    )


def _token_protocol_error(response: httpx.Response, body: object) -> PermissionManifestError:
    if isinstance(body, Mapping) and isinstance(body.get("error"), str) and body["error"]:
        return PermissionManifestError(
            "permission manifest machine token request failed",
            response.status_code,
            cast(str, body["error"]),
        )
    return PermissionManifestError(
        "invalid machine token error response",
        response.status_code,
        "INVALID_ERROR_RESPONSE",
    )


def _parse_result(body: object, request: PreparedPermissionManifest) -> PermissionManifestResult:
    payload = _mapping(body, "permission manifest result")
    if (
        not _exact_keys(
            payload,
            {
                "mode",
                "manifestId",
                "revision",
                "fingerprint",
                "applied",
                "results",
                "drift",
                "counts",
            },
        )
        or payload.get("mode") not in ("validate", "upsert")
        or payload.get("mode") != request.mode
        or payload.get("manifestId") != request.manifest_id
        or payload.get("revision") != request.revision
        or payload.get("fingerprint") != request.fingerprint
        or not _SHA256.fullmatch(cast(str, payload.get("fingerprint", "")))
        or payload.get("applied") != (request.mode == "upsert")
        or not isinstance(payload.get("results"), list)
        or not isinstance(payload.get("drift"), list)
    ):
        raise PermissionManifestError(
            "invalid permission manifest result", code="INVALID_MANIFEST_RESPONSE", body=body
        )
    results = tuple(_parse_item(item) for item in cast(list[object], payload["results"]))
    drift = tuple(_parse_drift(item) for item in cast(list[object], payload["drift"]))
    if [item.key for item in results] != sorted({item.key for item in results}) or [
        item.key for item in drift
    ] != sorted({item.key for item in drift}):
        raise PermissionManifestError(
            "invalid permission manifest result ordering",
            code="INVALID_MANIFEST_RESPONSE",
            body=body,
        )
    counts_payload = _mapping(payload.get("counts"), "permission manifest counts")
    if not _exact_keys(
        counts_payload, {"created", "updated", "unchanged", "resurrected", "conflict", "drift"}
    ):
        raise PermissionManifestError(
            "invalid permission manifest counts", code="INVALID_MANIFEST_RESPONSE"
        )
    counts = PermissionManifestCounts(
        *(
            _count(counts_payload.get(field))
            for field in ("created", "updated", "unchanged", "resurrected", "conflict", "drift")
        )
    )
    expected = (
        sum(item.operation == "CREATE" for item in results),
        sum(item.operation == "UPDATE" for item in results),
        sum(item.operation == "UNCHANGED" for item in results),
        sum(item.operation == "RESURRECT" for item in results),
        sum(item.operation == "CONFLICT" for item in results),
        len(drift),
    )
    if (
        counts.created,
        counts.updated,
        counts.unchanged,
        counts.resurrected,
        counts.conflict,
        counts.drift,
    ) != expected:
        raise PermissionManifestError(
            "permission manifest result counts mismatch",
            code="INVALID_MANIFEST_RESPONSE",
            body=body,
        )
    return PermissionManifestResult(
        cast(PermissionManifestMode, payload["mode"]),
        request.manifest_id,
        request.revision,
        request.fingerprint,
        cast(bool, payload["applied"]),
        results,
        drift,
        counts,
    )


def _parse_item(value: object) -> PermissionManifestItem:
    payload = _mapping(value, "permission manifest item")
    key = payload.get("key")
    if (
        not _exact_keys(payload, {"key", "operation", "reason"})
        or not isinstance(key, str)
        or not _valid_key(key)
        or payload.get("operation") not in _OPERATIONS
        or payload.get("reason") not in _REASONS
    ):
        raise PermissionManifestError(
            "invalid permission manifest item", code="INVALID_MANIFEST_RESPONSE", body=value
        )
    return PermissionManifestItem(
        key, cast(str, payload["operation"]), cast(str, payload["reason"])
    )


def _parse_drift(value: object) -> PermissionManifestDrift:
    payload = _mapping(value, "permission manifest drift")
    key = payload.get("key")
    if (
        not _exact_keys(payload, {"key", "kind", "source"})
        or not isinstance(key, str)
        or not _valid_key(key)
        or payload.get("kind") not in _DRIFT_KINDS
        or payload.get("source") not in {"CODE", "MANUAL"}
    ):
        raise PermissionManifestError(
            "invalid permission manifest drift", code="INVALID_MANIFEST_RESPONSE", body=value
        )
    return PermissionManifestDrift(key, cast(str, payload["kind"]), cast(str, payload["source"]))


def _count(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise PermissionManifestError(
            "invalid permission manifest count", code="INVALID_MANIFEST_RESPONSE", body=value
        )
    return value


def _exact_keys(value: Mapping[str, object], allowed: set[str]) -> bool:
    return set(value).issubset(allowed)


def _valid_key(value: str) -> bool:
    parts = value.split(":")
    return (
        len(parts) == 2
        and bool(_SEGMENT.fullmatch(parts[0]))
        and bool(_SEGMENT.fullmatch(parts[1]))
    )


def _parse_retry_after(value: str | None) -> int | None:
    if value is None or not re.fullmatch(r"[1-9][0-9]{0,4}", value):
        return None
    seconds = int(value)
    return seconds if seconds <= 86400 else None
