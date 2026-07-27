import json
import os
from pathlib import Path
from typing import cast

import httpx
import pytest

from axis_vertex.permission_manifest import (
    PermissionManifest,
    PermissionManifestClient,
    PermissionManifestClientConfig,
    PermissionManifestDeclaration,
    PermissionManifestError,
    PermissionManifestStartupOptions,
    _parse_retry_after,
    prepare_permission_manifest,
    run_permission_manifest_startup,
)

SHARED_FIXTURE = json.loads(
    (Path(__file__).parents[2] / "docs/fixtures/permission-manifest-vectors.json").read_text()
)


def manifest() -> PermissionManifest:
    return PermissionManifest(
        manifest_id="orders-api",
        revision="git:abc123",
        permissions=(PermissionManifestDeclaration("posts", "read", "Read posts", None),),
    )


def test_matches_backend_frozen_null_vector() -> None:
    prepared = prepare_permission_manifest(manifest(), "validate")
    assert (
        prepared.fingerprint == "bd2036720114f62abecb2850b61c165763a9cf1ee3736eab2bd59b9646aae9b5"
    )


def test_consumes_complete_shared_vector_matrix() -> None:
    fixture = SHARED_FIXTURE
    for vector in fixture["vectors"]:
        declarations = tuple(
            PermissionManifestDeclaration(**item) for item in vector["permissions"]
        )
        prepared = prepare_permission_manifest(
            PermissionManifest("vector", "1", declarations), "validate"
        )
        assert prepared.fingerprint == vector["fingerprint"], vector["name"]
    assert [
        _parse_retry_after(str(value)) for value in fixture["retry"]["validRetryAfterSeconds"]
    ] == [1, 12, 86400]
    assert all(_parse_retry_after(value) is None for value in fixture["retry"]["invalidRetryAfter"])


@pytest.mark.asyncio
async def test_shared_budget_token_redaction_and_required_response_fields() -> None:
    calls = 0
    observations: list[object] = []

    def invalid_token(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            json={
                "access_token": "sensitive-bearer",
                "token_type": "Bearer",
                "expires_in": 60,
                "scope": "wrong",
            },
        )

    config = PermissionManifestClientConfig(
        "https://issuer.test",
        "https://portal.test",
        "id",
        "secret",
        max_retries=2,
        max_retry_delay=0.001,
        observer=observations.append,
    )
    client = PermissionManifestClient(
        config, http_client=httpx.AsyncClient(transport=httpx.MockTransport(invalid_token))
    )
    with pytest.raises(PermissionManifestError) as token_error:
        await client.validate(manifest())
    assert token_error.value.code == "INVALID_TOKEN_RESPONSE"
    assert "sensitive-bearer" not in repr(token_error.value.body)
    assert calls == 1
    assert len(observations) == 1
    assert "sensitive-bearer" not in repr(observations)
    await client.close()


@pytest.mark.asyncio
async def test_malformed_token_json_and_issuer_description_are_redacted() -> None:
    malformed_client = PermissionManifestClient(
        PermissionManifestClientConfig(
            "https://issuer.test", "https://portal.test", "id", "secret", max_retries=0
        ),
        http_client=httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _request: httpx.Response(200, text='{"access_token":"sensitive-bearer"')
            )
        ),
    )
    with pytest.raises(PermissionManifestError) as malformed:
        await malformed_client.validate(manifest())
    assert malformed.value.code == "INVALID_JSON_RESPONSE"
    assert malformed.value.body is None
    assert "sensitive-bearer" not in repr(malformed.value)
    await malformed_client.close()

    protocol_client = PermissionManifestClient(
        PermissionManifestClientConfig(
            "https://issuer.test", "https://portal.test", "id", "secret", max_retries=0
        ),
        http_client=httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _request: httpx.Response(
                    400,
                    json={
                        "error": "invalid_client",
                        "error_description": "secret diagnostic",
                    },
                )
            )
        ),
    )
    with pytest.raises(PermissionManifestError) as protocol:
        await protocol_client.validate(manifest())
    assert protocol.value.code == "invalid_client"
    assert str(protocol.value) == "permission manifest machine token request failed"
    assert "secret diagnostic" not in repr(protocol.value)
    await protocol_client.close()


@pytest.mark.asyncio
async def test_budget_is_shared_across_issuer_and_portal() -> None:
    calls = 0
    manifest_path = ""

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls, manifest_path
        calls += 1
        if calls == 1:
            return httpx.Response(
                503,
                json={
                    "status": 503,
                    "error": "UNAVAILABLE",
                    "message": "down",
                    "timestamp": "2026-07-17T00:00:00Z",
                },
            )
        if request.url.path == "/oauth2/token":
            return httpx.Response(
                200,
                json={
                    "access_token": "safe",
                    "token_type": "Bearer",
                    "expires_in": 60,
                    "scope": "permissions:sync",
                },
            )
        manifest_path = request.url.path
        return httpx.Response(
            503,
            json={
                "status": 503,
                "error": "UNAVAILABLE",
                "message": "down",
                "timestamp": "2026-07-17T00:00:00Z",
            },
        )

    config = PermissionManifestClientConfig(
        "https://issuer.test",
        "https://portal.test",
        "id",
        "secret",
        max_retries=2,
        max_retry_delay=0.001,
    )
    client = PermissionManifestClient(
        config, http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )
    with pytest.raises(PermissionManifestError) as error:
        await client.validate(manifest())
    assert error.value.status_code == 503
    assert manifest_path == "/open/v1/permission-manifests:sync"
    assert calls == 3
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("name", SHARED_FIXTURE["responseReject"])
async def test_rejects_shared_response_vectors(name: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/oauth2/token":
            return httpx.Response(
                200,
                json={
                    "access_token": "safe",
                    "token_type": "Bearer",
                    "expires_in": 60,
                    "scope": "permissions:sync",
                },
            )
        prepared = prepare_permission_manifest(manifest(), "validate")
        result: dict[str, object] = {
            "mode": "validate",
            "manifestId": prepared.manifest_id,
            "revision": prepared.revision,
            "fingerprint": prepared.fingerprint,
            "applied": False,
            "results": [],
            "drift": [],
            "counts": {
                "created": 0,
                "updated": 0,
                "unchanged": 0,
                "resurrected": 0,
                "conflict": 0,
                "drift": 0,
            },
        }
        if name == "missing-required-field":
            return httpx.Response(200, json={})
        if name == "unknown-result-enum":
            result["results"] = [
                {
                    "key": "posts:read",
                    "operation": "UNKNOWN",
                    "reason": "DECLARATION_ACCEPTED",
                }
            ]
        if name == "wrong-counts":
            cast(dict[str, int], result["counts"])["created"] = 1
        if name == "malformed-json":
            return httpx.Response(200, text="{")
        if name == "duplicate-json-member-where-supported":
            return httpx.Response(
                200,
                text=json.dumps(result).replace(
                    '{"mode": "validate"',
                    '{"mode": "validate", "mode": "validate"',
                    1,
                ),
            )
        if name not in {
            "missing-required-field",
            "unknown-result-enum",
            "wrong-counts",
            "malformed-json",
            "duplicate-json-member-where-supported",
        }:
            pytest.fail(f"unknown shared responseReject vector {name}")
        return httpx.Response(200, json=result)

    config = PermissionManifestClientConfig(
        "https://issuer.test", "https://portal.test", "id", "secret"
    )
    client = PermissionManifestClient(
        config,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(PermissionManifestError) as error:
        await client.validate(manifest())
    assert error.value.code in {"INVALID_MANIFEST_RESPONSE", "INVALID_JSON_RESPONSE"}
    await client.close()


@pytest.mark.parametrize("name", SHARED_FIXTURE["localReject"])
def test_dispatches_every_shared_local_reject_vector(name: str) -> None:
    declaration = manifest().permissions[0]
    if name == "duplicate-resource-action-key":
        candidate = PermissionManifest("orders-api", "1", (declaration, declaration))
    elif name == "non-nfc-string":
        candidate = PermissionManifest(
            "orders-api", "1", (PermissionManifestDeclaration("posts", "read", "Cafe\u0301", None),)
        )
    elif name == "malformed-or-wildcard-key":
        candidate = PermissionManifest(
            "orders-api", "1", (PermissionManifestDeclaration("*", "read", "Read", None),)
        )
    elif name == "name-over-128-utf16-units":
        candidate = PermissionManifest(
            "orders-api", "1", (PermissionManifestDeclaration("posts", "read", "x" * 129, None),)
        )
    elif name == "description-over-512-utf16-units":
        candidate = PermissionManifest(
            "orders-api", "1", (PermissionManifestDeclaration("posts", "read", "Read", "x" * 513),)
        )
    else:
        pytest.fail(f"unknown shared localReject vector {name}")
    with pytest.raises(ValueError):
        prepare_permission_manifest(candidate, "validate")


@pytest.mark.asyncio
async def test_malformed_error_and_missing_fields_use_stable_codes() -> None:
    config = PermissionManifestClientConfig(
        "https://issuer.test", "https://portal.test", "id", "secret"
    )
    client = PermissionManifestClient(
        config,
        http_client=httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _request: httpx.Response(400, json={}))
        ),
    )
    with pytest.raises(PermissionManifestError) as error:
        await client.validate(manifest())
    assert error.value.code == "INVALID_ERROR_RESPONSE"
    await client.close()

    calls = 0

    def missing_fields(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if request.url.path == "/oauth2/token":
            return httpx.Response(
                200,
                json={
                    "access_token": "safe",
                    "token_type": "Bearer",
                    "expires_in": 60,
                    "scope": "permissions:sync",
                },
            )
        return httpx.Response(200, json={})

    client = PermissionManifestClient(
        config, http_client=httpx.AsyncClient(transport=httpx.MockTransport(missing_fields))
    )
    with pytest.raises(PermissionManifestError) as result_error:
        await client.validate(manifest())
    assert result_error.value.code == "INVALID_MANIFEST_RESPONSE"
    assert calls == 2
    await client.close()


def test_sorts_structured_declarations_and_rejects_duplicate_and_non_nfc() -> None:
    prepared = prepare_permission_manifest(
        PermissionManifest(
            "orders-api",
            "1",
            (
                PermissionManifestDeclaration("users", "read", "Read users", None),
                PermissionManifestDeclaration("orders", "write", "Café", "café/日"),
            ),
        ),
        "upsert",
    )
    assert [item.key for item in prepared.permissions] == ["orders:write", "users:read"]
    duplicate = PermissionManifest("orders-api", "1", (manifest().permissions[0],) * 2)
    with pytest.raises(ValueError, match="duplicate"):
        prepare_permission_manifest(duplicate, "validate")
    non_nfc = PermissionManifest(
        "orders-api", "1", (PermissionManifestDeclaration("posts", "read", "Cafe\u0301", None),)
    )
    with pytest.raises(ValueError, match="NFC"):
        prepare_permission_manifest(non_nfc, "validate")
    invalids = (
        PermissionManifestDeclaration("*", "read", "Read", None),
        PermissionManifestDeclaration("posts", "read", "x" * 129, None),
        PermissionManifestDeclaration("posts", "read", "Read", "x" * 513),
    )
    for declaration in invalids:
        with pytest.raises(ValueError):
            prepare_permission_manifest(
                PermissionManifest("orders-api", "1", (declaration,)), "validate"
            )


@pytest.mark.asyncio
async def test_disabled_startup_does_zero_work() -> None:
    class NoNetwork:
        async def validate(self, _manifest: PermissionManifest) -> object:
            raise AssertionError("network called")

        async def upsert(self, _manifest: PermissionManifest, _key: str) -> object:
            raise AssertionError("network called")

    result = await run_permission_manifest_startup(
        cast(PermissionManifestClient, NoNetwork()), manifest()
    )
    assert result.network_attempted is False
    assert result.continued is False
    assert result.result is None


@pytest.mark.asyncio
async def test_development_startup_requires_failure_policy() -> None:
    with pytest.raises(ValueError, match="failure_policy"):
        await run_permission_manifest_startup(
            cast(PermissionManifestClient, object()),
            manifest(),
            PermissionManifestStartupOptions(mode="DEVELOPMENT_STARTUP"),
        )


@pytest.mark.asyncio
async def test_development_continue_requires_and_emits_redacted_event() -> None:
    with pytest.raises(ValueError, match="on_continue_error"):
        await run_permission_manifest_startup(
            cast(PermissionManifestClient, object()),
            manifest(),
            PermissionManifestStartupOptions(
                mode="DEVELOPMENT_STARTUP",
                failure_policy="CONTINUE",
                idempotency_key="continue-key",
            ),
        )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/oauth2/token":
            return httpx.Response(
                200,
                json={
                    "access_token": "safe",
                    "token_type": "Bearer",
                    "expires_in": 60,
                    "scope": "permissions:sync",
                },
            )
        return httpx.Response(
            503,
            json={
                "status": 503,
                "error": "UNAVAILABLE",
                "message": "secret detail",
                "timestamp": "2026-07-17T00:00:00Z",
            },
        )

    client = PermissionManifestClient(
        PermissionManifestClientConfig(
            "https://issuer.test", "https://portal.test", "id", "secret", max_retries=0
        ),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    events: list[object] = []
    result = await run_permission_manifest_startup(
        client,
        manifest(),
        PermissionManifestStartupOptions(
            mode="DEVELOPMENT_STARTUP",
            failure_policy="CONTINUE",
            idempotency_key="continue-key",
            on_continue_error=events.append,
        ),
    )
    assert result.network_attempted is True
    assert result.continued is True
    assert result.result is None
    assert len(events) == 1
    assert "UNAVAILABLE" in repr(events)
    assert "secret detail" not in repr(events)
    await client.close()


def test_permission_manifest_uses_backend_utf16_text_limits() -> None:
    with pytest.raises(ValueError, match="name is invalid"):
        prepare_permission_manifest(
            PermissionManifest(
                "orders-api",
                "1",
                (PermissionManifestDeclaration("posts", "read", "😀" * 65, None),),
            ),
            "validate",
        )


@pytest.mark.asyncio
@pytest.mark.skipif(os.getenv("IAM_PERMISSION_MANIFEST_E2E") != "1", reason="live fixture disabled")
async def test_permission_manifest_real_backend_e2e() -> None:
    def config(client_id: str, client_secret: str) -> PermissionManifestClientConfig:
        return PermissionManifestClientConfig(
            issuer_endpoint=_env("IAM_MANIFEST_ISSUER"),
            portal_api_endpoint=_env("IAM_MANIFEST_PORTAL"),
            client_id=client_id,
            client_secret=client_secret,
            max_retries=0,
        )

    live_manifest = PermissionManifest(
        _env("IAM_MANIFEST_ID"),
        "e2e-1",
        (
            PermissionManifestDeclaration("orders", "write", "Café", "café/日"),
            PermissionManifestDeclaration("users", "read", "Read users", None),
        ),
    )
    client = PermissionManifestClient(
        config(_env("IAM_MANIFEST_CLIENT_ID"), _env("IAM_MANIFEST_CLIENT_SECRET"))
    )
    validate = await client.validate(live_manifest)
    first = await client.upsert(live_manifest, "sdk-python-replay-key")
    replay = await client.upsert(live_manifest, "sdk-python-replay-key")
    stored = await client.validate(live_manifest)
    assert validate.fingerprint == first.fingerprint == replay.fingerprint
    assert replay == first
    assert all(item.operation == "UNCHANGED" for item in stored.results)
    changed = PermissionManifest(live_manifest.manifest_id, "e2e-2", live_manifest.permissions)
    with pytest.raises(PermissionManifestError) as mismatch_error:
        await client.upsert(changed, "sdk-python-replay-key")
    assert mismatch_error.value.status_code == 409
    wrong = PermissionManifestClient(
        config(_env("IAM_MANIFEST_WRONG_CLIENT_ID"), _env("IAM_MANIFEST_WRONG_CLIENT_SECRET"))
    )
    with pytest.raises(PermissionManifestError) as wrong_error:
        await wrong.validate(live_manifest)
    assert wrong_error.value.status_code == 401
    cross = PermissionManifestClient(
        config(_env("IAM_MANIFEST_CROSS_CLIENT_ID"), _env("IAM_MANIFEST_CROSS_CLIENT_SECRET"))
    )
    with pytest.raises(PermissionManifestError) as cross_error:
        await cross.validate(live_manifest)
    assert cross_error.value.status_code == 404
    cross_application = PermissionManifestClient(
        config(_env("IAM_MANIFEST_APP_B_CLIENT_ID"), _env("IAM_MANIFEST_APP_B_CLIENT_SECRET"))
    )
    isolated = await cross_application.validate(live_manifest)
    assert all(item.operation == "CREATE" for item in isolated.results)
    await client.close()
    await wrong.close()
    await cross.close()
    await cross_application.close()


@pytest.mark.asyncio
@pytest.mark.skipif(
    not os.getenv("IAM_PERMISSION_MANIFEST_NEGATIVE_E2E"),
    reason="negative live fixture disabled",
)
async def test_permission_manifest_real_backend_negative_retry_policy() -> None:
    mode = _env("IAM_PERMISSION_MANIFEST_NEGATIVE_E2E")
    client_id = _env("IAM_NEG_RATE_CLIENT_ID" if mode == "rate" else "IAM_NEG_CLIENT_ID")
    secret = _env("IAM_NEG_RATE_CLIENT_SECRET" if mode == "rate" else "IAM_NEG_CLIENT_SECRET")
    manifest = PermissionManifest(f"m3-negative-python-{mode}", "1", ())

    def client(portal: str) -> PermissionManifestClient:
        return PermissionManifestClient(
            PermissionManifestClientConfig(
                issuer_endpoint=_env("IAM_NEG_ISSUER"),
                portal_api_endpoint=portal,
                client_id=client_id,
                client_secret=secret,
                max_retries=1 if mode == "rate" else 2,
                max_retry_delay=0.001,
            )
        )

    if mode == "terminal":
        direct = client(_env("IAM_NEG_PORTAL"))
        await direct.upsert(manifest, "sdk-python-terminal-key")
        await direct.close()
        manifest = PermissionManifest(manifest.manifest_id, "2", ())
    proxied = client(_env("IAM_NEG_PROXY"))
    with pytest.raises(PermissionManifestError) as error:
        if mode == "terminal":
            await proxied.upsert(manifest, "sdk-python-terminal-key")
        else:
            await proxied.validate(manifest)
    assert error.value.status_code == (429 if mode == "rate" else 409)
    await proxied.close()


def _env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value
