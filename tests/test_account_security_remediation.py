"""F-002/F-003: real HTTP/1.1 keep-alive, bounded protocol fixture, not Backend E2E."""

from __future__ import annotations

import asyncio
import json
import socket
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import fields
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import cast

import httpx
import pytest

from axis_vertex import (
    AccountSecurityError,
    AccountSecurityProtocolError,
    AccountSecurityTransportError,
    IamClient,
    IamConfig,
    MfaOperationCreate,
    MfaOperationType,
)

ID = "00000000-0000-0000-0000-000000000001"
RECOVERY_ID = "00000000-0000-0000-0000-000000000002"
ROOT = "/api/v1/auth/mfa"
ACTION: dict[str, object] = {
    "allowed": True,
    "reasonCode": None,
    "proofRequirement": "SESSION",
    "proofOptions": [],
}
CAPABILITIES = {
    "loginMethodVersion": 4,
    "totpEnroll": ACTION,
    "totpDisable": ACTION,
    "recoveryCodesGenerate": ACTION,
}


def operation(operation_id: str, kind: str, state: str = "READY") -> dict[str, object]:
    result: dict[str, object] | None = None
    if state == "COMMITTED":
        result = {
            "completedAt": "2026-10-31T00:00:00Z",
            "finalLoginMethodVersion": 5,
            "sessionImpact": "CURRENT_SESSION_RETAINED",
            "recoveryBatchId": RECOVERY_ID,
            "recoveryCount": 5,
        }
    return {
        "id": operation_id,
        "type": kind,
        "state": state,
        "createdAt": "2026-10-31T00:00:00Z",
        "expiresAt": "2026-10-31T00:10:00Z",
        "expectedLoginMethodVersion": 4,
        "proofRequirement": "SESSION",
        "proofOptions": [],
        "proofSatisfied": True,
        "nextChallengeAt": None,
        "reasonCode": None,
        "result": result,
    }


class ProtocolState:
    def __init__(self) -> None:
        self.counts = {"owner-a": 0, "owner-b": 2}
        self.requests: list[tuple[str, str, str, int]] = []
        self.mutations: list[str] = []
        self.operations: dict[str, dict[str, object]] = {}
        self.drop_create = False


@contextmanager
def protocol_server() -> Iterator[tuple[str, ProtocolState]]:
    state = ProtocolState()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def respond(self, status: int, body: object) -> None:
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            if status == 429:
                self.send_header("Retry-After", "2")
            self.end_headers()
            self.wfile.write(raw)
            self.wfile.flush()

        def handle_request(self) -> None:
            token = self.headers.get("Authorization", "").removeprefix("Bearer ")
            state.requests.append((self.command, self.path, token, self.client_address[1]))
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            body = cast(dict[str, object], json.loads(raw) if raw else {})
            if token not in state.counts:
                status = 429 if token == "rate" else 403 if token == "machine" else 401
                self.respond(
                    status,
                    {
                        "status": status,
                        "error": "OPERATION_PROOF_RATE_LIMITED"
                        if status == 429
                        else "UNAUTHORIZED",
                        "message": "fixture-private-diagnostic",
                    },
                )
                return
            if self.command == "GET" and self.path == ROOT + "/capabilities":
                self.respond(200, CAPABILITIES)
            elif self.command == "GET" and self.path == ROOT + "/recovery-codes/remaining":
                assert not raw
                self.respond(200, {"remaining": state.counts[token], "future": True})
            elif self.command == "POST" and self.path == ROOT + "/operations":
                assert self.headers.get("Idempotency-Key") in ("enroll-key", "recovery-key")
                assert body["expectedLoginMethodVersion"] == 4
                state.mutations.append("create")
                kind = str(body["type"])
                operation_id = RECOVERY_ID if kind == "RECOVERY_CODES_GENERATE" else ID
                state.operations[operation_id] = operation(operation_id, kind)
                if state.drop_create:
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.close_connection = True
                    return
                self.respond(201, state.operations[operation_id])
            elif self.path == ROOT + "/recovery-codes/verify" and self.command == "POST":
                state.mutations.append("verify")
                assert body == {"code": "fixture-code-0"}
                state.counts[token] -= 1
                self.respond(200, {"verified": True})
            else:
                operation_id = self.path.split("/operations/")[-1].split("/")[0]
                current = state.operations[operation_id]
                if self.command == "POST" and self.path.endswith("/cancel"):
                    state.mutations.append("cancel")
                    current["state"] = "CANCELLED"
                    self.respond(200, current)
                elif self.command == "POST" and self.path.endswith("/complete"):
                    state.mutations.append("complete")
                    assert body == {}
                    state.counts[token] = 5
                    current = operation(operation_id, "RECOVERY_CODES_GENERATE", "COMMITTED")
                    state.operations[operation_id] = current
                    self.respond(
                        200,
                        {
                            "operation": current,
                            "delivery": "AVAILABLE",
                            "recoveryCodes": {
                                "codes": [f"fixture-code-{i}" for i in range(5)],
                                "count": 5,
                            },
                        },
                    )
                else:
                    assert self.command == "GET"
                    self.respond(200, current)

        def do_GET(self) -> None:
            self.handle_request()

        def do_POST(self) -> None:
            self.handle_request()

        def log_message(self, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def configured(endpoint: str) -> IamClient:
    return IamClient(
        IamConfig(endpoint, "client", "fixture-secret", resource_audience="api://fixture")
    )


def test_real_keepalive_sync_lifecycle_and_live_remaining() -> None:
    with protocol_server() as (endpoint, state):
        client = configured(endpoint)
        try:
            assert client.get_mfa_capabilities_sync("owner-a").login_method_version == 4
            assert client.get_mfa_capabilities_sync("owner-a").login_method_version == 4
            assert client.get_recovery_codes_remaining_sync("owner-a").remaining == 0
            created = client.create_mfa_operation_sync(
                "owner-a", MfaOperationCreate(MfaOperationType.TOTP_ENROLL, 4), "enroll-key"
            )
            assert client.get_mfa_operation_sync("owner-a", created.id).id == created.id
            assert (
                client.cancel_mfa_operation_sync("owner-a", created.id).state.value == "CANCELLED"
            )
            generated = client.create_mfa_operation_sync(
                "owner-a",
                MfaOperationCreate(MfaOperationType.RECOVERY_CODES_GENERATE, 4),
                "recovery-key",
            )
            completed = client.complete_mfa_operation_sync("owner-a", generated.id)
            assert completed.operation.result is not None
            assert completed.operation.result.recovery_count == 5
            assert client.get_recovery_codes_remaining_sync("owner-a").remaining == 5
            with httpx.Client() as verifier:
                response = verifier.post(
                    endpoint + ROOT + "/recovery-codes/verify",
                    headers={"Authorization": "Bearer owner-a"},
                    json={"code": "fixture-code-0"},
                )
                assert response.json() == {"verified": True}
            remaining = client.get_recovery_codes_remaining_sync("owner-a")
            assert remaining.remaining == 4 != completed.operation.result.recovery_count
            assert [field.name for field in fields(remaining)] == ["remaining"]
            assert client.get_recovery_codes_remaining_sync("owner-b").remaining == 2
            sync_ports = {
                port
                for _method, path, _owner, port in state.requests
                if not path.endswith("/verify")
            }
            assert len(sync_ports) == 1  # real pooled connection is reused, not disabled/reset
            assert state.mutations == ["create", "cancel", "create", "complete", "verify"]
        finally:
            client.close_sync()
            asyncio.run(client.close())
        requests = len(state.requests)
        with pytest.raises(RuntimeError, match="closed"):
            client.get_mfa_capabilities_sync("owner-a")
        assert len(state.requests) == requests


def test_sync_and_async_channels_are_separate_and_async_does_not_block() -> None:
    with protocol_server() as (endpoint, state):
        client = configured(endpoint)
        client.get_mfa_capabilities_sync("owner-a")
        sync_port = state.requests[-1][3]

        async def use_async() -> None:
            try:
                for call in (
                    lambda: client.get_mfa_capabilities_sync("owner-a"),
                    lambda: client.get_recovery_codes_remaining_sync("owner-a"),
                    client.close_sync,
                ):
                    before = len(state.requests)
                    with pytest.raises(RuntimeError, match="active event loop"):
                        call()
                    assert len(state.requests) == before
                assert (await client.get_mfa_capabilities("owner-a")).login_method_version == 4
                assert (await client.get_recovery_codes_remaining("owner-a")).remaining == 0
                assert state.requests[-1][3] == state.requests[-2][3] != sync_port
            finally:
                await client.close()

        asyncio.run(use_async())


def test_sync_lost_mutation_is_not_replayed_and_status_is_recoverable() -> None:
    with protocol_server() as (endpoint, state):
        state.drop_create = True
        client = configured(endpoint)
        try:
            with pytest.raises(AccountSecurityTransportError) as error:
                client.create_mfa_operation_sync(
                    "owner-a", MfaOperationCreate(MfaOperationType.TOTP_ENROLL, 4), "enroll-key"
                )
            assert error.value.outcome_unknown
            assert state.mutations == ["create"]
            assert client.get_mfa_operation_sync("owner-a", ID).id == ID
            assert state.mutations == ["create"]
        finally:
            client.close_sync()
            asyncio.run(client.close())


def test_current_owner_and_typed_errors_do_not_fall_back_to_client_secret() -> None:
    with protocol_server() as (endpoint, state):
        client = configured(endpoint)
        try:
            for token, status in (("bad-user", 401), ("machine", 403), ("rate", 429)):
                before = len(state.requests)
                with pytest.raises(AccountSecurityError) as rejected:
                    client.get_recovery_codes_remaining_sync(token)
                assert rejected.value.status_code == status
                assert "fixture-private-diagnostic" not in str(rejected.value)
                assert rejected.value.retry_after_seconds == (2 if status == 429 else None)
                assert len(state.requests) == before + 1
                assert state.requests[-1][2] == token
            assert not state.mutations
        finally:
            client.close_sync()
            asyncio.run(client.close())


@pytest.mark.parametrize(
    "wire",
    [
        {},
        {"remaining": None},
        {"remaining": True},
        {"remaining": -1},
        {"remaining": 1.5},
        {"remaining": 2**63},
        {"remaining": 2, "codes": ["not-a-live-code"]},
    ],
)
def test_remaining_known_fields_fail_closed(wire: dict[str, object]) -> None:
    client = IamClient(
        IamConfig(
            "https://fixture.example.test",
            "client",
            "fixture-secret",
            resource_audience="api://fixture",
        ),
        sync_http_client_factory=lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json=wire))
        ),
    )
    try:
        with pytest.raises(AccountSecurityProtocolError):
            client.get_recovery_codes_remaining_sync("owner-a")
    finally:
        client.close_sync()
        asyncio.run(client.close())


def test_custom_async_transport_requires_explicit_distinct_sync_factory() -> None:
    calls: list[str] = []

    def respond(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(200, json={"remaining": 0})

    async_http = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    client = IamClient(
        IamConfig(
            "https://fixture.example.test",
            "client",
            "fixture-secret",
            resource_audience="api://fixture",
        ),
        http_client=async_http,
    )
    with pytest.raises(ValueError, match="sync_http_client_factory"):
        client.get_recovery_codes_remaining_sync("owner-a")
    assert calls == []
    asyncio.run(async_http.aclose())
    asyncio.run(client.close())
