from __future__ import annotations

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from axis_vertex import IamContext
from axis_vertex.fastapi import (
    IamAuthenticationMiddleware,
    get_iam_context,
    require_no_impersonation,
    require_permission,
    require_step_up,
)
from axis_vertex.testing import MockIamServer


def test_fastapi_dependencies_and_guards() -> None:
    server = MockIamServer().given_role("admin", "orders:read", "orders:create")
    iam = server.client()
    app = FastAPI()
    app.add_middleware(IamAuthenticationMiddleware, iam=iam)

    @app.get("/orders")
    async def list_orders(
        ctx: IamContext = Depends(get_iam_context(iam)),  # noqa: B008
    ) -> dict[str, str]:
        return {"user": ctx.user_id}

    @app.post("/orders", dependencies=[Depends(require_permission(iam, "orders", "create"))])
    async def create_order() -> dict[str, bool]:
        return {"ok": True}

    @app.post(
        "/transfer",
        dependencies=[
            Depends(require_step_up(iam, "urn:iam:acr:mfa")),
            Depends(require_no_impersonation(iam)),
        ],
    )
    async def transfer() -> dict[str, bool]:
        return {"ok": True}

    token = server.issue_token(
        "u1",
        roles=["admin"],
        extra_claims={"acr": "urn:iam:acr:mfa", "amr": ["pwd", "mfa"]},
    )
    client = TestClient(app)

    assert client.get("/orders").status_code == 401
    response = client.get("/orders", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"user": "u1"}
    assert client.post("/orders", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    assert client.post("/transfer", headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_fastapi_permission_and_step_up_failures() -> None:
    server = MockIamServer().given_role("viewer", "orders:read")
    iam = server.client()
    app = FastAPI()

    @app.post("/orders", dependencies=[Depends(require_permission(iam, "orders", "create"))])
    async def create_order() -> dict[str, bool]:
        return {"ok": True}

    @app.post("/transfer", dependencies=[Depends(require_step_up(iam, "urn:iam:acr:mfa"))])
    async def transfer() -> dict[str, bool]:
        return {"ok": True}

    token = server.issue_token("u1", roles=["viewer"])
    client = TestClient(app)

    permission_response = client.post("/orders", headers={"Authorization": f"Bearer {token}"})
    step_up_response = client.post("/transfer", headers={"Authorization": f"Bearer {token}"})

    assert permission_response.status_code == 403
    assert permission_response.json()["detail"]["code"] == "FORBIDDEN"
    assert step_up_response.status_code == 403
    assert step_up_response.json()["detail"]["code"] == "STEP_UP_REQUIRED"
