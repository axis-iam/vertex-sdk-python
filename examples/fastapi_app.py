from __future__ import annotations

import os

from fastapi import Depends, FastAPI
from generated_permissions import ORDERS_CREATE

from axis_vertex import IamClient, IamConfig, IamContext
from axis_vertex.fastapi import (
    get_iam_context,
    require_no_impersonation,
    require_permission,
    require_step_up,
)

iam = IamClient(
    IamConfig(
        endpoint=os.environ["IAM_ENDPOINT"],
        client_id=os.environ["IAM_CLIENT_ID"],
        client_secret=os.environ["IAM_CLIENT_SECRET"],
        resource_audience=os.environ["IAM_RESOURCE_AUDIENCE"],
    )
)

app = FastAPI()


@app.get("/orders")
async def list_orders(
    ctx: IamContext = Depends(get_iam_context(iam)),  # noqa: B008
) -> dict[str, str]:
    return {"user": ctx.user_id}


@app.post("/orders", dependencies=[Depends(require_permission(iam, ORDERS_CREATE))])
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
