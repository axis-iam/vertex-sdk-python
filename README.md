# Axis Vertex Python SDK

Server-side Python SDK for Axis Vertex resource APIs. The package distribution is
`axis-iam-vertex`; the import package is `axis_vertex`.

This SDK verifies Axis Vertex-issued access tokens, resolves `roles -> permissions` at
runtime, exposes request-local user context, and provides FastAPI/Django guards.
It does not implement browser login, Google/GitHub provider UI, OAuth callbacks,
Portal/Admin management APIs, or browser token storage.

## Permission manifest synchronization

Use an explicit structured manifest and separate issuer/Portal endpoints. Startup defaults disabled; CI validate,
deployment upsert, and development with explicit failure policy are opt-in. Commands share three attempts and
fifteen seconds, with five seconds per attempt. `PermissionManifestClientConfig.observer` emits only redacted
mode/outcome/status/duration values; never log secrets, tokens, bodies, revisions, descriptions, or idempotency keys.
Disabled startup returns `PermissionManifestStartupResult(network_attempted=False, ...)`; development `CONTINUE`
requires a redacted event handler and cannot silently swallow failure.

Generate typed constants locally from that same manifest before building the application:

```bash
vertex-codegen generate --manifest iam-permission-manifest.json --output src/generated_permissions.py
```

Generation performs zero network calls and needs no IAM credentials. The generated `PermissionKey` can be passed
directly to FastAPI `require_permission`; remote validate/upsert remains a separate server-only operation.

## Application Client Contract

Create one business Application for your product, then create a `WEB` or `M2M`
confidential ApplicationClient for Python server APIs.

- `client_id` is `ApplicationClient.clientId`.
- `client_secret` is that confidential ApplicationClient secret.
- `resource_audience` is `Application.resourceAudience`, for example `api://socratiq`. Resource servers use it to verify access-token `aud`.
- SPA/NATIVE public clients have no secret and must not be used by this server SDK.
- Browser login and embedded provider selection belong to `sdk-js`.
- If a Python WEB application implements interactive Authorization Code login itself, Axis Vertex requires both confidential client authentication at token exchange and S256 PKCE (`code_challenge_method=S256` plus matching `code_verifier`). Store OAuth `state` and the PKCE verifier server-side; this SDK does not provide a browser login/callback helper.

## Install

```bash
pip install axis-iam-vertex[fastapi]
pip install axis-iam-vertex[django]
```

For local development from this repository:

```bash
python -m pip install -e ".[dev,fastapi,django]"
```

## FastAPI Quickstart

```python
import os

from fastapi import Depends, FastAPI
from axis_vertex import IamClient, IamConfig, IamContext
from axis_vertex.fastapi import get_iam_context, require_permission
from generated_permissions import ORDERS_CREATE

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
async def list_orders(ctx: IamContext = Depends(get_iam_context(iam))) -> dict[str, str]:
    return {"user": ctx.user_id}


@app.post("/orders", dependencies=[Depends(require_permission(iam, ORDERS_CREATE))])
async def create_order() -> dict[str, bool]:
    return {"ok": True}
```

High-risk routes:

```python
from fastapi import Depends
from axis_vertex.fastapi import require_no_impersonation, require_step_up


@app.post(
    "/billing/payouts",
    dependencies=[
        Depends(require_step_up(iam, "urn:iam:acr:mfa")),
        Depends(require_no_impersonation(iam)),
    ],
)
async def approve_payout() -> dict[str, bool]:
    return {"ok": True}
```

## Django Quickstart

```python
# settings.py
import os

IAM_SDK = {
    "ENDPOINT": os.environ["IAM_ENDPOINT"],
    "CLIENT_ID": os.environ["IAM_CLIENT_ID"],
    "CLIENT_SECRET": os.environ["IAM_CLIENT_SECRET"],
    "RESOURCE_AUDIENCE": os.environ["IAM_RESOURCE_AUDIENCE"],
}

MIDDLEWARE = [
    "axis_vertex.django.IamAuthenticationMiddleware",
    # other middleware...
]
```

```python
# views.py
from django.http import JsonResponse
from axis_vertex.django import require_permission


@require_permission("orders", "read")
def list_orders(request):
    ctx = request.iam_context
    return JsonResponse({"user": ctx.user_id})
```

High-risk routes:

```python
from axis_vertex.django import require_no_impersonation, require_step_up


@require_step_up("urn:iam:acr:mfa")
@require_no_impersonation()
def approve_payout(request):
    return JsonResponse({"ok": True})
```

## Core API

```python
claims = await iam.verify_token(access_token)
ctx = await iam.authenticate(access_token)
permissions = await iam.resolve_permissions(["admin"])
profile = await iam.get_me(access_token, bypass_cache=True)
security = await iam.get_account_security_summary(access_token)
organizations = await iam.list_account_organizations(access_token)
switched = await iam.switch_account_organization(access_token, "org_123")
preview = await iam.preview_organization_invitation(invitation_token_from_url)
accepted = await iam.accept_organization_invitation(
    invitation_token_from_url, access_token=access_token
)
listed = await iam.list_permissions()  # strict confidential V2-shaped role snapshot
await iam.close()
```

Django-oriented sync wrappers:

```python
ctx = iam.authenticate_sync(access_token)
profile = iam.get_me_sync(access_token, bypass_cache=True)
```

## Portal Open API M2M Client

Portal `/open/v1/**` management APIs are server-side only. Use
`PortalOpenApiClient` from a backend service, CLI, or background job with an
`M2M` confidential ApplicationClient. Never pass this `client_secret` to
browser, React, SPA, or mobile code.

```python
import os

from axis_vertex import PortalOpenApiClient, PortalOpenApiConfig

portal = PortalOpenApiClient(
    PortalOpenApiConfig(
        issuer=os.environ["IAM_ISSUER"],  # iam-server for /oauth2/token
        portal_endpoint=os.environ["IAM_PORTAL_ENDPOINT"],
        client_id=os.environ["IAM_M2M_CLIENT_ID"],
        client_secret=os.environ["IAM_M2M_CLIENT_SECRET"],
    )
)

stats = await portal.request_json("GET", "/open/v1/stats")
role = await portal.request_json(
    "POST",
    "/open/v1/roles",
    json={"key": "editor", "name": "Editor"},
)
await portal.close()
```

The client requests OAuth2 `client_credentials` tokens from
`{issuer}/oauth2/token` with explicit `portal:openapi:read` for `GET` and
`portal:openapi:write` for `POST`, `PUT`, `PATCH`, and `DELETE`. Read and write
machine tokens are cached separately with `expires_in` minus
`token_skew_seconds`; a read token is never reused for writes. Portal requests
send only `Authorization: Bearer <machine_token>` and never send Basic Auth,
`X-IAM-Client-Id`, `X-Application-Id`, `X-App-Key`, or an internal Application
UUID to Portal endpoints.

Token failures raise `PortalOpenApiTokenError`; Portal endpoint failures raise
`PortalOpenApiError` with `status_code`, `code`, and `body`. Network failures
raise `PortalOpenApiTransportError`. No-scope token helpers are intentionally
not exposed because Axis Vertex rejects no-scope M2M requests with
`invalid_scope`.

### Server Registration Grant Management

Registration Grant helpers are server-only and require explicit `registration_grants:read`, `registration_grants:write`, and `registration_grants:redemptions:read` M2M scopes.

```python
created = await portal.create_registration_grant(CreateRegistrationGrantRequest(type="ACCESS_CODE"))
if created.registration_access_code is None:
    raise RuntimeError("missing one-time proof")
# Consume immediately. Never log, cache, or persist the proof.
```

## Permission Model

Permissions use `resource:action`.

- `orders:read` matches `orders:read`
- `orders:*` matches any action on `orders`
- `*:read` matches `read` on any resource
- `*:*` matches everything
- malformed entries never match
- matching is case-sensitive

Final permissions are not trusted from JWT claims. The SDK verifies JWT identity
and roles with `resource_audience`, then resolves permissions through
`POST /open/v1/permissions:resolve` using the configured `client_id`.

## Current User And Profile

`IamContext` exposes request-local authorization context:

```python
ctx.user_id
ctx.application_id
ctx.roles
ctx.permissions
ctx.has_permission("orders", "read")
ctx.has_mfa()
ctx.is_impersonating()
```

`get_me()` calls `GET /api/v1/auth/me/profile` explicitly and uses a short local cache.
`UserProfile.metadata` is profile metadata for display/profile reads. It is not
App User authorization attributes and must not be used as an authorization
source.

Account-center helpers use the current user's bearer token and do not send the
SDK client secret, Basic auth, or `X-IAM-Client-Id`:

```python
profile = await iam.get_me(access_token)
security = await iam.get_account_security_summary(access_token)
await iam.change_password(access_token, current_password="old", new_password="new")
sessions = await iam.list_account_sessions(access_token)
await iam.revoke_other_account_sessions(access_token)
organizations = await iam.list_account_organizations(access_token)
switched = await iam.switch_account_organization(access_token, "org_123")
summary = await iam.get_account_permission_summary(access_token, organization_id="org_123")
check = await iam.check_account_permission(access_token, "orders:read", organization_id="org_123")
```

Organization switch returns a refresh/reauth continuation. The Python SDK does
not mutate JWT `org_id` claims locally.

Email verification send/verify and password forgot/reset helpers are public
connected-app helpers. They use the configured ApplicationClient `client_id`
and do not send the SDK client secret. Current-user permission summary/check
calls use `/api/v1/auth/me/permissions*`; wildcard behavior is owned by IAM.

Public Organization invitation preview is unauthenticated. Accept can be called
without a bearer token and may return `LOGIN_REQUIRED` /
`LOGIN_OR_REGISTER_THEN_RETRY_ACCEPT`:

```python
preview = await iam.preview_organization_invitation(invitation_token_from_url)
accepted = await iam.accept_organization_invitation(invitation_token_from_url)
```

Do not persist raw invitation tokens in durable state. Keep them URL/request
scoped.

## Testing Helpers

## Server Authorization Management

The async `PortalOpenApiClient` exposes typed Application-scoped Role, Permission, role-permission, and user-role helpers. Keep M2M credentials in environment-backed configuration, use only exact family scopes, and retain quoted ETags:

```python
role = await portal.create_role(CreateRoleRequest("support", "Support"), idempotency_key=request_id)
role = await portal.update_role(
    role.id, UpdateRoleRequest(name="Support agents"), if_match=role.etag
)
```

```python
from axis_vertex.testing import MockIamServer, context

server = MockIamServer().given_role("admin", "orders:*")
iam = server.client()
token = server.issue_token("u1", roles=["admin"])

ctx = context(permissions=frozenset({"orders:read"}))
```

## Development

```bash
python -m ruff format --check .
python -m ruff check .
python -m mypy src tests
python -m pytest
python -m build
```
