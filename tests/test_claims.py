from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from axis_vertex.claims import IamClaims
from axis_vertex.context import IamContext, IamUser


def test_claims_parse_java_iam_shape() -> None:
    claims = IamClaims.from_mapping(
        {
            "sub": "user-1",
            "app_id": "app-1",
            "email": "user@example.com",
            "email_verified": True,
            "username": "alice",
            "org_id": "org-1",
            "org_slug": "acme",
            "org_role": "ADMIN",
            "workspace_id": "workspace-1",
            "sid": "session-1",
            "roles": ["admin"],
            "amr": ["pwd", "mfa"],
            "acr": "urn:iam:acr:mfa",
            "act": {"sub": "admin-1"},
        }
    )

    assert claims.subject == "user-1"
    assert claims.application_id == "app-1"
    assert claims.roles == frozenset({"admin"})
    assert claims.authentication_methods == ("pwd", "mfa")
    assert claims.actor is not None
    assert claims.actor.subject == "admin-1"


def test_context_delegates_fields_and_authorization_helpers() -> None:
    claims = IamClaims.from_mapping(
        {
            "sub": "user-1",
            "app_id": "app-1",
            "aud": "api://socratiq",
            "roles": "admin",
            "amr": ["mfa"],
            "acr": "urn:iam:acr:mfa",
        }
    )
    context = IamContext(
        user=IamUser.from_claims(claims, frozenset({"orders:*"})),
        access_token="token",
    )

    assert context.user_id == "user-1"
    assert context.application_id == "app-1"
    assert context.has_permission("orders", "read")
    assert context.has_mfa()
    assert not context.is_impersonating()
    with pytest.raises(FrozenInstanceError):
        context.user.user_id = "changed"  # type: ignore[misc]


def test_application_id_does_not_fallback_to_audience() -> None:
    claims = IamClaims.from_mapping(
        {
            "sub": "user-1",
            "aud": "api://socratiq",
        }
    )

    assert claims.application_id is None
