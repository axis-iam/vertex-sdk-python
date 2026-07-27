"""Testing helpers for the IAM SDK."""

from __future__ import annotations

from axis_vertex.claims import Actor
from axis_vertex.context import IamContext, IamUser
from axis_vertex.testing.server import MockIamServer
from axis_vertex.testing.tokens import TokenFactory

__all__ = [
    "MockIamServer",
    "TokenFactory",
    "context",
]


def context(
    *,
    user_id: str = "user-1",
    permissions: frozenset[str] | None = None,
    roles: frozenset[str] | None = None,
    acr: str | None = None,
    actor: Actor | None = None,
) -> IamContext:
    """Create an ``IamContext`` for business-logic unit tests."""

    user = IamUser(
        user_id=user_id,
        application_id="test-app",
        email=None,
        email_verified=False,
        username=None,
        organization_id=None,
        organization_slug=None,
        organization_role=None,
        workspace_id=None,
        session_id=None,
        roles=roles or frozenset(),
        permissions=permissions or frozenset(),
        authentication_methods=("mfa",) if acr else (),
        authentication_context_class=acr,
        actor=actor,
        claims={},
    )
    return IamContext(user=user, access_token=None)
