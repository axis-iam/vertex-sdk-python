from __future__ import annotations

from axis_vertex.claims import Actor
from axis_vertex.testing import MockIamServer, context


def test_context_factory_for_unit_tests() -> None:
    ctx = context(
        permissions=frozenset({"posts:*"}),
        acr="urn:iam:acr:mfa",
        actor=Actor("admin-1"),
    )

    assert ctx.has_permission("posts", "read")
    assert ctx.has_mfa()
    assert ctx.is_impersonating()


def test_mock_server_tracks_role_and_permission_state() -> None:
    server = MockIamServer().given_role("reader", "posts:read")
    token = server.issue_token("u1", roles=["reader"])

    assert isinstance(token, str)
    assert server.permissions_by_role["reader"] == {"posts:read"}
