from __future__ import annotations

import json
from pathlib import Path

import pytest

from axis_vertex.permissions import (
    PermissionKey,
    has_all_permissions,
    has_any_permission,
    match_permission,
    parse_permission,
)


@pytest.mark.parametrize(
    ("permissions", "resource", "action", "expected"),
    [
        (["orders:read"], "orders", "read", True),
        (["orders:*"], "orders", "read", True),
        (["orders:*"], "orders", "write", True),
        (["*:read"], "orders", "read", False),
        (["*:*"], "anything", "any", True),
        (["orders:read"], "orders", "write", False),
        (["orders:read"], "ORDERS", "read", False),
        ([], "orders", "read", False),
        (["orders"], "orders", "read", False),
        ([":read"], "orders", "read", False),
        (["orders:"], "orders", "read", False),
        (["orders:read:extra"], "orders", "read", False),
        (["*:read"], "orders", "write", False),
    ],
)
def test_match_permission(
    permissions: list[str],
    resource: str,
    action: str,
    expected: bool,
) -> None:
    assert match_permission(permissions, resource, action) is expected


def test_parse_permission_rejects_malformed_values() -> None:
    assert parse_permission("orders:read") == PermissionKey("orders", "read")
    assert parse_permission("orders") is None
    assert parse_permission("orders:read:extra") is None
    assert parse_permission(":read") is None


def test_consumes_shared_wildcard_vectors() -> None:
    fixture = json.loads(
        (Path(__file__).parents[2] / "docs/fixtures/permission-manifest-vectors.json").read_text()
    )
    for vector in fixture["codeGeneration"]["wildcardMatch"]:
        target = parse_permission(vector["target"])
        assert target is not None
        assert (
            match_permission([vector["granted"]], target.resource, target.action)
            is vector["matches"]
        )


def test_any_and_all_helpers_fail_safe_on_empty_targets() -> None:
    permissions = ["orders:read", "orders:write"]

    assert has_any_permission([PermissionKey("orders", "read")], permissions)
    assert has_all_permissions(
        [PermissionKey("orders", "read"), PermissionKey("orders", "write")],
        permissions,
    )
    assert not has_any_permission([], permissions)
    assert not has_all_permissions([], permissions)
