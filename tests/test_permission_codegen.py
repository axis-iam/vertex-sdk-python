from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from axis_vertex.permission_codegen import (
    generate_permission_constants,
    load_permission_manifest,
    main,
    permission_constant_name,
)
from axis_vertex.permission_manifest import PermissionManifest, PermissionManifestDeclaration

SHARED_FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures/permission-manifest-vectors.json").read_text()
)


def test_generates_shared_vectors_deterministically_and_compiles() -> None:
    declarations = tuple(
        PermissionManifestDeclaration(**item)
        for item in SHARED_FIXTURE["codeGeneration"]["permissions"]
    )
    forward = generate_permission_constants(PermissionManifest("codegen", "1", declarations))
    reverse = generate_permission_constants(
        PermissionManifest("codegen", "1", tuple(reversed(declarations)))
    )
    assert forward == reverse
    assert [
        line.split(" =", 1)[0] for line in forward.splitlines() if " = PermissionKey" in line
    ] == SHARED_FIXTURE["codeGeneration"]["expectedNames"]["python"]
    compile(forward, "permissions.gen.py", "exec")


@pytest.mark.parametrize(
    "vector", SHARED_FIXTURE["codeGeneration"]["reject"], ids=lambda v: v["name"]
)
def test_executes_every_shared_rejection_vector(vector: dict[str, object]) -> None:
    raw_permissions = cast(list[dict[str, object]], vector["permissions"])
    permissions = tuple(
        PermissionManifestDeclaration(
            cast(str, item["resource"]),
            cast(str, item["action"]),
            cast(str, item["name"]),
            cast(str | None, item["description"]),
        )
        for item in raw_permissions
    )
    classification = "NONE"
    try:
        generate_permission_constants(PermissionManifest("codegen", "1", permissions))
    except ValueError as error:
        classification = classify_codegen_error(error, permissions)
    assert classification == vector["classification"]


def test_local_cli_generates_without_network_configuration(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    output = tmp_path / "permissions.gen.py"
    manifest.write_text(
        '{"manifestId":"orders","revision":"1","permissions":['
        '{"resource":"orders","action":"read","name":"Read","description":null}]}'
    )
    assert main(["generate", "--manifest", str(manifest), "--output", str(output)]) == 0
    assert "ORDERS_READ = PermissionKey('orders', 'read')" in output.read_text()


def test_manifest_reader_rejects_duplicate_members(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        '{"manifestId":"orders","manifestId":"other","revision":"1","permissions":[]}'
    )
    with pytest.raises(ValueError, match="duplicate JSON member"):
        load_permission_manifest(manifest)


def test_identifier_prefixes_leading_digit() -> None:
    assert permission_constant_name("2fa", "read") == "P_2FA_READ"


def classify_codegen_error(
    error: ValueError, permissions: tuple[PermissionManifestDeclaration, ...]
) -> str:
    message = str(error)
    if "duplicate permission key" in message:
        return "DUPLICATE_KEY"
    if "NFC" in message:
        return "NON_NFC"
    if "name collision" in message:
        return "NAME_COLLISION"
    if any(item.resource == "*" or item.action == "*" for item in permissions):
        return "WILDCARD_KEY"
    if "invalid concrete permission key" in message:
        return "MALFORMED_KEY"
    return "UNKNOWN"
