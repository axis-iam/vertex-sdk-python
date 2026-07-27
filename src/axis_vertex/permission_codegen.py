"""Deterministic local constants generation from an explicit permission manifest."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Sequence
from pathlib import Path

from .permission_manifest import (
    PermissionManifest,
    PermissionManifestDeclaration,
    prepare_permission_manifest,
)

_IDENTIFIER_PART = re.compile(r"[^A-Z0-9]+")


def permission_constant_name(resource: str, action: str) -> str:
    """Map a concrete permission key to a stable Python identifier."""

    name = _IDENTIFIER_PART.sub("_", f"{resource}_{action}".upper())
    return f"P_{name}" if name[:1].isdigit() else name


def generate_permission_constants(manifest: PermissionManifest) -> str:
    """Render typed constants without network access or source scanning."""

    prepared = prepare_permission_manifest(manifest, "validate")
    names: dict[str, str] = {}
    lines = [
        '"""Generated from the explicit IAM permission manifest. Do not edit."""',
        "",
        "from axis_vertex.permissions import PermissionKey",
        "",
    ]
    for declaration in prepared.permissions:
        constant = permission_constant_name(declaration.resource, declaration.action)
        previous = names.get(constant)
        if previous is not None:
            raise ValueError(
                f"generated permission name collision: {previous} and {declaration.key} "
                f"both map to {constant}"
            )
        names[constant] = declaration.key
        lines.append(
            f"{constant} = PermissionKey({declaration.resource!r}, {declaration.action!r})"
        )
    lines.extend(
        ("", f"ALL = ({', '.join(names)},)" if names else "ALL: tuple[PermissionKey, ...] = ()", "")
    )
    return "\n".join(lines)


def load_permission_manifest(path: str | Path) -> PermissionManifest:
    """Read an exact structured JSON manifest and reject duplicate members."""

    def exact_object(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"manifest contains duplicate JSON member {key}")
            result[key] = value
        return result

    payload = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=exact_object)
    if not isinstance(payload, dict) or set(payload) != {"manifestId", "revision", "permissions"}:
        raise ValueError("manifest fields must be exactly manifestId, revision and permissions")
    raw_permissions = payload["permissions"]
    if not isinstance(raw_permissions, list):
        raise ValueError("manifest permissions must be an array")
    declarations: list[PermissionManifestDeclaration] = []
    for item in raw_permissions:
        if not isinstance(item, dict) or set(item) != {"resource", "action", "name", "description"}:
            raise ValueError("permission declaration fields must be exact")
        declarations.append(
            PermissionManifestDeclaration(
                _string(item["resource"], "resource"),
                _string(item["action"], "action"),
                _string(item["name"], "name"),
                _nullable_string(item["description"]),
            )
        )
    return PermissionManifest(
        _string(payload["manifestId"], "manifestId"),
        _string(payload["revision"], "revision"),
        tuple(declarations),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vertex-codegen")
    parser.add_argument("generate", choices=["generate"])
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output", required=True)
    options = parser.parse_args(argv)
    output = Path(options.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        generate_permission_constants(load_permission_manifest(options.manifest)), encoding="utf-8"
    )
    return 0


def _string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"permission manifest {field} must be a non-empty string")
    return value


def _nullable_string(value: object) -> str | None:
    if value is None or isinstance(value, str):
        return value
    raise ValueError("permission declaration description must be string or null")
