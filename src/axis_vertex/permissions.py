"""Permission model helpers shared by core and framework adapters."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

_CONCRETE_SEGMENT = re.compile(r"^[a-z0-9_-]{1,128}$")


@dataclass(frozen=True, slots=True)
class PermissionKey:
    """Canonical ``resource:action`` permission identifier."""

    resource: str
    action: str

    def authority(self) -> str:
        """Return the wire-format authority string."""

        return f"{self.resource}:{self.action}"


@dataclass(frozen=True, slots=True)
class PermissionDefinition:
    """Permission declaration that can be registered with IAM."""

    resource: str
    action: str
    description: str = ""

    @property
    def key(self) -> PermissionKey:
        """Return the key for this definition."""

        return PermissionKey(self.resource, self.action)


def parse_permission(value: str) -> PermissionKey | None:
    """Parse ``resource:action`` and reject malformed values fail-safe."""

    if value.count(":") != 1:
        return None
    resource, action = value.split(":", 1)
    if not resource or not action:
        return None
    return PermissionKey(resource, action)


def matches_permission(target: PermissionKey, granted: str) -> bool:
    """Return whether ``granted`` satisfies ``target``.

    Matching is case-sensitive and aligned with Java/Go/JS SDK behavior:
    exact, resource action wildcard, and full wildcard. ``*:action`` and
    malformed/non-canonical granted strings never match.
    """

    if not _CONCRETE_SEGMENT.fullmatch(target.resource) or not _CONCRETE_SEGMENT.fullmatch(
        target.action
    ):
        return False
    grant = parse_permission(granted)
    if grant is None:
        return False
    if grant.resource == "*":
        return grant.action == "*"
    if not _CONCRETE_SEGMENT.fullmatch(grant.resource):
        return False
    if grant.action == "*":
        return grant.resource == target.resource
    return bool(
        _CONCRETE_SEGMENT.fullmatch(grant.action)
        and grant.resource == target.resource
        and grant.action == target.action
    )


def match_permission(
    permissions: Iterable[str],
    resource: str,
    action: str,
) -> bool:
    """Return whether a permission set contains ``resource:action``."""

    return has_permission(PermissionKey(resource, action), permissions)


def has_permission(target: PermissionKey, permissions: Iterable[str]) -> bool:
    """Return whether any granted permission satisfies ``target``."""

    return any(matches_permission(target, granted) for granted in permissions)


def has_any_permission(targets: Sequence[PermissionKey], permissions: Iterable[str]) -> bool:
    """Return whether at least one target is satisfied."""

    return any(has_permission(target, permissions) for target in targets)


def has_all_permissions(targets: Sequence[PermissionKey], permissions: Iterable[str]) -> bool:
    """Return whether every target is satisfied; empty target lists deny."""

    return bool(targets) and all(has_permission(target, permissions) for target in targets)
