"""Generated from examples/iam-permission-manifest.json. Do not edit."""

from axis_vertex.permissions import PermissionKey

ORDERS_CREATE = PermissionKey("orders", "create")

ALL = (ORDERS_CREATE,)
