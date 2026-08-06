"""PR12: permission-aware authorization.

The Gateway's PolicyMiddleware already forwards the requester's JWT
`permissions` claim on every /policy/evaluate call (see
omnibioai-api-gateway app/services/policy_client.py), but until this PR
nothing here ever read it -- authorization was role-name/action-string
matching only (app/core/rbac.py). This module adds a second, additive gate
keyed off the same permission-registry strings omnibioai-auth already
reserves (app/core/permission_names.py there: workflow.execute,
dataset.read, workflow.manage, etc) without inventing any new ones.

Deliberately opt-in: still a no-op for a caller who supplies
permissions=[] (falls back to the pre-existing role-based
rbac.evaluate_rbac check), so nothing here changes behavior for traffic
that predates permission-awareness entirely.

PR13 (Dynamic Permission Assignment & Enterprise RBAC Activation):
omnibioai-auth now grants these registry permissions to real roles
(scientist/viewer, and any org's custom roles), so `permissions` is
populated for real traffic, not just this file's own test fixtures --
this gate is now genuinely live, not aspirational. That PR also fixed a
real gap in ACTION_PERMISSION_MAP below: workbench/tes/toolserver/
model-registry (4 of the 5 gateway-routed services) had zero real
enforcement through this gate regardless of what permissions a caller
held, because the Gateway sends `action` as the literal permission string
itself ("workflow.execute"/"model.use") for those services, which matched
neither this map nor PREFIX_PERMISSION_MAP's "tes." prefix rule -- only
"dataset.read" (rag) was ever actually enforced. See
tests/test_permissions.py's workflow.execute/model.use regression tests.
"""

from typing import List, Optional

# action (exact match) -> required permission
#
# PR13: workflow.execute/model.use added. The Gateway's PolicyClient
# (omnibioai-api-gateway app/services/policy_client.py) pre-resolves
# `action` from SERVICE_PERMISSION_MAP for its 5 mapped services -- for
# workbench/tes/toolserver it sends the literal string "workflow.execute",
# for model-registry "model.use". Before this PR, only "dataset.read" (rag)
# had a matching entry here; the other two matched neither this map nor
# PREFIX_PERMISSION_MAP's "tes." prefix (the literal string "workflow.execute"
# does not start with "tes." -- that prefix only ever matched this module's
# own synthetic test fixtures, never real gateway traffic), so
# required_permission() silently returned None and evaluate_permission
# allowed unconditionally for 4 of 5 gateway-routed services regardless of
# what the caller's permissions were. These two entries are identity
# mappings by design, matching how "dataset.read" already (correctly)
# worked -- the map's job for gateway-routed traffic is confirming "yes,
# this action requires this permission," not translating one string to
# another.
ACTION_PERMISSION_MAP = {
    "dataset.read": "dataset.read",
    "workflow.execute": "workflow.execute",
    "model.use": "model.use",
}

# action prefix -> required permission
PREFIX_PERMISSION_MAP = {
    "tes.": "workflow.execute",
}

# (resource, action) -> required permission
RESOURCE_ACTION_PERMISSION_MAP = {
    ("model_registry", "delete"): "workflow.manage",
}


def required_permission(action: str, resource: str) -> Optional[str]:
    if action in ACTION_PERMISSION_MAP:
        return ACTION_PERMISSION_MAP[action]

    for prefix, permission in PREFIX_PERMISSION_MAP.items():
        if action.startswith(prefix):
            return permission

    return RESOURCE_ACTION_PERMISSION_MAP.get((resource, action))


def evaluate_permission(
    roles: List[str], permissions: List[str], action: str, resource: str
) -> tuple[bool, str]:
    if "admin" in roles:
        return True, "admin override"

    if not permissions:
        # Not permission-aware traffic (see module docstring) -- defer
        # entirely to rbac.evaluate_rbac, which already ran before this.
        return True, "permission check skipped: no permissions supplied"

    permission = required_permission(action, resource)
    if permission is None:
        return True, "no permission required"

    if permission in permissions:
        return True, "permission granted"

    return False, f"missing permission: {permission}"
