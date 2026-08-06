"""PR12: permission-aware authorization.

The Gateway's PolicyMiddleware already forwards the requester's JWT
`permissions` claim on every /policy/evaluate call (see
omnibioai-api-gateway app/services/policy_client.py), but until this PR
nothing here ever read it -- authorization was role-name/action-string
matching only (app/core/rbac.py). This module adds a second, additive gate
keyed off the same permission-registry strings omnibioai-auth already
reserves (app/core/permission_names.py there: workflow.execute,
dataset.read, workflow.manage, etc) without inventing any new ones.

Deliberately opt-in: enforced only when the caller actually populates
`permissions` (a non-empty list). No role in the live system is granted
these registry permissions yet (they're reserved-but-unassigned in
omnibioai-auth), so every real request today still carries permissions=[]
and this gate is a no-op there, falling back to the pre-existing
role-based rbac.evaluate_rbac check -- exactly today's behavior, not a
new production restriction. It only actively deters/tests once a caller
(a fixture in these tests, or eventually a real user once
omnibioai-auth grants these permissions to a role) supplies a non-empty
permissions list. This is intentional scope containment for PR12 -- see
this PR's report for why granting these permissions to real roles is out
of scope (would require a DB/role change in omnibioai-auth).
"""

from typing import List, Optional

# action (exact match) -> required permission
ACTION_PERMISSION_MAP = {
    "dataset.read": "dataset.read",
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
