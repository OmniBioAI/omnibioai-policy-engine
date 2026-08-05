"""PR12: organization-tenancy scoping.

Neither this service nor omnibioai-hpc-policy-engine had any concept of
org_id before this PR -- authorization was scoped only per user_id. This
adds an additive tenancy gate: if the request names which organization
owns the resource being acted on (`context["resource_org_id"]`, supplied
by the caller -- this service has no database of its own to look
resource ownership up in), the requester's own `org_id` must match it.

Opt-in the same way app/core/permissions.py is: a caller that never
supplies `resource_org_id` in context (true of every caller today) gets
"no tenancy scoping required" -- a no-op, not a new restriction on
existing traffic. It only activates once a caller (a fixture in these
tests, or eventually the Gateway once it's taught which org owns a given
resource) actually supplies it.
"""

from typing import Any, Dict


def evaluate_tenancy(org_id: Any, context: Dict[str, Any]) -> tuple[bool, str]:
    resource_org_id = context.get("resource_org_id")

    if resource_org_id is None:
        return True, "no tenancy scoping required"

    if org_id is None:
        return False, "missing organization context"

    if str(org_id) != str(resource_org_id):
        return False, "cross-tenant access denied"

    return True, "tenancy check passed"
