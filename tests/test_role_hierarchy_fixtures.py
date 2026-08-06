"""PR12 SS2 RBAC Permission Validation.

The PR12 spec describes a conceptual Platform Owner -> Organization Admin
-> Scientist -> Viewer hierarchy. omnibioai-auth has no roles by those
names (see this PR's architecture report) -- it has global admin/
platform_admin and org-scoped org_admin/org_member, plus a permission
registry with entries (workflow.execute, dataset.read, workflow.manage,
manage_all_orgs, manage_org, billing.manage, ...) that are reserved but
not yet granted to any role. Per this PR's scope decision, these fixtures
map the spec's conceptual tiers onto that real vocabulary *for testing
this engine* -- no new role or DB change is introduced anywhere.

Composition note: RBAC (legacy, app/core/rbac.py -- role-name/action-
prefix matching) and PERMISSION (new, app/core/permissions.py --
registry-permission matching) are both independent, additive gates over
the same actions, not alternatives -- see this PR's report for why (a
permission alone cannot substitute for the legacy role check without
either changing rbac.py's existing behavior, which several of its own
unit tests lock in, or silently loosening enforcement for the ~100% of
today's real traffic that has permissions=[]). So a tier that needs to
pass an action gated by rbac.py (tes.* requires "researcher") must carry
both the legacy role AND the registry permission. The one deliberate
exception is dataset.read, narrowed in rbac.py by this same PR to be
governed by the permission gate alone -- see that change's comment --
which is what makes a genuine read-only Viewer tier possible at all.
"""

import pytest

from app.core.engine import PolicyEngine
from app.models.request import PolicyRequest
from app.services.cache import PolicyCache
from unittest.mock import MagicMock, patch


def make_engine():
    mock_redis = MagicMock()
    mock_redis.get.return_value = None
    with patch("app.services.cache.redis") as mock_redis_module:
        mock_redis_module.from_url.return_value = mock_redis
        cache = PolicyCache(redis_url="redis://localhost")
        cache.redis = mock_redis
    return PolicyEngine(cache=cache)


# Conceptual tier -> (roles, permissions), mirroring PR12 SS2's fixture list.
PLATFORM_OWNER = (["admin"], ["manage_all_orgs", "manage_roles", "billing.manage", "workflow.execute"])
ORG_ADMIN = (["researcher"], ["manage_org", "manage_teams", "workflow.execute", "workflow.manage", "dataset.read"])
SCIENTIST = (["researcher"], ["workflow.execute", "dataset.read"])
VIEWER = ([], ["dataset.read"])


def request_for(tier, action, resource="job_queue", org_id="org-1", context=None):
    roles, perms = tier
    return PolicyRequest(
        user_id="u1",
        email="u1@test.com",
        roles=roles,
        permissions=perms,
        org_id=org_id,
        action=action,
        resource=resource,
        context=context or {},
    )


# ---------------------------------------------------------------------------
# Allowed: user with permission -> success
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tier", [PLATFORM_OWNER, ORG_ADMIN, SCIENTIST])
def test_execute_workflows_allowed_for_tiers_holding_workflow_execute(tier):
    engine = make_engine()
    decision = engine._evaluate_core(request_for(tier, "tes.submit"))
    assert decision.allowed is True


@pytest.mark.parametrize("tier", [PLATFORM_OWNER, ORG_ADMIN, SCIENTIST, VIEWER])
def test_dataset_read_allowed_for_every_tier(tier):
    engine = make_engine()
    decision = engine._evaluate_core(request_for(tier, "dataset.read"))
    assert decision.allowed is True


def test_org_admin_workflow_manage_permission_passes_but_immutable_rule_still_blocks():
    """"Manage resources" for Org Admin passes RBAC and the new PERMISSION
    gate (workflow.manage present) -- but model_registry deletion is an
    absolute RULES-layer restriction that applies to every tier, including
    admin (see test_rules_deny_model_registry_delete in test_engine.py).
    A registry permission is not a way around that -- defense in depth."""
    engine = make_engine()
    decision = engine._evaluate_core(
        request_for(ORG_ADMIN, "delete", resource="model_registry")
    )
    assert decision.allowed is False
    assert decision.policy_source == "RULES"


# ---------------------------------------------------------------------------
# Denied: missing permission -> 403-equivalent (allowed=False)
# ---------------------------------------------------------------------------

def test_viewer_denied_execute_workflows():
    engine = make_engine()
    decision = engine._evaluate_core(request_for(VIEWER, "tes.submit"))
    assert decision.allowed is False


def test_scientist_denied_model_registry_delete():
    engine = make_engine()
    decision = engine._evaluate_core(
        request_for(SCIENTIST, "delete", resource="model_registry")
    )
    assert decision.allowed is False
    assert decision.policy_source == "PERMISSION"
    assert "workflow.manage" in decision.reason


# ---------------------------------------------------------------------------
# Tenancy still applies regardless of tier
# ---------------------------------------------------------------------------

def test_org_admin_denied_cross_org_even_with_manage_org():
    engine = make_engine()
    decision = engine._evaluate_core(
        request_for(
            ORG_ADMIN,
            "tes.submit",
            org_id="org-1",
            context={"resource_org_id": "org-2"},
        )
    )
    assert decision.allowed is False
    assert decision.policy_source == "TENANCY"
