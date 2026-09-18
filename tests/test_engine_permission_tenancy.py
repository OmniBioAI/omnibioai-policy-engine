"""Unit tests for PolicyEngine's permission and tenancy checks: a required
permission's absence denies at the PERMISSION stage (unless the caller is admin
or held no permissions at all, the legacy role-only shape), a request whose
resource organization differs from the caller's is denied at the TENANCY stage,
and PolicyCache.build_key's cache key varies with organization id and
permissions.

Developer: Manish Kumar <manish@omnibioai.org>
"""
import json
from unittest.mock import MagicMock, patch

from app.core.engine import PolicyEngine
from app.models.request import PolicyRequest
from app.services.cache import PolicyCache


def make_engine():
    """Build a PolicyEngine with its cache backed by a mock Redis client that always misses."""
    mock_redis = MagicMock()
    mock_redis.get.return_value = None
    with patch("app.services.cache.redis") as mock_redis_module:
        mock_redis_module.from_url.return_value = mock_redis
        cache = PolicyCache(redis_url="redis://localhost")
        cache.redis = mock_redis
    return PolicyEngine(cache=cache), mock_redis


def basic_request(**kwargs):
    """Build a PolicyRequest with sensible defaults, overridable by keyword."""
    defaults = {
        "user_id": "u1",
        "email": "u1@test.com",
        "roles": [],
        "permissions": [],
        "org_id": None,
        "action": "tes.submit",
        "resource": "job_queue",
        "context": {},
    }
    defaults.update(kwargs)
    return PolicyRequest(**defaults)


# ---------------------------------------------------------------------------
# PERMISSION gate runs after RBAC, before ABAC/RULES
# ---------------------------------------------------------------------------

def test_permission_deny_stops_before_abac():
    """A request lacking the required workflow.execute permission is denied at the PERMISSION stage
    with a reason naming it.
    """
    engine, _ = make_engine()
    req = basic_request(
        roles=["researcher"],  # passes RBAC
        permissions=["dataset.read"],  # populated, but missing workflow.execute
        action="tes.submit",
        context={"gpu_required": True},  # would also fail ABAC if reached
    )

    decision = engine._evaluate_core(req)

    assert decision.allowed is False
    assert decision.policy_source == "PERMISSION"
    assert "workflow.execute" in decision.reason


def test_permission_allow_falls_through_to_all_passed():
    """A request holding the required workflow.execute permission passes through to ALL_PASSED."""
    engine, _ = make_engine()
    req = basic_request(
        roles=["researcher"],
        permissions=["workflow.execute"],
        action="tes.submit",
    )

    decision = engine._evaluate_core(req)

    assert decision.allowed is True
    assert decision.policy_source == "ALL_PASSED"


def test_permission_deny_for_real_gateway_action_shape_workflow_execute():
    """PR13 regression lock: the tests above all use action="tes.submit",
    which is never what real gateway-routed traffic actually sends for
    workbench/tes/toolserver (the Gateway's PolicyClient pre-resolves
    `action` to the literal permission string itself, per
    SERVICE_PERMISSION_MAP) -- this is that real shape, and would have
    caught the ACTION_PERMISSION_MAP gap this PR fixes (previously
    required_permission("workflow.execute", ...) returned None, so this
    request was allowed unconditionally regardless of `permissions`)."""
    engine, _ = make_engine()
    req = basic_request(
        roles=[], permissions=["dataset.read"],  # populated, but missing workflow.execute
        action="workflow.execute", resource="workbench",
    )

    decision = engine._evaluate_core(req)

    assert decision.allowed is False
    assert decision.policy_source == "PERMISSION"


def test_permission_allow_for_real_gateway_action_shape_model_use():
    """A request for the real model.use action against the model registry, holding no roles but the
    model.use permission, is allowed.
    """
    engine, _ = make_engine()
    req = basic_request(
        roles=[], permissions=["model.use"], action="model.use", resource="model-registry",
    )

    decision = engine._evaluate_core(req)

    assert decision.allowed is True
    assert decision.policy_source == "ALL_PASSED"


def test_permission_check_is_noop_for_legacy_role_only_traffic():
    """No permissions supplied at all (today's real production shape) must
    behave exactly as it did before this PR."""
    engine, _ = make_engine()
    req = basic_request(roles=["researcher"], permissions=[], action="tes.submit")

    decision = engine._evaluate_core(req)

    assert decision.allowed is True
    assert decision.policy_source == "ALL_PASSED"


# ---------------------------------------------------------------------------
# TENANCY gate runs after PERMISSION, before ABAC/RULES
# ---------------------------------------------------------------------------

def test_tenancy_deny_cross_org_access():
    """A request whose resource belongs to a different organization than the caller is denied at the
    TENANCY stage with reason "cross-tenant access denied".
    """
    engine, _ = make_engine()
    req = basic_request(
        roles=["researcher"],
        permissions=["workflow.execute"],
        org_id="org-1",
        action="tes.submit",
        context={"resource_org_id": "org-2"},
    )

    decision = engine._evaluate_core(req)

    assert decision.allowed is False
    assert decision.policy_source == "TENANCY"
    assert decision.reason == "cross-tenant access denied"


def test_tenancy_allow_same_org():
    """A request whose resource belongs to the caller's own organization passes the TENANCY stage.
    """
    engine, _ = make_engine()
    req = basic_request(
        roles=["researcher"],
        permissions=["workflow.execute"],
        org_id="org-1",
        action="tes.submit",
        context={"resource_org_id": "org-1"},
    )

    decision = engine._evaluate_core(req)

    assert decision.allowed is True
    assert decision.policy_source == "ALL_PASSED"


def test_admin_bypasses_permission_but_not_tenancy():
    """Admin override in rbac/permissions is a role-scope bypass, not a
    tenancy bypass -- an admin acting cross-org must still be scoped,
    since tenancy is about *which organization's data*, not *how
    privileged this user is*."""
    engine, _ = make_engine()
    req = basic_request(
        roles=["admin"],
        permissions=[],
        org_id="org-1",
        action="tes.submit",
        context={"resource_org_id": "org-2"},
    )

    decision = engine._evaluate_core(req)

    assert decision.allowed is False
    assert decision.policy_source == "TENANCY"


# ---------------------------------------------------------------------------
# Cache key incorporates org_id/permissions
# ---------------------------------------------------------------------------

def test_cache_key_differs_by_org_id():
    """build_key produces different cache keys for the same request under different organization
    ids.
    """
    _, mock_redis = make_engine()
    cache = PolicyCache(redis_url="redis://localhost")
    key_org1 = cache.build_key("u1", "tes.submit", "job", {}, org_id="org-1", permissions=[])
    key_org2 = cache.build_key("u1", "tes.submit", "job", {}, org_id="org-2", permissions=[])
    assert key_org1 != key_org2


def test_cache_key_differs_by_permissions():
    """build_key produces different cache keys for the same request with different permission sets.
    """
    cache = PolicyCache(redis_url="redis://localhost")
    key_a = cache.build_key("u1", "tes.submit", "job", {}, org_id=None, permissions=["workflow.execute"])
    key_b = cache.build_key("u1", "tes.submit", "job", {}, org_id=None, permissions=[])
    assert key_a != key_b
