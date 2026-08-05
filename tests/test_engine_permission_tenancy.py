import json
from unittest.mock import MagicMock, patch

from app.core.engine import PolicyEngine
from app.models.request import PolicyRequest
from app.services.cache import PolicyCache


def make_engine():
    mock_redis = MagicMock()
    mock_redis.get.return_value = None
    with patch("app.services.cache.redis") as mock_redis_module:
        mock_redis_module.from_url.return_value = mock_redis
        cache = PolicyCache(redis_url="redis://localhost")
        cache.redis = mock_redis
    return PolicyEngine(cache=cache), mock_redis


def basic_request(**kwargs):
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
    engine, _ = make_engine()
    req = basic_request(
        roles=["researcher"],
        permissions=["workflow.execute"],
        action="tes.submit",
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
    _, mock_redis = make_engine()
    cache = PolicyCache(redis_url="redis://localhost")
    key_org1 = cache.build_key("u1", "tes.submit", "job", {}, org_id="org-1", permissions=[])
    key_org2 = cache.build_key("u1", "tes.submit", "job", {}, org_id="org-2", permissions=[])
    assert key_org1 != key_org2


def test_cache_key_differs_by_permissions():
    cache = PolicyCache(redis_url="redis://localhost")
    key_a = cache.build_key("u1", "tes.submit", "job", {}, org_id=None, permissions=["workflow.execute"])
    key_b = cache.build_key("u1", "tes.submit", "job", {}, org_id=None, permissions=[])
    assert key_a != key_b
