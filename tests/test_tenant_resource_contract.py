"""G4 reproduction tests for explicit global/tenant/admin resource scope."""

from app.core.engine import PolicyEngine
from app.models.request import PolicyRequest
from tests.test_engine import make_engine


def _request(**overrides):
    data = dict(
        user_id="u1", roles=["researcher"], permissions=["dataset.read"],
        action="dataset.read", resource="study-a", org_id="org-a", context={},
        resource_scope="tenant",
    )
    data.update(overrides)
    return PolicyRequest(**data)


def test_tenant_resource_with_matching_owner_is_allowed():
    engine, _ = make_engine()
    decision = engine._evaluate_core(_request(context={"resource_org_id": "org-a"}))
    assert decision.allowed is True


def test_tenant_resource_with_mismatched_owner_is_denied():
    engine, _ = make_engine()
    decision = engine._evaluate_core(_request(context={"resource_org_id": "org-b"}))
    assert decision.allowed is False
    assert decision.policy_source == "TENANCY"


def test_tenant_resource_missing_owner_context_is_denied():
    engine, _ = make_engine()
    decision = engine._evaluate_core(_request())
    assert decision.allowed is False
    assert decision.policy_source == "TENANCY"


def test_global_resource_without_owner_context_remains_allowed():
    engine, _ = make_engine()
    decision = engine._evaluate_core(_request(resource_scope="global", context={}))
    assert decision.allowed is True


def test_platform_admin_resource_requires_explicit_admin_role():
    engine, _ = make_engine()
    denied = engine._evaluate_core(_request(resource_scope="admin", roles=["researcher"]))
    allowed = engine._evaluate_core(_request(resource_scope="admin", roles=["admin"]))
    assert denied.allowed is False
    assert allowed.allowed is True
