"""Deterministic security-boundary tests for the policy engine.

These tests deliberately use fakes/mocks only.  They cover ordering,
validation, cache failure behavior, and boundary values without requiring
Redis, IAM, a database, or a network service.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from app.core.engine import PolicyEngine
from app.models.request import PolicyRequest
from app.services.cache import PolicyCache


def request(**overrides):
    values = {
        "user_id": "u1",
        "roles": ["researcher"],
        "permissions": [],
        "action": "tes.submit",
        "resource": "job-1",
        "context": {},
    }
    values.update(overrides)
    return PolicyRequest(**values)


def engine_with_redis(redis):
    with patch("app.services.cache.redis") as redis_module:
        redis_module.from_url.return_value = redis
        cache = PolicyCache("redis://unused")
    cache.redis = redis
    return PolicyEngine(cache)


def test_evaluation_stops_at_first_denial_in_security_order():
    redis = MagicMock()
    redis.get.return_value = None
    engine = engine_with_redis(redis)

    with patch("app.core.engine.rbac.evaluate_rbac", return_value=(True, "rbac")) as rbac, \
         patch("app.core.engine.permissions.evaluate_permission", return_value=(True, "permission")) as permission, \
         patch("app.core.engine.tenancy.evaluate_tenancy", return_value=(True, "tenancy")) as tenancy, \
         patch("app.core.engine.abac.evaluate_abac", return_value=(False, "abac deny")) as abac, \
         patch("app.core.engine.rules.evaluate_rules") as rules:
        decision = engine._evaluate_core(request())

    assert (decision.allowed, decision.policy_source, decision.reason) == (
        False,
        "ABAC",
        "abac deny",
    )
    rbac.assert_called_once()
    permission.assert_called_once()
    tenancy.assert_called_once()
    abac.assert_called_once()
    rules.assert_not_called()


@pytest.mark.parametrize(
    ("denying_check", "source", "reason", "later_checks"),
    [
        ("rbac", "RBAC", "rbac deny", ("permission", "tenancy", "abac", "rules")),
        ("permission", "PERMISSION", "permission deny", ("tenancy", "abac", "rules")),
        ("tenancy", "TENANCY", "tenancy deny", ("abac", "rules")),
    ],
)
def test_earlier_denials_prevent_all_later_policy_layers(
    denying_check, source, reason, later_checks
):
    redis = MagicMock()
    redis.get.return_value = None
    engine = engine_with_redis(redis)
    checks = {
        "rbac": "app.core.engine.rbac.evaluate_rbac",
        "permission": "app.core.engine.permissions.evaluate_permission",
        "tenancy": "app.core.engine.tenancy.evaluate_tenancy",
        "abac": "app.core.engine.abac.evaluate_abac",
        "rules": "app.core.engine.rules.evaluate_rules",
    }
    patches = [
        patch(path, return_value=(False, reason) if name == denying_check else (True, name))
        for name, path in checks.items()
    ]
    with patches[0] as rbac, patches[1] as permission, patches[2] as tenancy, patches[3] as abac, patches[4] as rules:
        decision = engine._evaluate_core(request())

    assert decision.allowed is False
    assert decision.policy_source == source
    assert decision.reason == reason
    mocks = dict(zip(checks, (rbac, permission, tenancy, abac, rules)))
    for name in later_checks:
        mocks[name].assert_not_called()


def test_rules_deny_is_not_overridden_by_admin_or_permissions():
    redis = MagicMock()
    redis.get.return_value = None
    engine = engine_with_redis(redis)

    decision = engine._evaluate_core(
        request(
            roles=["admin"],
            permissions=["workflow.manage"],
            action="delete",
            resource="model_registry",
        )
    )

    assert decision.allowed is False
    assert decision.policy_source == "RULES"
    assert decision.reason == "model registry is immutable"


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"user_id": "u1", "action": "read"},
        {"user_id": "u1", "roles": "researcher", "action": "read", "resource": "r"},
        {"user_id": "u1", "roles": [], "action": "read", "resource": "r", "context": []},
    ],
)
def test_malformed_policy_input_is_rejected_before_evaluation(payload):
    with pytest.raises(ValidationError):
        PolicyRequest(**payload)


def test_cache_malformed_external_response_is_not_treated_as_an_allow():
    redis = MagicMock()
    redis.get.return_value = "not-json"
    engine = engine_with_redis(redis)

    with pytest.raises(json.JSONDecodeError):
        engine.evaluate(request())


def test_cache_backend_failure_does_not_fall_through_to_allow():
    redis = MagicMock()
    redis.get.side_effect = ConnectionError("cache unavailable")
    engine = engine_with_redis(redis)

    with pytest.raises(ConnectionError):
        engine.evaluate(request())


def test_cache_key_separates_context_values_that_change_abac_decisions():
    redis = MagicMock()
    cache = engine_with_redis(redis).cache

    unrestricted = cache.build_key("u1", "tes.submit", "job-1", {})
    gpu = cache.build_key("u1", "tes.submit", "job-1", {"gpu_required": True})
    tenant_a = cache.build_key(
        "u1", "tes.submit", "job-1", {"resource_org_id": "org-a"}, org_id="org-a"
    )
    tenant_b = cache.build_key(
        "u1", "tes.submit", "job-1", {"resource_org_id": "org-b"}, org_id="org-b"
    )

    assert unrestricted != gpu
    assert tenant_a != tenant_b


def test_tenancy_missing_context_fails_closed_when_resource_is_scoped():
    redis = MagicMock()
    redis.get.return_value = None
    engine = engine_with_redis(redis)

    decision = engine._evaluate_core(
        request(org_id=None, context={"resource_org_id": "org-a"})
    )

    assert decision.allowed is False
    assert decision.policy_source == "TENANCY"
    assert decision.reason == "missing organization context"


@pytest.mark.xfail(
    strict=True,
    reason="Unknown actions currently pass the default RBAC/permission path; fail-closed unknown-action handling is a production defect.",
)
def test_unknown_action_should_fail_closed():
    redis = MagicMock()
    redis.get.return_value = None
    engine = engine_with_redis(redis)

    decision = engine._evaluate_core(
        request(roles=[], permissions=["unrelated"], action="totally.unknown", resource="unknown")
    )

    assert decision.allowed is False


@pytest.mark.xfail(
    strict=True,
    reason="Wildcard action/resource semantics are not defined or denied; current implementation treats them as unrelated actions.",
)
def test_wildcard_action_should_not_bypass_authorization():
    redis = MagicMock()
    redis.get.return_value = None
    engine = engine_with_redis(redis)

    decision = engine._evaluate_core(
        request(roles=[], permissions=[], action="*", resource="*")
    )

    assert decision.allowed is False
