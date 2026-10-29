"""Contract and security tests for the opt-in Skills policy-decision/v2 path."""

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import fakeredis
import pytest
from pydantic import ValidationError

from app.core.skills_policy import (
    ACTION_PERMISSION_MAP,
    APPROVED_MAPPING_DIGEST,
    POLICY_VERSION,
    WORKLOAD_SCOPE,
    SkillsPolicyService,
    SkillsPolicySettings,
    permission_set_digest,
)
from app.models.skills_policy import SkillsPolicyRequest
from app.services.cache import PolicyCache

NOW = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)
SECRET = "fixture-only-workload-secret"


def settings(**changes):
    values = {
        "live": True,
        "kill_switch": False,
        "execution_enabled": False,
        "owner_approval_reference": "approval:test-only",
        "mapping_digest": APPROVED_MAPPING_DIGEST,
        "tenant_allowlist": frozenset({"tenant-a"}),
        "trusted_workloads": frozenset({"gateway-test"}),
        "workload_secret": SECRET,
        "request_max_age_seconds": 30,
        "cache_ttl_seconds": 0,
        "max_body_bytes": 16384,
    }
    values.update(changes)
    return SkillsPolicySettings(**values)


def request(**changes):
    permissions = changes.pop("verified_permissions", ["skill.plan"])
    values = {
        "schema_version": "policy-decision/v2",
        "principal_id": "principal-a",
        "tenant_id": "tenant-a",
        "action": "skill.plan",
        "resource": "skill:variant-annotation@1.2.3",
        "verified_permissions": permissions,
        "permission_set_digest": permission_set_digest(permissions),
        "correlation_id": "corr-1",
        "delegation_reference": None,
        "request_time": NOW,
        "authorization_epoch": 7,
    }
    values.update(changes)
    return SkillsPolicyRequest(**values)


def signature(req, *, workload="gateway-test", scope=WORKLOAD_SCOPE, timestamp=None):
    timestamp = int(NOW.timestamp()) if timestamp is None else timestamp
    canonical = json.dumps(
        req.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    message = "\n".join((workload, scope, str(timestamp), canonical))
    return hmac.new(SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()


@pytest.fixture
def service():
    cache = PolicyCache.__new__(PolicyCache)
    cache.redis = fakeredis.FakeRedis(decode_responses=True)
    audit_events = []
    instance = SkillsPolicyService(
        cache=cache, clock=lambda: NOW, audit=audit_events.append
    )
    cache.redis.set(cache.authorization_epoch_key("tenant-a", "principal-a"), 7)
    return instance, cache, audit_events


def evaluate(service, req=None, configured=None, **identity):
    instance, _, _ = service
    req = req or request()
    timestamp = identity.pop("timestamp", str(int(NOW.timestamp())))
    return instance.evaluate(
        req,
        settings=configured or settings(),
        workload_id=identity.pop("workload_id", "gateway-test"),
        scope=identity.pop("scope", WORKLOAD_SCOPE),
        timestamp=timestamp,
        signature=identity.pop("signature", signature(req, timestamp=int(timestamp))),
    )


def test_approved_mapping_is_exact_and_digest_is_stable():
    assert ACTION_PERMISSION_MAP == {
        f"skill.{name}": f"skill.{name}"
        for name in ("discover", "execute", "plan", "validate")
    }
    assert len(APPROVED_MAPPING_DIGEST) == 64


def test_bound_allow_has_v2_identity_metadata_and_audit(service):
    decision = evaluate(service)
    assert decision.allowed is True
    assert decision.schema_version == "policy-decision/v2"
    assert len(decision.decision_id) == 32
    assert decision.policy_version == POLICY_VERSION
    assert decision.enforcement == "enforced"
    assert decision.principal_id == "principal-a"
    assert decision.tenant_id == "tenant-a"
    assert decision.action == "skill.plan"
    assert decision.resource == "skill:variant-annotation@1.2.3"
    assert service[2][0]["event_type"] == "skill_authorization"
    assert "verified_permissions" not in service[2][0]


@pytest.mark.parametrize(
    ("req", "code"),
    [
        (request(action="skill.unknown"), "UNKNOWN_ACTION"),
        (request(verified_permissions=[]), "DENIED"),
        (request(resource="dataset:not-a-skill"), "UNMAPPED_RESOURCE"),
        (request(permission_set_digest="0" * 64), "BINDING_MISMATCH"),
        (request(request_time=NOW - timedelta(seconds=31)), "STALE"),
    ],
)
def test_gaps_fail_closed(service, req, code):
    decision = evaluate(service, req=req)
    assert decision.allowed is False
    assert decision.error_code == code
    assert decision.enforcement == "enforced"


def test_admin_role_or_wildcard_cannot_be_asserted_or_grant(service):
    with pytest.raises(ValidationError):
        SkillsPolicyRequest(**{**request().model_dump(), "roles": ["admin"]})
    req = request(verified_permissions=["skill.*", "*"])
    assert evaluate(service, req=req).error_code == "DENIED"


def test_workload_authentication_binds_complete_request(service):
    req = request()
    assert (
        evaluate(service, req=req, signature="bad").error_code
        == "WORKLOAD_UNAUTHORIZED"
    )
    assert (
        evaluate(service, req=req, workload_id="unknown").error_code
        == "WORKLOAD_UNAUTHORIZED"
    )
    assert (
        evaluate(service, req=req, scope="policy.admin").error_code
        == "WORKLOAD_UNAUTHORIZED"
    )
    stale = str(int((NOW - timedelta(seconds=31)).timestamp()))
    assert evaluate(service, req=req, timestamp=stale).error_code == "STALE"


@pytest.mark.parametrize(
    "configured",
    [
        settings(owner_approval_reference=""),
        settings(mapping_digest="0" * 64),
        settings(tenant_allowlist=frozenset()),
        settings(kill_switch=True),
    ],
)
def test_activation_controls_fail_closed(service, configured):
    assert evaluate(service, configured=configured).allowed is False


def test_execution_has_independent_default_off_kill_switch(service):
    req = request(action="skill.execute", verified_permissions=["skill.execute"])
    assert evaluate(service, req=req).error_code == "KILL_SWITCH"
    assert (
        evaluate(service, req=req, configured=settings(execution_enabled=True)).allowed
        is True
    )


def test_revocation_epoch_is_checked_before_every_decision(service):
    _, cache, _ = service
    first = evaluate(service)
    second = evaluate(service)
    assert first.allowed and second.allowed
    assert second.decision_id != first.decision_id
    assert second.cache_age_seconds == 0
    cache.redis.set(cache.authorization_epoch_key("tenant-a", "principal-a"), 8)
    revoked = evaluate(service)
    assert revoked.allowed is False
    assert revoked.error_code == "STALE"


def test_positive_decision_caching_fails_closed_until_slo_is_approved(service):
    assert (
        evaluate(service, configured=settings(cache_ttl_seconds=1)).error_code
        == "MALFORMED"
    )


def test_cache_key_partitions_every_authorization_binding(service):
    _, cache, _ = service
    base = {
        "tenant_id": "tenant-a",
        "principal_id": "principal-a",
        "action": "skill.discover",
        "resource": "skill:x@1",
        "permission_set_digest": "a" * 64,
        "authorization_epoch": 1,
        "policy_version": "v1",
        "activation_nonce": "activation-a",
    }
    keys = {cache.build_skills_key(**base)}
    for field, value in {
        "tenant_id": "tenant-b",
        "principal_id": "principal-b",
        "action": "skill.plan",
        "resource": "skill:y@1",
        "permission_set_digest": "b" * 64,
        "authorization_epoch": 2,
        "policy_version": "v2",
        "activation_nonce": "activation-b",
    }.items():
        keys.add(cache.build_skills_key(**{**base, field: value}))
    assert len(keys) == 9


def test_cache_and_revocation_failures_never_allow(service):
    _, cache, _ = service
    cache.redis.get = Mock(side_effect=RuntimeError("down"))
    assert evaluate(service).error_code == "UNAVAILABLE"


def test_audit_failure_turns_allow_into_deny(service):
    instance, _, _ = service
    instance.audit = lambda event: (_ for _ in ()).throw(RuntimeError("audit down"))
    assert evaluate(service).error_code == "AUDIT_FAILURE"
