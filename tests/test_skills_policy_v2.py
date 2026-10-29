"""Contract and security tests for the opt-in Skills policy-decision/v2 path."""

import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import fakeredis
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

from app.api import routes_policy
from app.core.skills_policy import (
    ACTION_PERMISSION_MAP,
    APPROVED_MAPPING_DIGEST,
    POLICY_VERSION,
    SkillsPolicyService,
    SkillsPolicySettings,
    permission_set_digest,
)
from app.core.workload_identity import (
    REVOCATION_SLO_SECONDS,
    WORKLOAD_SCOPE,
    JWKSWorkloadIdentityVerifier,
    WorkloadIdentityError,
)
from app.models.skills_policy import SkillsPolicyRequest
from app.services.audit_receipts import AuditReceipt, SecurityAuditReceiptClient
from app.services.cache import PolicyCache

NOW = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)
VALID_WORKLOAD_TOKEN = "fixture-client-credentials-token"


class AllowingVerifier:
    def verify(self, token, **_kwargs):
        if token != VALID_WORKLOAD_TOKEN:
            raise WorkloadIdentityError("workload token verification failed")
        return "gateway-test"


class FakeAuditPublisher:
    def __init__(self):
        self.events = []

    def publish(self, event):
        self.events.append(event)
        return AuditReceipt(
            receipt_id=f"receipt-{event['event_id']}",
            event_id=event["event_id"],
            source="security-audit",
            durable=True,
            persisted_at=NOW,
        )


def settings(**changes):
    values = {
        "live": True,
        "kill_switch": False,
        "execution_enabled": False,
        "owner_approval_reference": "approval:test-only",
        "mapping_digest": APPROVED_MAPPING_DIGEST,
        "tenant_allowlist": frozenset({"tenant-a"}),
        "trusted_workload_clients": frozenset({"gateway-test"}),
        "workload_jwks_url": "http://auth/.well-known/jwks.json",
        "workload_issuer": "omnibioai-auth",
        "workload_audience": "policy-engine",
        "transport_mode": "network-isolated",
        "audit_receipt_url": "http://security-audit/audit/receipts",
        "audit_token_file": "/runtime/secrets/security-audit.token",
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


@pytest.fixture
def service():
    cache = PolicyCache.__new__(PolicyCache)
    cache.redis = fakeredis.FakeRedis(decode_responses=True)
    audit = FakeAuditPublisher()
    instance = SkillsPolicyService(
        cache=cache,
        verifier=AllowingVerifier(),
        clock=lambda: NOW,
        audit=audit,
    )
    cache.redis.set(cache.authorization_epoch_key("tenant-a", "principal-a"), 7)
    return instance, cache, audit


def evaluate(service, req=None, configured=None, workload_token=VALID_WORKLOAD_TOKEN):
    instance, _, _ = service
    req = req or request()
    return instance.evaluate(
        req,
        settings=configured or settings(),
        workload_token=workload_token,
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
    assert decision.audit_receipt_id.startswith("receipt-")
    assert service[2].events[0]["event_type"] == "skill_authorization"
    assert "verified_permissions" not in service[2].events[0]


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


def test_missing_workload_token_denies(service):
    assert evaluate(service, workload_token=None).error_code == "WORKLOAD_UNAUTHORIZED"


def _workload_token(**changes):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(time.time())
    ttl = changes.pop("_ttl", REVOCATION_SLO_SECONDS)
    claims = {
        "aud": "policy-engine",
        "iss": "omnibioai-auth",
        "iat": now,
        "exp": now + ttl,
        "jti": "fixture-jti",
        "type": "access",
        "auth_method": "client_credentials",
        "client_id": "gateway-test",
        "org_id": "tenant-a",
        "scopes": [WORKLOAD_SCOPE],
    }
    claims.update(changes)
    token = jwt.encode(
        claims, private_key, algorithm="RS256", headers={"kid": "test-key"}
    )
    return token, private_key.public_key(), datetime.fromtimestamp(now, tz=UTC)


def _verify_workload(token, public_key, now, **changes):
    jwks_client = MagicMock()
    jwks_client.get_signing_key_from_jwt.return_value = SimpleNamespace(key=public_key)
    verifier = JWKSWorkloadIdentityVerifier(
        jwks_client_factory=lambda _url: jwks_client
    )
    values = {
        "jwks_url": "https://auth/.well-known/jwks.json",
        "issuer": "omnibioai-auth",
        "audience": "policy-engine",
        "trusted_clients": frozenset({"gateway-test"}),
        "tenant_id": "tenant-a",
        "now": now,
    }
    values.update(changes)
    return verifier.verify(token, **values)


def test_jwks_verifier_accepts_short_lived_bound_client_credentials_token():
    token, public_key, now = _workload_token()
    assert _verify_workload(token, public_key, now) == "gateway-test"


@pytest.mark.parametrize(
    "changes",
    [
        {"aud": "wrong-audience"},
        {"auth_method": "password"},
        {"scopes": ["policy.admin"]},
        {"org_id": "tenant-b"},
        {"_ttl": REVOCATION_SLO_SECONDS + 1},
        {"sub": "user-1"},
    ],
)
def test_jwks_verifier_rejects_wrong_or_overlong_workload_tokens(changes):
    token, public_key, now = _workload_token(**changes)
    with pytest.raises(WorkloadIdentityError):
        _verify_workload(token, public_key, now)


def test_transport_requires_tls_or_explicit_network_isolation(service):
    unsafe = settings(transport_mode="tls")
    assert evaluate(service, configured=unsafe).error_code == "TRANSPORT_UNSAFE"
    tls = settings(
        transport_mode="tls",
        workload_jwks_url="https://auth/.well-known/jwks.json",
        audit_receipt_url="https://security-audit/audit/receipts",
    )
    assert evaluate(service, configured=tls).allowed is True


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


def test_security_audit_client_requires_matching_durable_receipt(tmp_path):
    token_file = tmp_path / "audit.token"
    token_file.write_text("fixture-audit-token", encoding="utf-8")
    event = {"event_id": "event-12345678"}

    response = MagicMock()
    response.json.return_value = {
        "receipt_id": "receipt-12345678",
        "event_id": event["event_id"],
        "source": "security-audit",
        "durable": True,
        "persisted_at": NOW.isoformat(),
    }
    post = MagicMock(return_value=response)
    client = SecurityAuditReceiptClient(
        url="https://security-audit/audit/receipts",
        token_file=str(token_file),
        post=post,
    )
    assert client.publish(event).receipt_id == "receipt-12345678"
    assert post.call_args.kwargs["headers"] == {
        "Authorization": "Bearer fixture-audit-token"
    }

    response.json.return_value["durable"] = False
    with pytest.raises(RuntimeError, match="durable receipt"):
        client.publish(event)


def test_route_selects_v2_only_when_feature_flag_is_enabled(monkeypatch):
    req = request()
    expected = {"allowed": True, "schema_version": "policy-decision/v2"}
    evaluator = MagicMock()
    evaluator.evaluate.return_value = expected
    monkeypatch.setattr(routes_policy, "skills_engine", evaluator)
    monkeypatch.setenv("SKILLS_POLICY_LIVE", "true")

    result = routes_policy.evaluate(
        req.model_dump(mode="json"),
        authorization="Bearer fixture-client-credentials-token",
        content_length="512",
    )

    assert result == expected
    evaluator.evaluate.assert_called_once()
    assert evaluator.evaluate.call_args.kwargs["workload_token"] == VALID_WORKLOAD_TOKEN


def test_route_rejects_malformed_or_oversized_v2_without_legacy_fallback(monkeypatch):
    legacy = MagicMock()
    monkeypatch.setattr(routes_policy, "evaluate_policy", legacy)
    monkeypatch.setenv("SKILLS_POLICY_LIVE", "true")

    malformed = routes_policy.evaluate({}, content_length="2")
    oversized = routes_policy.evaluate({}, content_length="20000")

    assert malformed["allowed"] is False and malformed["error_code"] == "MALFORMED"
    assert oversized["allowed"] is False and oversized["error_code"] == "MALFORMED"
    legacy.assert_not_called()
