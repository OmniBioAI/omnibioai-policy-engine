"""Fail-closed, opt-in policy-decision/v2 implementation for Skills."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlparse

from app.core.workload_identity import (
    REVOCATION_SLO_SECONDS,
    JWKSWorkloadIdentityVerifier,
    WorkloadIdentityError,
)
from app.models.skills_policy import (
    SkillsPolicyDecision,
    SkillsPolicyErrorCode,
    SkillsPolicyRequest,
)
from app.services.audit_receipts import (
    AuditReceiptPublisher,
    SecurityAuditReceiptClient,
)
from app.services.cache import PolicyCache

POLICY_VERSION = "skills-policy-2026-10-v2"
RESOURCE_PATTERN = re.compile(
    r"^skill:[a-z0-9][a-z0-9_.-]*@[A-Za-z0-9][A-Za-z0-9_.+-]*$"
)
ACTION_PERMISSION_MAP = {
    "skill.discover": "skill.discover",
    "skill.execute": "skill.execute",
    "skill.plan": "skill.plan",
    "skill.validate": "skill.validate",
}


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


APPROVED_MAPPING_DIGEST = hashlib.sha256(
    _canonical_json(ACTION_PERMISSION_MAP).encode("utf-8")
).hexdigest()


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return -1


class SkillsPolicyError(Exception):
    """A bounded fail-closed error safe to expose to a policy consumer."""

    def __init__(self, code: SkillsPolicyErrorCode, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason


@dataclass(frozen=True)
class SkillsPolicySettings:
    live: bool
    kill_switch: bool
    execution_enabled: bool
    owner_approval_reference: str
    mapping_digest: str
    tenant_allowlist: frozenset[str]
    trusted_workload_clients: frozenset[str]
    workload_jwks_url: str
    workload_issuer: str
    workload_audience: str
    transport_mode: str
    audit_receipt_url: str
    audit_token_file: str
    request_max_age_seconds: int
    cache_ttl_seconds: int
    max_body_bytes: int

    @classmethod
    def from_env(cls) -> SkillsPolicySettings:
        return cls(
            live=os.getenv("SKILLS_POLICY_LIVE", "false").lower() == "true",
            kill_switch=os.getenv("SKILLS_POLICY_KILL_SWITCH", "false").lower()
            == "true",
            execution_enabled=os.getenv("SKILLS_EXECUTION_ENABLED", "false").lower()
            == "true",
            owner_approval_reference=os.getenv(
                "SKILLS_POLICY_OWNER_APPROVAL", ""
            ).strip(),
            mapping_digest=os.getenv("SKILLS_POLICY_MAPPING_DIGEST", "").strip(),
            tenant_allowlist=frozenset(
                item.strip()
                for item in os.getenv("SKILLS_POLICY_TENANT_ALLOWLIST", "").split(",")
                if item.strip()
            ),
            trusted_workload_clients=frozenset(
                item.strip()
                for item in os.getenv("SKILLS_POLICY_TRUSTED_CLIENTS", "").split(",")
                if item.strip()
            ),
            workload_jwks_url=os.getenv("SKILLS_POLICY_JWKS_URL", "").strip(),
            workload_issuer=os.getenv("SKILLS_POLICY_TOKEN_ISSUER", "").strip(),
            workload_audience=os.getenv(
                "SKILLS_POLICY_TOKEN_AUDIENCE", "policy-engine"
            ).strip(),
            transport_mode=os.getenv("SKILLS_POLICY_TRANSPORT_MODE", "").strip(),
            audit_receipt_url=os.getenv("SKILLS_POLICY_AUDIT_RECEIPT_URL", "").strip(),
            audit_token_file=os.getenv("SKILLS_POLICY_AUDIT_TOKEN_FILE", "").strip(),
            request_max_age_seconds=_env_int(
                "SKILLS_POLICY_REQUEST_MAX_AGE_SECONDS", 30
            ),
            cache_ttl_seconds=_env_int("SKILLS_POLICY_CACHE_TTL_SECONDS", 0),
            max_body_bytes=_env_int("SKILLS_POLICY_MAX_BODY_BYTES", 16384),
        )

    def validate_for_request(self, tenant_id: str, action: str) -> None:
        if not self.live:
            raise SkillsPolicyError(SkillsPolicyErrorCode.DISABLED, "skills policy integration is disabled")
        if self.kill_switch:
            raise SkillsPolicyError(
                SkillsPolicyErrorCode.KILL_SWITCH, "skills policy kill switch is active"
            )
        if action == "skill.execute" and not self.execution_enabled:
            raise SkillsPolicyError(
                SkillsPolicyErrorCode.KILL_SWITCH, "skills execution kill switch is active"
            )
        if not self.owner_approval_reference:
            raise SkillsPolicyError(SkillsPolicyErrorCode.UNAPPROVED, "owner approval is absent")
        if not hmac.compare_digest(self.mapping_digest, APPROVED_MAPPING_DIGEST):
            raise SkillsPolicyError(
                SkillsPolicyErrorCode.MAPPING_MISMATCH, "permission mapping is not approved"
            )
        if not self.tenant_allowlist or tenant_id not in self.tenant_allowlist:
            raise SkillsPolicyError(SkillsPolicyErrorCode.TENANT_DENIED, "tenant is not enabled")
        if (
            not self.trusted_workload_clients
            or not self.workload_jwks_url
            or not self.workload_issuer
            or self.workload_audience != "policy-engine"
        ):
            raise SkillsPolicyError(
                SkillsPolicyErrorCode.WORKLOAD_UNAVAILABLE, "workload identity is not configured"
            )
        if self.transport_mode not in {"tls", "network-isolated"}:
            raise SkillsPolicyError(SkillsPolicyErrorCode.TRANSPORT_UNSAFE, "transport guarantee is absent")
        urls = (self.workload_jwks_url, self.audit_receipt_url)
        if not self.audit_receipt_url or not self.audit_token_file:
            raise SkillsPolicyError(
                SkillsPolicyErrorCode.AUDIT_FAILURE, "security-audit receipt is not configured"
            )
        schemes = {urlparse(url).scheme for url in urls}
        if not schemes <= {"http", "https"}:
            raise SkillsPolicyError(SkillsPolicyErrorCode.TRANSPORT_UNSAFE, "endpoint scheme is invalid")
        if schemes != {"https"} and self.transport_mode != "network-isolated":
            raise SkillsPolicyError(
                SkillsPolicyErrorCode.TRANSPORT_UNSAFE, "non-TLS transport is not isolated"
            )
        if self.cache_ttl_seconds != 0:
            raise SkillsPolicyError(
                SkillsPolicyErrorCode.MALFORMED, "positive decision caching is not approved"
            )
        if not 1 <= self.request_max_age_seconds <= REVOCATION_SLO_SECONDS:
            raise SkillsPolicyError(SkillsPolicyErrorCode.MALFORMED, "request freshness limit is invalid")
        if not 1024 <= self.max_body_bytes <= 1_048_576:
            raise SkillsPolicyError(SkillsPolicyErrorCode.MALFORMED, "request size limit is invalid")


def permission_set_digest(permissions: list[str]) -> str:
    normalized = sorted(set(permissions))
    return hashlib.sha256(_canonical_json(normalized).encode("utf-8")).hexdigest()


class SkillsPolicyService:
    def __init__(
        self,
        cache: PolicyCache,
        verifier: JWKSWorkloadIdentityVerifier | None = None,
        clock: Callable[[], datetime] | None = None,
        audit: AuditReceiptPublisher | None = None,
    ) -> None:
        self.cache = cache
        self.verifier = verifier or JWKSWorkloadIdentityVerifier()
        self.clock = clock or (lambda: datetime.now(UTC))
        self.audit = audit

    def evaluate(
        self,
        request: SkillsPolicyRequest,
        *,
        settings: SkillsPolicySettings,
        workload_token: str | None,
    ) -> SkillsPolicyDecision:
        started = time.monotonic()
        now = self.clock()
        try:
            settings.validate_for_request(request.tenant_id, request.action)
            self._validate_request(request, settings, now)
            try:
                self.verifier.verify(
                    workload_token,
                    jwks_url=settings.workload_jwks_url,
                    issuer=settings.workload_issuer,
                    audience=settings.workload_audience,
                    trusted_clients=settings.trusted_workload_clients,
                    tenant_id=request.tenant_id,
                    now=now,
                )
            except WorkloadIdentityError as exc:
                raise SkillsPolicyError(SkillsPolicyErrorCode.WORKLOAD_UNAUTHORIZED, str(exc)) from exc
            self._validate_revocation(request)
            decision = self._evaluate(request, now)
            try:
                receipt_id = self._audit(
                    decision, settings, started, "allow" if decision.allowed else "deny"
                )
            except SkillsPolicyError:
                return self.denial(
                    request, SkillsPolicyErrorCode.AUDIT_FAILURE, "authorization audit failed", now
                )
            return decision.model_copy(update={"audit_receipt_id": receipt_id})
        except SkillsPolicyError as exc:
            decision = self.denial(request, exc.code, exc.reason, now)
            try:
                receipt_id = self._audit(decision, settings, started, "fail")
            except SkillsPolicyError:
                return self.denial(
                    request, SkillsPolicyErrorCode.AUDIT_FAILURE, "authorization audit failed", now
                )
            return decision.model_copy(update={"audit_receipt_id": receipt_id})
        except Exception:  # noqa: BLE001 - every unexpected dependency error must deny
            decision = self.denial(
                request, SkillsPolicyErrorCode.UNAVAILABLE, "policy evaluation unavailable", now
            )
            try:
                receipt_id = self._audit(decision, settings, started, "fail")
            except SkillsPolicyError:
                return self.denial(
                    request, SkillsPolicyErrorCode.AUDIT_FAILURE, "authorization audit failed", now
                )
            return decision.model_copy(update={"audit_receipt_id": receipt_id})

    def _validate_request(
        self,
        request: SkillsPolicyRequest,
        settings: SkillsPolicySettings,
        now: datetime,
    ) -> None:
        required = ACTION_PERMISSION_MAP.get(request.action)
        if required is None:
            raise SkillsPolicyError(SkillsPolicyErrorCode.UNKNOWN_ACTION, "unknown action denied")
        if not RESOURCE_PATTERN.fullmatch(request.resource):
            raise SkillsPolicyError(
                SkillsPolicyErrorCode.UNMAPPED_RESOURCE, "resource is not a canonical skill version"
            )
        if request.permission_set_digest != permission_set_digest(
            request.verified_permissions
        ):
            raise SkillsPolicyError(
                SkillsPolicyErrorCode.BINDING_MISMATCH, "permission set digest mismatch"
            )
        request_time = request.request_time
        if request_time.tzinfo is None:
            raise SkillsPolicyError(SkillsPolicyErrorCode.MALFORMED, "request time must include a timezone")
        age = (now - request_time.astimezone(UTC)).total_seconds()
        if age < -5 or age > settings.request_max_age_seconds:
            raise SkillsPolicyError(SkillsPolicyErrorCode.STALE, "request is outside the freshness window")

    def _validate_revocation(self, request: SkillsPolicyRequest) -> None:
        try:
            current = self.cache.get_authorization_epoch(
                request.tenant_id, request.principal_id
            )
        except Exception as exc:
            raise SkillsPolicyError(
                SkillsPolicyErrorCode.UNAVAILABLE, "revocation authority unavailable"
            ) from exc
        if current is None:
            raise SkillsPolicyError(SkillsPolicyErrorCode.UNAVAILABLE, "revocation evidence is absent")
        if current != request.authorization_epoch:
            raise SkillsPolicyError(SkillsPolicyErrorCode.STALE, "authorization evidence is stale")

    def _evaluate(
        self, request: SkillsPolicyRequest, now: datetime
    ) -> SkillsPolicyDecision:
        required = ACTION_PERMISSION_MAP[request.action]
        if required not in request.verified_permissions:
            decision = self.denial(
                request, SkillsPolicyErrorCode.DENIED, f"missing required permission: {required}", now
            )
        else:
            decision = SkillsPolicyDecision(
                decision_id=uuid.uuid4().hex,
                allowed=True,
                reason="access granted",
                error_code=SkillsPolicyErrorCode.NONE,
                policy_version=POLICY_VERSION,
                policy_source="SKILLS_PERMISSION",
                evaluated_at=now,
                cache_age_seconds=0,
                principal_id=request.principal_id,
                tenant_id=request.tenant_id,
                action=request.action,
                resource=request.resource,
                permission_set_digest=request.permission_set_digest,
                correlation_id=request.correlation_id,
                authorization_epoch=request.authorization_epoch,
            )
        return decision

    @staticmethod
    def denial(
        request: SkillsPolicyRequest, code: SkillsPolicyErrorCode, reason: str, now: datetime
    ) -> SkillsPolicyDecision:
        return SkillsPolicyDecision(
            decision_id=uuid.uuid4().hex,
            allowed=False,
            reason=reason[:256],
            error_code=code,
            policy_version=POLICY_VERSION,
            policy_source="SKILLS_POLICY",
            evaluated_at=now,
            cache_age_seconds=0,
            principal_id=request.principal_id,
            tenant_id=request.tenant_id,
            action=request.action,
            resource=request.resource,
            permission_set_digest=request.permission_set_digest,
            correlation_id=request.correlation_id,
            authorization_epoch=request.authorization_epoch,
        )

    def _audit(
        self,
        decision: SkillsPolicyDecision,
        settings: SkillsPolicySettings,
        started: float,
        outcome: str,
    ) -> str:
        event = {
            "event_id": uuid.uuid4().hex,
            "timestamp": decision.evaluated_at.isoformat(),
            "service": "omnibioai-policy-engine",
            "event_type": "skill_authorization",
            "user_id": decision.principal_id,
            "organization_id": decision.tenant_id,
            "tenant_scope": "organization",
            "action": decision.action,
            "resource": decision.resource,
            "decision": outcome,
            "reason": decision.error_code,
            "trace_id": decision.correlation_id,
            "context": {
                "decision_id": decision.decision_id,
                "policy_version": decision.policy_version,
                "policy_source": decision.policy_source,
                "enforcement": decision.enforcement,
                "cache_age_bucket": "fresh"
                if decision.cache_age_seconds == 0
                else "cached",
                "latency_bucket": "lt_100ms"
                if time.monotonic() - started < 0.1
                else "gte_100ms",
                "error_code": decision.error_code,
            },
        }
        try:
            publisher = self.audit or SecurityAuditReceiptClient(
                url=settings.audit_receipt_url,
                token_file=settings.audit_token_file,
            )
            receipt = publisher.publish(event)
        except Exception as exc:
            raise SkillsPolicyError(
                SkillsPolicyErrorCode.AUDIT_FAILURE, "authorization audit failed"
            ) from exc
        return receipt.receipt_id
