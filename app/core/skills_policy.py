"""Fail-closed, opt-in policy-decision/v2 implementation for Skills."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from app.models.skills_policy import SkillsPolicyDecision, SkillsPolicyRequest
from app.services.cache import PolicyCache

LOGGER = logging.getLogger("omnibioai.policy.skills")
POLICY_VERSION = "skills-policy-2026-10-v2"
WORKLOAD_SCOPE = "policy.evaluate:skills"
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

    def __init__(self, code: str, reason: str) -> None:
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
    trusted_workloads: frozenset[str]
    workload_secret: str
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
            trusted_workloads=frozenset(
                item.strip()
                for item in os.getenv("SKILLS_POLICY_TRUSTED_WORKLOADS", "").split(",")
                if item.strip()
            ),
            workload_secret=os.getenv("SKILLS_POLICY_WORKLOAD_SECRET", ""),
            request_max_age_seconds=_env_int(
                "SKILLS_POLICY_REQUEST_MAX_AGE_SECONDS", 30
            ),
            cache_ttl_seconds=_env_int("SKILLS_POLICY_CACHE_TTL_SECONDS", 0),
            max_body_bytes=_env_int("SKILLS_POLICY_MAX_BODY_BYTES", 16384),
        )

    def validate_for_request(self, tenant_id: str, action: str) -> None:
        if not self.live:
            raise SkillsPolicyError("DISABLED", "skills policy integration is disabled")
        if self.kill_switch:
            raise SkillsPolicyError(
                "KILL_SWITCH", "skills policy kill switch is active"
            )
        if action == "skill.execute" and not self.execution_enabled:
            raise SkillsPolicyError(
                "KILL_SWITCH", "skills execution kill switch is active"
            )
        if not self.owner_approval_reference:
            raise SkillsPolicyError("UNAPPROVED", "owner approval is absent")
        if not hmac.compare_digest(self.mapping_digest, APPROVED_MAPPING_DIGEST):
            raise SkillsPolicyError(
                "MAPPING_MISMATCH", "permission mapping is not approved"
            )
        if not self.tenant_allowlist or tenant_id not in self.tenant_allowlist:
            raise SkillsPolicyError("TENANT_DENIED", "tenant is not enabled")
        if not self.trusted_workloads or not self.workload_secret:
            raise SkillsPolicyError(
                "WORKLOAD_UNAVAILABLE", "workload identity is not configured"
            )
        if self.cache_ttl_seconds != 0:
            raise SkillsPolicyError(
                "MALFORMED", "positive decision caching is not approved"
            )
        if not 1 <= self.request_max_age_seconds <= 300:
            raise SkillsPolicyError("MALFORMED", "request freshness limit is invalid")
        if not 1024 <= self.max_body_bytes <= 1_048_576:
            raise SkillsPolicyError("MALFORMED", "request size limit is invalid")


class WorkloadIdentityVerifier:
    """Verify a runtime-injected HMAC workload credential over the complete request."""

    def verify(
        self,
        request: SkillsPolicyRequest,
        settings: SkillsPolicySettings,
        workload_id: str | None,
        scope: str | None,
        timestamp: str | None,
        signature: str | None,
        now: datetime,
    ) -> None:
        if not workload_id or workload_id not in settings.trusted_workloads:
            raise SkillsPolicyError(
                "WORKLOAD_UNAUTHORIZED", "workload identity is not trusted"
            )
        if scope != WORKLOAD_SCOPE:
            raise SkillsPolicyError(
                "WORKLOAD_UNAUTHORIZED", "workload scope is invalid"
            )
        try:
            signed_at = int(timestamp or "")
        except ValueError as exc:
            raise SkillsPolicyError(
                "WORKLOAD_UNAUTHORIZED", "workload timestamp is invalid"
            ) from exc
        if abs(int(now.timestamp()) - signed_at) > settings.request_max_age_seconds:
            raise SkillsPolicyError("STALE", "workload credential is stale")
        message = "\n".join(
            (
                workload_id,
                scope,
                str(signed_at),
                _canonical_json(request.model_dump(mode="json")),
            )
        )
        expected = hmac.new(
            settings.workload_secret.encode("utf-8"),
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not signature or not hmac.compare_digest(signature, expected):
            raise SkillsPolicyError(
                "WORKLOAD_UNAUTHORIZED", "workload signature is invalid"
            )


def permission_set_digest(permissions: list[str]) -> str:
    normalized = sorted(set(permissions))
    return hashlib.sha256(_canonical_json(normalized).encode("utf-8")).hexdigest()


class SkillsPolicyService:
    def __init__(
        self,
        cache: PolicyCache,
        verifier: WorkloadIdentityVerifier | None = None,
        clock: Callable[[], datetime] | None = None,
        audit: Callable[[dict], None] | None = None,
    ) -> None:
        self.cache = cache
        self.verifier = verifier or WorkloadIdentityVerifier()
        self.clock = clock or (lambda: datetime.now(UTC))
        self.audit = audit or (
            lambda event: LOGGER.info("skill_authorization %s", _canonical_json(event))
        )

    def evaluate(
        self,
        request: SkillsPolicyRequest,
        *,
        settings: SkillsPolicySettings,
        workload_id: str | None,
        scope: str | None,
        timestamp: str | None,
        signature: str | None,
    ) -> SkillsPolicyDecision:
        started = time.monotonic()
        now = self.clock()
        try:
            settings.validate_for_request(request.tenant_id, request.action)
            self._validate_request(request, settings, now)
            self.verifier.verify(
                request, settings, workload_id, scope, timestamp, signature, now
            )
            self._validate_revocation(request)
            decision = self._evaluate(request, now)
            try:
                self._audit(decision, started, "allow" if decision.allowed else "deny")
            except SkillsPolicyError:
                return self.denial(
                    request, "AUDIT_FAILURE", "authorization audit failed", now
                )
            return decision
        except SkillsPolicyError as exc:
            decision = self.denial(request, exc.code, exc.reason, now)
            try:
                self._audit(decision, started, "fail")
            except SkillsPolicyError:
                return self.denial(
                    request, "AUDIT_FAILURE", "authorization audit failed", now
                )
            return decision
        except Exception:  # noqa: BLE001 - every unexpected dependency error must deny
            decision = self.denial(
                request, "UNAVAILABLE", "policy evaluation unavailable", now
            )
            try:
                self._audit(decision, started, "fail")
            except Exception:
                LOGGER.exception("authorization denial audit failed")
            return decision

    def _validate_request(
        self,
        request: SkillsPolicyRequest,
        settings: SkillsPolicySettings,
        now: datetime,
    ) -> None:
        required = ACTION_PERMISSION_MAP.get(request.action)
        if required is None:
            raise SkillsPolicyError("UNKNOWN_ACTION", "unknown action denied")
        if not RESOURCE_PATTERN.fullmatch(request.resource):
            raise SkillsPolicyError(
                "UNMAPPED_RESOURCE", "resource is not a canonical skill version"
            )
        if request.permission_set_digest != permission_set_digest(
            request.verified_permissions
        ):
            raise SkillsPolicyError(
                "BINDING_MISMATCH", "permission set digest mismatch"
            )
        request_time = request.request_time
        if request_time.tzinfo is None:
            raise SkillsPolicyError("MALFORMED", "request time must include a timezone")
        age = (now - request_time.astimezone(UTC)).total_seconds()
        if age < -5 or age > settings.request_max_age_seconds:
            raise SkillsPolicyError("STALE", "request is outside the freshness window")

    def _validate_revocation(self, request: SkillsPolicyRequest) -> None:
        try:
            current = self.cache.get_authorization_epoch(
                request.tenant_id, request.principal_id
            )
        except Exception as exc:
            raise SkillsPolicyError(
                "UNAVAILABLE", "revocation authority unavailable"
            ) from exc
        if current is None:
            raise SkillsPolicyError("UNAVAILABLE", "revocation evidence is absent")
        if current != request.authorization_epoch:
            raise SkillsPolicyError("STALE", "authorization evidence is stale")

    def _evaluate(
        self, request: SkillsPolicyRequest, now: datetime
    ) -> SkillsPolicyDecision:
        required = ACTION_PERMISSION_MAP[request.action]
        if required not in request.verified_permissions:
            decision = self.denial(
                request, "DENIED", f"missing required permission: {required}", now
            )
        else:
            decision = SkillsPolicyDecision(
                decision_id=uuid.uuid4().hex,
                allowed=True,
                reason="access granted",
                error_code="NONE",
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
        request: SkillsPolicyRequest, code: str, reason: str, now: datetime
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
        self, decision: SkillsPolicyDecision, started: float, outcome: str
    ) -> None:
        event = {
            "event_type": "skill_authorization",
            "event_id": uuid.uuid4().hex,
            "decision_id": decision.decision_id,
            "correlation_id": decision.correlation_id,
            "tenant_id": decision.tenant_id,
            "principal_id": decision.principal_id,
            "action": decision.action,
            "resource": decision.resource,
            "outcome": outcome,
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
        }
        try:
            self.audit(event)
        except Exception as exc:
            raise SkillsPolicyError(
                "AUDIT_FAILURE", "authorization audit failed"
            ) from exc
