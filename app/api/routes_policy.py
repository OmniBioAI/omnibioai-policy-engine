"""
OmniBioAI app.api.routes_policy.

Purpose:
    Defines HTTP route handlers for app.api.routes_policy, including evaluate.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

from datetime import UTC, datetime

from fastapi import APIRouter, Header
from pydantic import ValidationError

from app.core.skills_policy import SkillsPolicySettings
from app.models.skills_policy import SkillsPolicyRequest
from app.models.skills_policy import SkillsPolicyErrorCode
from app.services.policy_service import evaluate_policy, skills_engine

router = APIRouter()


@router.post("/evaluate")
def evaluate(
    req: dict,
    authorization: str | None = Header(default=None),
    content_length: str | None = Header(default=None),
):
    settings = SkillsPolicySettings.from_env()
    if settings.live:
        try:
            body_size = int(content_length or "0")
        except ValueError:
            body_size = settings.max_body_bytes + 1
        if body_size > settings.max_body_bytes:
            return {
                "schema_version": "policy-decision/v2",
                "decision_id": "oversized-"
                + datetime.now(UTC).strftime("%Y%m%d%H%M%S%f"),
                "allowed": False,
                "reason": "policy request exceeds the configured size limit",
                "error_code": SkillsPolicyErrorCode.MALFORMED,
                "policy_version": "skills-policy-2026-10-v2",
                "policy_source": "SKILLS_POLICY",
                "evaluated_at": datetime.now(UTC).isoformat(),
                "cache_age_seconds": 0,
                "enforcement": "enforced",
            }
        try:
            request = SkillsPolicyRequest(**req)
        except ValidationError:
            # The legacy route is unreachable while v2 is enabled. A malformed
            # body cannot be safely bound, so return a bounded non-decision.
            return {
                "schema_version": "policy-decision/v2",
                "decision_id": "malformed-"
                + datetime.now(UTC).strftime("%Y%m%d%H%M%S%f"),
                "allowed": False,
                "reason": "malformed policy-decision/v2 request",
                "error_code": SkillsPolicyErrorCode.MALFORMED,
                "policy_version": "skills-policy-2026-10-v2",
                "policy_source": "SKILLS_POLICY",
                "evaluated_at": datetime.now(UTC).isoformat(),
                "cache_age_seconds": 0,
                "enforcement": "enforced",
            }
        scheme, _, token = (authorization or "").partition(" ")
        workload_token = token if scheme.lower() == "bearer" and token else None
        return skills_engine.evaluate(
            request,
            settings=settings,
            workload_token=workload_token,
        )
    return evaluate_policy(req)
