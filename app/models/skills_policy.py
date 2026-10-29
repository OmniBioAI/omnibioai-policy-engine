"""Versioned, bound models for the opt-in Skills policy contract."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class SkillsPolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["policy-decision/v2"]
    principal_id: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=256)
    action: str = Field(min_length=1, max_length=128)
    resource: str = Field(min_length=1, max_length=512)
    verified_permissions: list[str] = Field(max_length=256)
    permission_set_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    correlation_id: str = Field(min_length=1, max_length=256)
    delegation_reference: str | None = Field(default=None, max_length=256)
    request_time: datetime
    authorization_epoch: int = Field(ge=0)


class SkillsPolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["policy-decision/v2"] = "policy-decision/v2"
    decision_id: str = Field(min_length=8, max_length=128)
    allowed: bool
    reason: str = Field(max_length=256)
    error_code: str
    policy_version: str
    policy_source: str
    evaluated_at: datetime
    cache_age_seconds: float = Field(ge=0)
    enforcement: Literal["enforced"] = "enforced"
    principal_id: str
    tenant_id: str
    action: str
    resource: str
    permission_set_digest: str
    correlation_id: str
    authorization_epoch: int
    audit_receipt_id: str | None = None
