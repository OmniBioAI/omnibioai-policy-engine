"""Versioned, bound models for the opt-in Skills policy contract."""

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


ERROR_CODE_CONTRACT_VERSION = "1.0.0"


class SkillsPolicyErrorCode(StrEnum):
    """Stable, namespaced policy-decision/v2 error code contract."""

    NONE = "policy.none"
    DISABLED = "policy.disabled"
    KILL_SWITCH = "policy.kill_switch"
    UNAPPROVED = "policy.unapproved"
    MAPPING_MISMATCH = "policy.mapping_mismatch"
    TENANT_DENIED = "policy.tenant_denied"
    WORKLOAD_UNAVAILABLE = "policy.workload_unavailable"
    TRANSPORT_UNSAFE = "policy.transport_unsafe"
    AUDIT_FAILURE = "policy.audit_failure"
    MALFORMED = "policy.malformed"
    WORKLOAD_UNAUTHORIZED = "policy.workload_unauthorized"
    UNKNOWN_ACTION = "policy.unknown_action"
    UNMAPPED_RESOURCE = "policy.unmapped_resource"
    BINDING_MISMATCH = "policy.binding_mismatch"
    STALE = "policy.stale"
    UNAVAILABLE = "policy.unavailable"
    DENIED = "policy.denied"


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
    error_code: SkillsPolicyErrorCode
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
