"""
OmniBioAI app.models.decision.

Purpose:
    Defines the PolicyDecision data model for app.models.decision.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

from typing import Any

from pydantic import BaseModel


class PolicyDecision(BaseModel):
    allowed: bool
    reason: str
    policy_source: str  # RBAC / ABAC / RULE_ENGINE
    context: dict[str, Any] = {}