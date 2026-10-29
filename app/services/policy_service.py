"""
OmniBioAI app.services.policy_service.

Purpose:
    Defines evaluate_policy for app.services.policy_service.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

import os

from app.core.engine import PolicyEngine
from app.core.skills_policy import SkillsPolicyService
from app.models.request import PolicyRequest
from app.services.cache import PolicyCache

cache = PolicyCache(
    redis_url=os.getenv("REDIS_URL", "redis://localhost:6379")
)

engine = PolicyEngine(cache)
skills_engine = SkillsPolicyService(cache)


def evaluate_policy(data: dict):
    req = PolicyRequest(**data)
    return engine.evaluate(req)
