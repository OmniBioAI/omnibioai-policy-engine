import os

from app.core.engine import PolicyEngine
from app.models.request import PolicyRequest
from app.services.cache import PolicyCache

cache = PolicyCache(
    redis_url=os.getenv("REDIS_URL", "redis://localhost:6379")
)

engine = PolicyEngine(cache)


def evaluate_policy(data: dict):
    req = PolicyRequest(**data)
    return engine.evaluate(req)