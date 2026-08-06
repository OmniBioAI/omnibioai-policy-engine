import json
import hashlib
import redis
from typing import Optional, Any


class PolicyCache:
    def __init__(self, redis_url: str):
        self.redis = redis.from_url(redis_url, decode_responses=True)

    # ----------------------------
    # deterministic cache key
    # ----------------------------
    def build_key(
        self,
        user_id: str,
        action: str,
        resource: str,
        context: dict,
        org_id: Optional[str] = None,
        permissions: Optional[list] = None,
    ) -> str:
        # PR12: org_id/permissions now affect the decision (tenancy.py,
        # permissions.py), so they must be part of the key -- otherwise a
        # cache hit for one org/permission-set could be served to another.
        raw = (
            f"{user_id}:{action}:{resource}:{json.dumps(context, sort_keys=True)}:"
            f"{org_id}:{json.dumps(sorted(permissions or []))}"
        )
        digest = hashlib.sha256(raw.encode()).hexdigest()
        return f"policy:{digest}"

    # ----------------------------
    # get cached decision
    # ----------------------------
    def get(self, key: str) -> Optional[dict]:
        val = self.redis.get(key)
        if val:
            return json.loads(val)
        return None

    # ----------------------------
    # set cache with TTL
    # ----------------------------
    def set(self, key: str, value: dict, ttl: int = 300):
        self.redis.setex(key, ttl, json.dumps(value))

    # ----------------------------
    # invalidation (important for IAM sync)
    # ----------------------------
    def invalidate_user(self, user_id: str):
        # simple pattern-based invalidation (can be improved later with redis SCAN)
        for key in self.redis.scan_iter(f"policy:*"):
            if user_id in key:
                self.redis.delete(key)