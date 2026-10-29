"""
OmniBioAI app.services.cache.

Purpose:
    Defines PolicyCache with build_key, get, set and invalidate_user methods for app.services.cache.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

import hashlib
import json

import redis


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
        org_id: str | None = None,
        permissions: list | None = None,
        resource_scope: str = "global",
    ) -> str:
        # PR12: org_id/permissions now affect the decision (tenancy.py,
        # permissions.py), so they must be part of the key -- otherwise a
        # cache hit for one org/permission-set could be served to another.
        raw = (
            f"{user_id}:{action}:{resource}:{json.dumps(context, sort_keys=True)}:"
            f"{org_id}:{json.dumps(sorted(permissions or []))}:{resource_scope}"
        )
        digest = hashlib.sha256(raw.encode()).hexdigest()
        return f"policy:{digest}"

    # ----------------------------
    # get cached decision
    # ----------------------------
    def get(self, key: str) -> dict | None:
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
        for key in self.redis.scan_iter("policy:*"):
            if user_id in key:
                self.redis.delete(key)

    @staticmethod
    def authorization_epoch_key(tenant_id: str, principal_id: str) -> str:
        identity = f"{tenant_id}\0{principal_id}".encode()
        return "skills-policy:authz-epoch:" + hashlib.sha256(identity).hexdigest()

    def get_authorization_epoch(self, tenant_id: str, principal_id: str) -> int | None:
        value = self.redis.get(self.authorization_epoch_key(tenant_id, principal_id))
        if value is None:
            return None
        return int(value)

    def build_skills_key(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        action: str,
        resource: str,
        permission_set_digest: str,
        authorization_epoch: int,
        policy_version: str,
        activation_nonce: str,
    ) -> str:
        raw = _canonical_cache_value(
            {
                "tenant_id": tenant_id,
                "principal_id": principal_id,
                "action": action,
                "resource": resource,
                "permission_set_digest": permission_set_digest,
                "authorization_epoch": authorization_epoch,
                "policy_version": policy_version,
                "activation_nonce": activation_nonce,
            }
        )
        return (
            "skills-policy:decision:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()
        )


def _canonical_cache_value(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))
