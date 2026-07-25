from app.core import rbac, abac, rules
from app.models.request import PolicyRequest
from app.models.decision import PolicyDecision
from app.services.cache import PolicyCache


class PolicyEngine:

    def __init__(self, cache: PolicyCache):
        self.cache = cache

    # ----------------------------
    # CORE EVALUATION
    # ----------------------------
    def _evaluate_core(self, req: PolicyRequest) -> PolicyDecision:

        ok, reason = rbac.evaluate_rbac(req.roles, req.action)
        if not ok:
            return PolicyDecision(
                allowed=False,
                reason=reason,
                policy_source="RBAC"
            )

        ok, reason = abac.evaluate_abac(req.context, req.roles)
        if not ok:
            return PolicyDecision(
                allowed=False,
                reason=reason,
                policy_source="ABAC"
            )

        ok, reason = rules.evaluate_rules(req.action, req.resource)
        if not ok:
            return PolicyDecision(
                allowed=False,
                reason=reason,
                policy_source="RULES"
            )

        return PolicyDecision(
            allowed=True,
            reason="access granted",
            policy_source="ALL_PASSED"
        )

    # ----------------------------
    # PUBLIC ENTRY (CACHE-FIRST)
    # ----------------------------
    def evaluate(self, req: PolicyRequest) -> PolicyDecision:

        key = self.cache.build_key(
            req.user_id,
            req.action,
            req.resource,
            req.context
        )

        # 1. CACHE HIT (sub-ms path)
        cached = self.cache.get(key)
        if cached:
            # `cached` is a previously stored decision.dict(), which always
            # already has a policy_source key (RBAC/ABAC/RULES/ALL_PASSED) --
            # spreading it alongside an explicit policy_source= kwarg raises
            # "got multiple values for keyword argument 'policy_source'".
            # Override it in the dict instead of passing it twice.
            return PolicyDecision(**{**cached, "policy_source": "CACHE"})

        # 2. COMPUTE DECISION
        decision = self._evaluate_core(req)

        # 3. STORE IN CACHE
        self.cache.set(key, decision.dict(), ttl=300)

        return decision