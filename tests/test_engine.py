import json
import pytest
from unittest.mock import MagicMock
from app.core.engine import PolicyEngine
from app.models.request import PolicyRequest
from app.models.decision import PolicyDecision


def make_engine(mock_redis=None):
    if mock_redis is None:
        mock_redis = MagicMock()
        mock_redis.get.return_value = None

    from app.services.cache import PolicyCache
    from unittest.mock import patch
    with patch("app.services.cache.redis") as mock_redis_module:
        mock_redis_module.from_url.return_value = mock_redis
        cache = PolicyCache(redis_url="redis://localhost")
        cache.redis = mock_redis
    return PolicyEngine(cache=cache), mock_redis


def basic_request(**kwargs):
    defaults = {
        "user_id": "u1",
        "email": "u1@test.com",
        "roles": ["researcher"],
        "permissions": [],
        "action": "tes.submit",
        "resource": "job_queue",
        "context": {},
    }
    defaults.update(kwargs)
    return PolicyRequest(**defaults)


# ---------------------------------------------------------------------------
# _evaluate_core — RBAC denial
# ---------------------------------------------------------------------------

def test_rbac_deny_stops_evaluation():
    engine, _ = make_engine()
    req = basic_request(roles=[], action="tes.submit")  # no researcher role

    decision = engine._evaluate_core(req)

    assert decision.allowed is False
    assert decision.policy_source == "RBAC"
    assert "researcher" in decision.reason


# ---------------------------------------------------------------------------
# _evaluate_core — ABAC denial
# ---------------------------------------------------------------------------

def test_abac_deny_gpu_access():
    engine, _ = make_engine()
    req = basic_request(
        roles=["researcher"],
        context={"gpu_required": True},  # no gpu_user role
    )

    decision = engine._evaluate_core(req)

    assert decision.allowed is False
    assert decision.policy_source == "ABAC"
    assert "GPU" in decision.reason


def test_abac_deny_hpc_access():
    engine, _ = make_engine()
    req = basic_request(
        roles=["researcher"],
        context={"node": "hpc"},  # no hpc_user role
    )

    decision = engine._evaluate_core(req)

    assert decision.allowed is False
    assert decision.policy_source == "ABAC"
    assert "HPC" in decision.reason


# ---------------------------------------------------------------------------
# _evaluate_core — Rules denial
# ---------------------------------------------------------------------------

def test_rules_deny_protected_dataset_delete():
    engine, _ = make_engine()
    req = basic_request(
        roles=["data_scientist"],
        action="dataset.delete",
        resource="human_genome_v1",
    )

    decision = engine._evaluate_core(req)

    assert decision.allowed is False
    assert decision.policy_source == "RULES"


def test_rules_deny_model_registry_delete():
    engine, _ = make_engine()
    req = basic_request(
        roles=["admin"],
        action="delete",
        resource="model_registry",
    )
    # admin overrides RBAC, ABAC passes, but RULES should deny
    decision = engine._evaluate_core(req)

    assert decision.allowed is False
    assert decision.policy_source == "RULES"


# ---------------------------------------------------------------------------
# _evaluate_core — full allow
# ---------------------------------------------------------------------------

def test_all_checks_pass_returns_allowed():
    engine, _ = make_engine()
    req = basic_request()

    decision = engine._evaluate_core(req)

    assert decision.allowed is True
    assert decision.policy_source == "ALL_PASSED"
    assert decision.reason == "access granted"


# ---------------------------------------------------------------------------
# evaluate — cache-first path
# ---------------------------------------------------------------------------

def test_evaluate_returns_cached_decision():
    mock_redis = MagicMock()
    # A real cached entry is always a previous decision.dict(), which always
    # includes policy_source (RBAC/ABAC/RULES/ALL_PASSED) -- a payload
    # missing that key (as this test used to use) can't reproduce the
    # duplicate-kwarg bug in evaluate()'s cache-hit branch. See
    # test_evaluate_cache_hit_after_miss_does_not_raise for the regression
    # test that exercises a real store->retrieve round trip instead.
    mock_redis.get.return_value = json.dumps(
        {"allowed": True, "reason": "cached", "context": {}, "policy_source": "ALL_PASSED"}
    )
    engine, _ = make_engine(mock_redis)

    req = basic_request()
    decision = engine.evaluate(req)

    assert decision.allowed is True
    assert decision.policy_source == "CACHE"
    mock_redis.setex.assert_not_called()


class _FakeRedis:
    """Minimal redis stand-in: get/setex backed by an in-memory dict, so a
    real store -> retrieve round trip happens instead of a static mocked
    payload. This is what actually reproduces the PolicyDecision
    duplicate-kwarg bug: a stored decision.dict() always carries its own
    policy_source (e.g. "ALL_PASSED"), which a hand-written mock payload can
    accidentally omit and mask (as test_evaluate_returns_cached_decision
    used to, before it was corrected above)."""

    def __init__(self):
        self.store: dict = {}

    def get(self, key):
        return self.store.get(key)

    def setex(self, key, ttl, value):
        self.store[key] = value


def test_evaluate_cache_hit_after_miss_does_not_raise():
    """Regression test for PolicyDecision(**cached, policy_source="CACHE")
    raising TypeError: got multiple values for keyword argument
    'policy_source'. `cached` is a previously stored decision.dict(), which
    already has a policy_source key from the original evaluation -- the
    first call (real cache miss) computes and stores a real decision, and
    the second call (real cache hit against that same stored value) must
    succeed instead of raising, returning policy_source="CACHE"."""
    fake_redis = _FakeRedis()
    engine, _ = make_engine(fake_redis)
    req = basic_request()

    first = engine.evaluate(req)
    assert first.allowed is True
    assert first.policy_source == "ALL_PASSED"

    second = engine.evaluate(req)  # must not raise

    assert second.allowed == first.allowed
    assert second.reason == first.reason
    assert second.policy_source == "CACHE"


def test_evaluate_cache_miss_computes_and_stores():
    mock_redis = MagicMock()
    mock_redis.get.return_value = None
    engine, _ = make_engine(mock_redis)

    req = basic_request()
    decision = engine.evaluate(req)

    assert decision.allowed is True
    mock_redis.setex.assert_called_once()


def test_evaluate_cache_miss_rbac_deny_stores_denial():
    mock_redis = MagicMock()
    mock_redis.get.return_value = None
    engine, _ = make_engine(mock_redis)

    req = basic_request(roles=[], action="tes.submit")
    decision = engine.evaluate(req)

    assert decision.allowed is False
    mock_redis.setex.assert_called_once()


# ---------------------------------------------------------------------------
# abac / rules helpers imported via engine
# ---------------------------------------------------------------------------

def test_abac_gpu_with_gpu_user_role_passes():
    engine, _ = make_engine()
    req = basic_request(
        roles=["researcher", "gpu_user"],
        context={"gpu_required": True},
    )
    decision = engine._evaluate_core(req)
    assert decision.allowed is True


def test_abac_hpc_with_hpc_user_role_passes():
    engine, _ = make_engine()
    req = basic_request(
        roles=["researcher", "hpc_user"],
        context={"node": "hpc"},
    )
    decision = engine._evaluate_core(req)
    assert decision.allowed is True
