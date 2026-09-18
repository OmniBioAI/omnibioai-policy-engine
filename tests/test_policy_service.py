"""
Tests for evaluate_policy() — patches the module-level engine so no Redis needed.

Developer: Manish Kumar <manish@omnibioai.org>
"""
import pytest
from unittest.mock import MagicMock, patch


def make_engine_with_mock_redis():
    """Return a real PolicyEngine wired to a mock Redis."""
    mock_redis = MagicMock()
    mock_redis.get.return_value = None  # cache always misses

    with patch("app.services.cache.redis") as mr:
        mr.from_url.return_value = mock_redis
        from app.services.cache import PolicyCache
        cache = PolicyCache(redis_url="redis://localhost")
        cache.redis = mock_redis  # override to ensure mock

    from app.core.engine import PolicyEngine
    return PolicyEngine(cache=cache), mock_redis


@pytest.fixture
def patched_engine():
    engine, mock_redis = make_engine_with_mock_redis()
    with patch("app.services.policy_service.engine", engine):
        yield engine, mock_redis


def test_evaluate_policy_allow(patched_engine):
    """evaluate_policy allows a request that passes every policy stage."""
    from app.services.policy_service import evaluate_policy

    result = evaluate_policy({
        "user_id": "u1",
        "email": "u1@test.com",
        "roles": ["researcher"],
        "permissions": [],
        "action": "tes.submit",
        "resource": "job_queue",
        "context": {},
    })

    assert result.allowed is True


def test_evaluate_policy_deny_rbac(patched_engine):
    """evaluate_policy denies a request missing its required role, reporting policy_source RBAC."""
    from app.services.policy_service import evaluate_policy

    result = evaluate_policy({
        "user_id": "u2",
        "email": "u2@test.com",
        "roles": [],
        "permissions": [],
        "action": "tes.submit",
        "resource": "job_queue",
        "context": {},
    })

    assert result.allowed is False
    assert result.policy_source == "RBAC"


def test_evaluate_policy_deny_abac(patched_engine):
    """evaluate_policy denies a GPU-required request from a caller without the gpu_user role,
    reporting policy_source ABAC.
    """
    from app.services.policy_service import evaluate_policy

    result = evaluate_policy({
        "user_id": "u3",
        "email": "u3@test.com",
        "roles": ["researcher"],
        "permissions": [],
        "action": "tes.submit",
        "resource": "job_queue",
        "context": {"gpu_required": True},
    })

    assert result.allowed is False
    assert result.policy_source == "ABAC"


def test_evaluate_policy_deny_rules(patched_engine):
    """evaluate_policy denies deleting a protected human-genome dataset, reporting policy_source
    RULES.
    """
    from app.services.policy_service import evaluate_policy

    result = evaluate_policy({
        "user_id": "u4",
        "email": "u4@test.com",
        "roles": ["data_scientist"],
        "permissions": [],
        "action": "dataset.delete",
        "resource": "human_genome_v1",
        "context": {},
    })

    assert result.allowed is False
    assert result.policy_source == "RULES"
