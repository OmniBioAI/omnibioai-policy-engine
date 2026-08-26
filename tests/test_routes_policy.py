"""
Route tests — patch evaluate_policy at the routes module level so no Redis is hit.
"""
import pytest
from unittest.mock import patch, MagicMock
from fastapi import FastAPI

from app.models.decision import PolicyDecision


def _make_decision(allowed: bool, reason: str, source: str = "TEST") -> PolicyDecision:
    return PolicyDecision(allowed=allowed, reason=reason, policy_source=source)


@pytest.fixture
def client():
    with patch("app.api.routes_policy.evaluate_policy") as mock_eval:
        from app.api.routes_policy import router
        app = FastAPI()
        app.include_router(router, prefix="/policy")
        from app.api.routes_policy import evaluate
        yield evaluate, mock_eval


ALLOW_PAYLOAD = {
    "user_id": "u1",
    "email": "u1@test.com",
    "roles": ["researcher"],
    "permissions": [],
    "action": "tes.submit",
    "resource": "job_queue",
    "context": {},
}

DENY_PAYLOAD = {**ALLOW_PAYLOAD, "roles": []}


def test_evaluate_endpoint_returns_allow(client):
    evaluate, mock_eval = client
    mock_eval.return_value = _make_decision(True, "access granted", "ALL_PASSED")

    response = evaluate(ALLOW_PAYLOAD)

    assert response.allowed is True
    mock_eval.assert_called_once()


def test_evaluate_endpoint_returns_deny(client):
    evaluate, mock_eval = client
    mock_eval.return_value = _make_decision(False, "missing role: researcher", "RBAC")

    response = evaluate(DENY_PAYLOAD)

    assert response.allowed is False
    assert "researcher" in response.reason
    assert response.policy_source == "RBAC"


def test_evaluate_endpoint_abac_deny(client):
    evaluate, mock_eval = client
    mock_eval.return_value = _make_decision(False, "GPU access denied", "ABAC")

    payload = {**ALLOW_PAYLOAD, "context": {"gpu_required": True}}
    response = evaluate(payload)

    assert response.policy_source == "ABAC"


def test_evaluate_endpoint_rules_deny(client):
    evaluate, mock_eval = client
    mock_eval.return_value = _make_decision(False, "protected dataset cannot be deleted", "RULES")

    response = evaluate({**ALLOW_PAYLOAD, "action": "dataset.delete", "resource": "human_genome_v1"})

    assert response.allowed is False
    assert response.policy_source == "RULES"


def test_evaluate_endpoint_admin_override(client):
    evaluate, mock_eval = client
    mock_eval.return_value = _make_decision(True, "admin override", "RBAC")

    response = evaluate({**DENY_PAYLOAD, "roles": ["admin"]})

    assert response.allowed is True


def test_evaluate_passes_full_request_to_service(client):
    evaluate, mock_eval = client
    mock_eval.return_value = _make_decision(True, "ok", "ALL_PASSED")

    evaluate(ALLOW_PAYLOAD)

    call_args = mock_eval.call_args[0][0]
    assert call_args["user_id"] == "u1"
    assert call_args["action"] == "tes.submit"
