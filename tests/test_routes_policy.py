"""
Route tests — patch evaluate_policy at the routes module level so no Redis is hit.

Developer: Manish Kumar <manish@omnibioai.org>
"""
import pytest
from unittest.mock import patch, MagicMock
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.models.decision import PolicyDecision


def _make_decision(allowed: bool, reason: str, source: str = "TEST") -> PolicyDecision:
    """Build a PolicyDecision with the given allow/reason/source."""
    return PolicyDecision(allowed=allowed, reason=reason, policy_source=source)


@pytest.fixture
def client():
    """Provide a TestClient for the policy router with evaluate_policy mocked, together with that
    mock.
    """
    with patch("app.api.routes_policy.evaluate_policy") as mock_eval:
        from app.api.routes_policy import router
        app = FastAPI()
        app.include_router(router, prefix="/policy")
        tc = TestClient(app)
        yield tc, mock_eval


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
    """POST /policy/evaluate returns 200 with allow true when evaluate_policy allows."""
    tc, mock_eval = client
    mock_eval.return_value = _make_decision(True, "access granted", "ALL_PASSED")

    response = tc.post("/policy/evaluate", json=ALLOW_PAYLOAD)

    assert response.status_code == 200
    data = response.json()
    assert data["allowed"] is True
    mock_eval.assert_called_once()


def test_evaluate_endpoint_returns_deny(client):
    """POST /policy/evaluate returns the RBAC denial's reason and policy_source unchanged."""
    tc, mock_eval = client
    mock_eval.return_value = _make_decision(False, "missing role: researcher", "RBAC")

    response = tc.post("/policy/evaluate", json=DENY_PAYLOAD)

    assert response.status_code == 200
    data = response.json()
    assert data["allowed"] is False
    assert "researcher" in data["reason"]
    assert data["policy_source"] == "RBAC"


def test_evaluate_endpoint_abac_deny(client):
    """POST /policy/evaluate returns policy_source ABAC for a GPU-required request that
    evaluate_policy denies.
    """
    tc, mock_eval = client
    mock_eval.return_value = _make_decision(False, "GPU access denied", "ABAC")

    payload = {**ALLOW_PAYLOAD, "context": {"gpu_required": True}}
    response = tc.post("/policy/evaluate", json=payload)

    assert response.status_code == 200
    assert response.json()["policy_source"] == "ABAC"


def test_evaluate_endpoint_rules_deny(client):
    """POST /policy/evaluate returns allow false and policy_source RULES for a protected-dataset
    delete that evaluate_policy denies.
    """
    tc, mock_eval = client
    mock_eval.return_value = _make_decision(False, "protected dataset cannot be deleted", "RULES")

    response = tc.post("/policy/evaluate", json={**ALLOW_PAYLOAD, "action": "dataset.delete", "resource": "human_genome_v1"})

    assert response.status_code == 200
    assert response.json()["allowed"] is False
    assert response.json()["policy_source"] == "RULES"


def test_evaluate_endpoint_admin_override(client):
    """POST /policy/evaluate returns allow true for an admin request even though the underlying
    payload would otherwise be denied.
    """
    tc, mock_eval = client
    mock_eval.return_value = _make_decision(True, "admin override", "RBAC")

    response = tc.post("/policy/evaluate", json={**DENY_PAYLOAD, "roles": ["admin"]})

    assert response.status_code == 200
    assert response.json()["allowed"] is True


def test_evaluate_passes_full_request_to_service(client):
    """The route passes the full request payload, including user_id and action, through to
    evaluate_policy.
    """
    tc, mock_eval = client
    mock_eval.return_value = _make_decision(True, "ok", "ALL_PASSED")

    tc.post("/policy/evaluate", json=ALLOW_PAYLOAD)

    call_args = mock_eval.call_args[0][0]
    assert call_args["user_id"] == "u1"
    assert call_args["action"] == "tes.submit"
