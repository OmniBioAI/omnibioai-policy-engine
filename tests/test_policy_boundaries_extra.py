"""Additional deterministic boundary tests for the policy engine.

These tests invoke pure policy functions and route/helper callables directly.
They intentionally avoid the environment's hanging FastAPI TestClient path.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from app import main as main_module
from app.api import routes_policy
from app.core import abac, permissions, rules, tenancy
from app.main import custom_swagger_ui, health, swagger_static
from app.models.request import PolicyRequest
from app.services import policy_service


@pytest.mark.parametrize(
    ("context", "roles", "allowed", "reason"),
    [
        ({}, [], True, "abac passed"),
        ({"gpu_required": True}, [], False, "GPU access denied"),
        ({"gpu_required": True}, ["gpu_user"], True, "abac passed"),
        ({"node": "hpc"}, [], False, "HPC access denied"),
        ({"node": "hpc"}, ["hpc_user"], True, "abac passed"),
        ({"gpu_required": True, "node": "hpc"}, ["gpu_user"], False, "HPC access denied"),
    ],
)
def test_abac_boundary_combinations(context, roles, allowed, reason):
    assert abac.evaluate_abac(context, roles) == (allowed, reason)


@pytest.mark.parametrize(
    ("action", "resource", "expected"),
    [
        ("tes.submit", "job", "workflow.execute"),
        ("tes.submit.extra", "job", "workflow.execute"),
        ("dataset.read", "dataset", "dataset.read"),
        ("delete", "model_registry", "workflow.manage"),
        ("read", "model_registry", None),
    ],
)
def test_permission_resolution_covers_exact_prefix_resource_and_unknown_actions(
    action, resource, expected
):
    assert permissions.required_permission(action, resource) == expected


def test_permission_gate_admin_override_and_missing_permission_are_distinct():
    assert permissions.evaluate_permission(["admin"], [], "unknown", "resource") == (
        True,
        "admin override",
    )
    assert permissions.evaluate_permission([], ["dataset.read"], "delete", "model_registry") == (
        False,
        "missing permission: workflow.manage",
    )


def test_permission_gate_unknown_action_is_currently_permissive():
    # This records the current fail-open behavior without disguising it as a
    # secure contract; the pre-existing security-boundary test tracks the
    # desired fail-closed behavior separately as an expected failure.
    assert permissions.evaluate_permission([], ["unrelated"], "unknown", "resource") == (
        True,
        "no permission required",
    )


@pytest.mark.parametrize(
    ("org_id", "resource_org_id", "expected"),
    [
        ("org-a", None, (True, "no tenancy scoping required")),
        ("org-a", "org-a", (True, "tenancy check passed")),
        ("org-a", "org-b", (False, "cross-tenant access denied")),
        (None, "org-a", (False, "missing organization context")),
        (7, "7", (True, "tenancy check passed")),
    ],
)
def test_tenancy_boundary_values(org_id, resource_org_id, expected):
    assert tenancy.evaluate_tenancy(org_id, {"resource_org_id": resource_org_id}) == expected


def test_rules_protect_both_human_genome_and_model_registry_resources():
    assert rules.evaluate_rules("dataset.delete", "human_genome_v1") == (
        False,
        "protected dataset cannot be deleted",
    )
    assert rules.evaluate_rules("delete", "model_registry") == (
        False,
        "model registry is immutable",
    )
    assert rules.evaluate_rules("dataset.read", "human_genome_v1") == (True, "rules passed")


def test_policy_request_defaults_are_independent_and_validate_required_fields():
    first = PolicyRequest(user_id="u1", action="read", resource="r")
    second = PolicyRequest(user_id="u2", action="read", resource="r")
    first.roles.append("viewer")
    first.context["resource_org_id"] = "org-a"

    assert second.roles == []
    assert second.context == {}
    with pytest.raises(ValidationError):
        PolicyRequest(user_id="u1", action="read")


def test_policy_service_rejects_invalid_request_before_calling_engine(monkeypatch):
    engine = MagicMock()
    monkeypatch.setattr(policy_service, "engine", engine)

    with pytest.raises(ValidationError):
        policy_service.evaluate_policy({"user_id": "u1", "action": "read"})
    engine.evaluate.assert_not_called()


def test_policy_route_delegates_without_testclient(monkeypatch):
    evaluate = MagicMock(return_value={"allowed": True})
    monkeypatch.setattr(routes_policy, "evaluate_policy", evaluate)
    payload = {"user_id": "u1", "action": "read", "resource": "dataset"}

    assert routes_policy.evaluate(payload) == {"allowed": True}
    evaluate.assert_called_once_with(payload)


def test_health_and_swagger_helpers_are_deterministic():
    assert asyncio.run(health()) == {"status": "ok"}
    missing = asyncio.run(swagger_static("does-not-exist.js"))
    assert missing.status_code == 404
    css = asyncio.run(swagger_static("swagger-ui.css"))
    assert css.status_code == 200


def test_custom_swagger_ui_contains_openapi_metadata():
    response = asyncio.run(custom_swagger_ui())
    body = response.body.decode()
    assert response.status_code == 200
    assert "OmniBioAI Policy Engine" in body
    assert '"openapi"' in body


def test_invalidation_subscriber_restarts_after_pubsub_stream_closes(monkeypatch):
    class PubSub:
        def __init__(self):
            self.listen_calls = 0

        async def subscribe(self, channel):
            assert channel == "policy:invalidate"

        async def listen(self):
            self.listen_calls += 1
            if self.listen_calls == 1:
                return
            raise asyncio.CancelledError
            yield  # Keep this an async generator for the first empty stream.

    class Client:
        def __init__(self):
            self.pubsub_instance = PubSub()

        def pubsub(self):
            return self.pubsub_instance

    client = Client()
    monkeypatch.setattr(main_module.aioredis, "from_url", lambda *args, **kwargs: client)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(main_module._invalidation_subscriber())

    assert client.pubsub_instance.listen_calls == 2
