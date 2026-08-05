import pytest
from app.core.permissions import evaluate_permission, required_permission


# ---------------------------------------------------------------------------
# Backward compatibility: no permissions supplied -> no-op (PR12 requirement
# that existing role-only callers see zero behavior change)
# ---------------------------------------------------------------------------

def test_no_permissions_supplied_is_noop():
    allowed, reason = evaluate_permission(["researcher"], [], "tes.submit", "job")
    assert allowed is True
    assert "no permissions supplied" in reason


def test_admin_role_always_overrides_even_with_permissions_supplied():
    allowed, reason = evaluate_permission(["admin"], ["something.else"], "tes.submit", "job")
    assert allowed is True
    assert reason == "admin override"


# ---------------------------------------------------------------------------
# required_permission mapping
# ---------------------------------------------------------------------------

def test_required_permission_for_tes_prefix():
    assert required_permission("tes.submit", "job") == "workflow.execute"


def test_required_permission_for_dataset_read():
    assert required_permission("dataset.read", "human_genome") == "dataset.read"


def test_required_permission_for_model_registry_delete():
    assert required_permission("delete", "model_registry") == "workflow.manage"


def test_required_permission_none_for_unrelated_action():
    assert required_permission("profile.read", "profile") is None


# ---------------------------------------------------------------------------
# Allow: permission present
# ---------------------------------------------------------------------------

def test_scientist_with_workflow_execute_allowed_tes_submit():
    allowed, reason = evaluate_permission(
        [], ["workflow.execute", "dataset.read"], "tes.submit", "job"
    )
    assert allowed is True
    assert reason == "permission granted"


def test_viewer_with_dataset_read_allowed_dataset_read():
    allowed, reason = evaluate_permission([], ["dataset.read"], "dataset.read", "human_genome")
    assert allowed is True


# ---------------------------------------------------------------------------
# Deny: permissions supplied but missing the required one
# ---------------------------------------------------------------------------

def test_viewer_without_workflow_execute_denied_tes_submit():
    allowed, reason = evaluate_permission([], ["dataset.read"], "tes.submit", "job")
    assert allowed is False
    assert "workflow.execute" in reason


def test_scientist_without_workflow_manage_denied_model_registry_delete():
    allowed, reason = evaluate_permission(
        [], ["workflow.execute", "dataset.read"], "delete", "model_registry"
    )
    assert allowed is False
    assert "workflow.manage" in reason


def test_unrelated_action_allowed_even_with_permissions_supplied():
    allowed, reason = evaluate_permission([], ["dataset.read"], "profile.read", "profile")
    assert allowed is True
    assert reason == "no permission required"
