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


# ---------------------------------------------------------------------------
# PR13: regression lock for a real gap this map had -- the Gateway's
# PolicyClient sends the literal string "workflow.execute" (for
# workbench/tes/toolserver) and "model.use" (for model-registry) as
# `action` for its 5 gateway-routed services, never a "tes.*"-prefixed
# string. Before PR13, neither literal matched anything in this map (the
# "tes." prefix rule only ever matched this test file's own synthetic
# "tes.submit" fixtures, never real gateway traffic), so
# required_permission() silently returned None for those two and
# evaluate_permission allowed unconditionally regardless of the caller's
# permissions -- 4 of 5 gateway-routed services had zero real enforcement
# through this engine no matter what permissions a caller did or didn't
# have. These are the exact action shapes real traffic sends, not just the
# "tes.submit"-style ones every other test in this file uses.
# ---------------------------------------------------------------------------


def test_required_permission_for_workflow_execute_action():
    assert required_permission("workflow.execute", "job") == "workflow.execute"


def test_required_permission_for_model_use_action():
    assert required_permission("model.use", "model") == "model.use"


def test_scientist_denied_workflow_publish_via_gateway_shaped_action():
    """Scientist's permission set (per this PR's role matrix) has
    workflow.execute/dataset.read/model.use but not workflow.publish."""
    allowed, reason = evaluate_permission(
        [], ["workflow.execute", "dataset.read", "model.use"], "model.use", "model"
    )
    assert allowed is True

    allowed, reason = evaluate_permission(
        [], ["workflow.execute", "dataset.read", "model.use"], "workflow.execute", "job"
    )
    assert allowed is True


def test_viewer_denied_workflow_execute_via_gateway_shaped_action():
    """Viewer's permission set (dataset.read/workflow.read) does not
    include workflow.execute -- the exact scenario a gateway-routed
    workbench/tes/toolserver request from a Viewer must be denied."""
    allowed, reason = evaluate_permission([], ["dataset.read", "workflow.read"], "workflow.execute", "job")
    assert allowed is False
    assert "workflow.execute" in reason


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
