"""Unit tests for app/core/rbac.py::evaluate_rbac: admin always overrides, tes.*
actions require the researcher role, dataset actions require data_scientist,
viewer is denied dataset access, and an unrelated action or an empty role list
is allowed since RBAC does not gate it.

Developer: Manish Kumar <manish@omnibioai.org>
"""
import pytest
from app.core.rbac import evaluate_rbac


# ---------------------------------------------------------------------------
# Admin override
# ---------------------------------------------------------------------------

def test_admin_gets_universal_allow():
    """The admin role allows any action with reason "admin override"."""
    allowed, reason = evaluate_rbac(["admin"], "tes.submit")
    assert allowed is True
    assert reason == "admin override"


def test_admin_with_other_roles_still_overrides():
    """Admin still overrides even when combined with other roles."""
    allowed, reason = evaluate_rbac(["admin", "viewer"], "dataset.delete")
    assert allowed is True
    assert reason == "admin override"


# ---------------------------------------------------------------------------
# tes.* action — requires "researcher"
# ---------------------------------------------------------------------------

def test_researcher_can_submit_tes_job():
    """The researcher role passes RBAC for a tes.submit action."""
    allowed, reason = evaluate_rbac(["researcher"], "tes.submit")
    assert allowed is True
    assert reason == "rbac passed"


def test_missing_researcher_denied_tes_action():
    """Missing the researcher role denies a tes.* action with a reason naming it."""
    allowed, reason = evaluate_rbac(["viewer"], "tes.submit")
    assert allowed is False
    assert "researcher" in reason


def test_data_scientist_cannot_access_tes():
    """The data_scientist role alone is denied a tes.* action, with a reason naming researcher."""
    allowed, reason = evaluate_rbac(["data_scientist"], "tes.run")
    assert allowed is False
    assert "researcher" in reason


# ---------------------------------------------------------------------------
# dataset.* action — requires "data_scientist"
# ---------------------------------------------------------------------------

def test_data_scientist_can_access_dataset():
    """The data_scientist role passes RBAC for a dataset action."""
    allowed, reason = evaluate_rbac(["data_scientist"], "dataset.read")
    assert allowed is True
    assert reason == "rbac passed"


def test_missing_data_scientist_denied_dataset_action():
    """Missing the data_scientist role denies a dataset action with a reason naming it."""
    allowed, reason = evaluate_rbac(["researcher"], "dataset.write")
    assert allowed is False
    assert "data_scientist" in reason


def test_viewer_denied_dataset_action():
    """The viewer role alone is denied a dataset action."""
    allowed, reason = evaluate_rbac([], "dataset.delete")
    assert allowed is False


# ---------------------------------------------------------------------------
# Unrelated actions — default allow
# ---------------------------------------------------------------------------

def test_unrelated_action_allowed_for_any_role():
    """An action RBAC does not gate is allowed for any role, with reason "rbac passed"."""
    allowed, reason = evaluate_rbac(["viewer"], "profile.read")
    assert allowed is True
    assert reason == "rbac passed"


def test_empty_roles_allowed_for_unrelated_action():
    """An action RBAC does not gate is allowed even with no roles at all."""
    allowed, reason = evaluate_rbac([], "ping")
    assert allowed is True
