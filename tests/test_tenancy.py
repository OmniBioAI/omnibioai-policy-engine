"""Unit tests for app/core/tenancy.py::evaluate_tenancy: a resource with no
organization context is unscoped and allowed, a matching organization passes, a
mismatched one is denied, a caller with no organization is denied against a
scoped resource, and organization ids are compared as strings so an int and a
string of the same value match.

Developer: Manish Kumar <manish@omnibioai.org>
"""
from app.core.tenancy import evaluate_tenancy


def test_no_resource_org_id_is_noop():
    """A resource with no resource_org_id is allowed with reason "no tenancy scoping required"."""
    allowed, reason = evaluate_tenancy("org-1", {})
    assert allowed is True
    assert reason == "no tenancy scoping required"


def test_matching_org_allowed():
    """A resource whose organization matches the caller's is allowed with reason "tenancy check
    passed".
    """
    allowed, reason = evaluate_tenancy("org-1", {"resource_org_id": "org-1"})
    assert allowed is True
    assert reason == "tenancy check passed"


def test_mismatched_org_denied():
    """A resource belonging to a different organization is denied with reason "cross-tenant access
    denied".
    """
    allowed, reason = evaluate_tenancy("org-1", {"resource_org_id": "org-2"})
    assert allowed is False
    assert reason == "cross-tenant access denied"


def test_missing_requester_org_denied_when_resource_scoped():
    """A caller with no organization is denied against an organization-scoped resource, with reason
    "missing organization context".
    """
    allowed, reason = evaluate_tenancy(None, {"resource_org_id": "org-2"})
    assert allowed is False
    assert reason == "missing organization context"


def test_org_id_compared_as_string():
    """An int-typed caller organization id matches a string-typed resource organization id of the
    same value.
    """
    # A gateway/JWT could hand back an int-typed org_id; a resource_org_id
    # supplied as a string (or vice versa) must not spuriously mismatch.
    allowed, reason = evaluate_tenancy(1, {"resource_org_id": "1"})
    assert allowed is True
