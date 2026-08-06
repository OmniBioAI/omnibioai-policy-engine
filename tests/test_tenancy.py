from app.core.tenancy import evaluate_tenancy


def test_no_resource_org_id_is_noop():
    allowed, reason = evaluate_tenancy("org-1", {})
    assert allowed is True
    assert reason == "no tenancy scoping required"


def test_matching_org_allowed():
    allowed, reason = evaluate_tenancy("org-1", {"resource_org_id": "org-1"})
    assert allowed is True
    assert reason == "tenancy check passed"


def test_mismatched_org_denied():
    allowed, reason = evaluate_tenancy("org-1", {"resource_org_id": "org-2"})
    assert allowed is False
    assert reason == "cross-tenant access denied"


def test_missing_requester_org_denied_when_resource_scoped():
    allowed, reason = evaluate_tenancy(None, {"resource_org_id": "org-2"})
    assert allowed is False
    assert reason == "missing organization context"


def test_org_id_compared_as_string():
    # A gateway/JWT could hand back an int-typed org_id; a resource_org_id
    # supplied as a string (or vice versa) must not spuriously mismatch.
    allowed, reason = evaluate_tenancy(1, {"resource_org_id": "1"})
    assert allowed is True
