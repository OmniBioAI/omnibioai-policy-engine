def evaluate_rbac(user_roles: list[str], action: str) -> tuple[bool, str]:
    if "admin" in user_roles:
        return True, "admin override"

    if action.startswith("tes.") and "researcher" not in user_roles:
        return False, "missing role: researcher"

    # PR12: dataset.read is exempted from the blanket data_scientist
    # requirement -- read access is now governed by the finer-grained
    # permissions.py gate (the "dataset.read" permission) instead, which
    # is what lets a read-only "Viewer" tier exist at all (this legacy
    # rule previously made ANY dataset.* action, including read,
    # data_scientist-only, with no way to grant read without also
    # granting write/delete). Write/delete actions are unaffected --
    # still gated here exactly as before.
    if (
        action.startswith("dataset.")
        and action != "dataset.read"
        and "data_scientist" not in user_roles
    ):
        return False, "missing role: data_scientist"

    return True, "rbac passed"