"""
OmniBioAI app.core.abac.

Purpose:
    Defines evaluate_abac for app.core.abac.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

def evaluate_abac(context: dict, roles: list[str]) -> tuple[bool, str]:
    # GPU restriction example
    if context.get("gpu_required") and "gpu_user" not in roles:
        return False, "GPU access denied"

    # HPC node restriction
    if context.get("node") == "hpc" and "hpc_user" not in roles:
        return False, "HPC access denied"

    return True, "abac passed"
