"""
OmniBioAI app.core.rules.

Purpose:
    Defines evaluate_rules for app.core.rules.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

def evaluate_rules(action: str, resource: str) -> tuple[bool, str]:
    # Example dataset protection rules
    if resource.startswith("human_genome") and action == "dataset.delete":
        return False, "protected dataset cannot be deleted"

    # Model registry protection
    if resource == "model_registry" and action == "delete":
        return False, "model registry is immutable"

    return True, "rules passed"