"""
OmniBioAI app.api.routes_policy.

Purpose:
    Defines HTTP route handlers for app.api.routes_policy, including evaluate.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

from fastapi import APIRouter

from app.services.policy_service import evaluate_policy

router = APIRouter()


@router.post("/evaluate")
def evaluate(req: dict):
    return evaluate_policy(req)