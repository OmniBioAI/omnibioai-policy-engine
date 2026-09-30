from fastapi import APIRouter

from app.services.policy_service import evaluate_policy

router = APIRouter()


@router.post("/evaluate")
def evaluate(req: dict):
    return evaluate_policy(req)