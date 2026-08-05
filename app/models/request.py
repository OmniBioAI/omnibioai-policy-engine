from pydantic import BaseModel
from typing import Dict, Any, Optional


class PolicyRequest(BaseModel):
    user_id: str
    email: Optional[str] = None
    roles: list[str] = []
    permissions: list[str] = []
    # PR12: requester's organization, for tenancy scoping (app/core/tenancy.py).
    org_id: Optional[str] = None

    action: str
    resource: str

    context: Dict[str, Any] = {}