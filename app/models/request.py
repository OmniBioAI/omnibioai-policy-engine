"""
OmniBioAI app.models.request.

Purpose:
    Defines the PolicyRequest data model for app.models.request.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

from typing import Any, Literal

from pydantic import BaseModel


class PolicyRequest(BaseModel):
    user_id: str
    email: str | None = None
    roles: list[str] = []
    permissions: list[str] = []
    # PR12: requester's organization, for tenancy scoping (app/core/tenancy.py).
    org_id: str | None = None

    action: str
    resource: str

    context: dict[str, Any] = {}
    # Explicitly separates capability checks from resource ownership.
    # Global is the compatibility default for operations with no resource.
    resource_scope: Literal["global", "tenant", "admin"] | None = None
