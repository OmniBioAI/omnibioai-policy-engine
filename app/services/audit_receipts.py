"""Security Audit durable-receipt client for authorization decisions."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

import httpx
from pydantic import BaseModel, ConfigDict, Field


class AuditReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    receipt_id: str = Field(min_length=8, max_length=256)
    event_id: str = Field(min_length=8, max_length=256)
    source: str = Field(pattern=r"^security-audit$")
    durable: bool
    persisted_at: datetime


class AuditReceiptPublisher(Protocol):
    def publish(self, event: dict[str, Any]) -> AuditReceipt: ...


class SecurityAuditReceiptClient:
    """Publish to Security Audit and require its durable persistence receipt."""

    def __init__(
        self,
        *,
        url: str,
        token_file: str,
        post: Callable[..., Any] | None = None,
    ) -> None:
        self.url = url
        self.token_file = token_file
        self._post = post or httpx.post

    def publish(self, event: dict[str, Any]) -> AuditReceipt:
        if not self.url or not self.token_file:
            raise RuntimeError("security-audit receipt publisher is not configured")
        token = Path(self.token_file).read_text(encoding="utf-8").strip()
        if not token:
            raise RuntimeError("security-audit workload token is absent")
        response = self._post(
            self.url,
            json=event,
            headers={"Authorization": f"Bearer {token}"},
            timeout=httpx.Timeout(1.0, connect=0.25),
        )
        response.raise_for_status()
        receipt = AuditReceipt.model_validate(response.json())
        if not receipt.durable or receipt.event_id != event.get("event_id"):
            raise RuntimeError(
                "security-audit durable receipt is missing or mismatched"
            )
        return receipt
