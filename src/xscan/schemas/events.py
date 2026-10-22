"""Domain events published on the EventBus."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(UTC)




class EventType(StrEnum):
    # Scan lifecycle
    SCAN_CREATED     = "scan.created"
    SCAN_STARTED     = "scan.started"
    SCAN_COMPLETED   = "scan.completed"
    SCAN_FAILED      = "scan.failed"
    SCAN_CANCELLED   = "scan.cancelled"
    # DAG
    NODE_STARTED     = "node.started"
    NODE_COMPLETED   = "node.completed"
    NODE_FAILED      = "node.failed"
    # Findings
    FINDING_CREATED  = "finding.created"
    FINDING_CONFIRMED = "finding.confirmed"
    # Evidence
    EVIDENCE_CAPTURED = "evidence.captured"
    # Tools
    TOOL_INSTALLED   = "tool.installed"
    TOOL_FAILED      = "tool.failed"
    # Policy
    POLICY_VIOLATION = "policy.violation"
    # LLM
    LLM_REQUEST_SENT = "llm.request_sent"
    LLM_RESPONSE_RECEIVED = "llm.response_received"


class DomainEvent(BaseModel):
    """A single domain event published on the EventBus."""
    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    type: EventType
    scan_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=_utcnow)

