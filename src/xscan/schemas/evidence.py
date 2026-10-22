"""EvidenceNode, EvidenceEdge, EvidenceType, and Artifact schemas."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(UTC)




class EvidenceType(StrEnum):
    HTTP_REQUEST    = "http-request"
    HTTP_RESPONSE   = "http-response"
    SCREENSHOT      = "screenshot"
    DOM_SNAPSHOT    = "dom-snapshot"
    CONSOLE_LOG     = "console-log"
    NETWORK_LOG     = "network-log"
    AST_NODE        = "ast-node"
    TAINT_PATH      = "taint-path"
    REFLECTION      = "reflection"
    DIFF            = "diff"
    TOOL_OUTPUT     = "tool-output"


class Artifact(BaseModel):
    """Binary or text artifact linked to an evidence node."""
    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    evidence_id: str
    filename: str
    mime_type: str = "application/octet-stream"
    size_bytes: int = 0
    storage_path: str = ""          # relative path under ~/.xscan/artifacts/
    created_at: datetime = Field(default_factory=_utcnow)


class EvidenceNode(BaseModel):
    """A single piece of evidence with full provenance."""
    id: str = Field(default_factory=lambda: "E-" + uuid.uuid4().hex[:10])
    scan_id: str
    node_id: str = ""               # DAG node that produced this
    type: EvidenceType
    url: str = ""
    summary: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    artifact_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)
    # Provenance chain â€” links to parent evidence nodes
    parent_ids: list[str] = Field(default_factory=list)


class EvidenceEdge(BaseModel):
    """Directed edge in the evidence graph."""
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    from_id: str
    to_id: str
    label: str = ""                 # e.g. "reflects", "triggers", "contains"

