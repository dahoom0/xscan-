"""
Scan execution events — small structured records streamed from DAG nodes.

Rules:
  - Events are tiny metadata records (never full HTTP bodies, HTML, screenshots).
  - Large data is stored as artifacts and referenced by ID.
  - The terminal renders events; the scan store persists them.
  - Events carry metrics (counts, durations) not raw data.
"""
from __future__ import annotations

from datetime import datetime, UTC
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class NodeEventType(StrEnum):
    STARTED   = "started"
    PROGRESS  = "progress"
    WARNING   = "warning"
    COMPLETED = "completed"
    FAILED    = "failed"
    SKIPPED   = "skipped"


class NodeEvent(BaseModel):
    """
    One event emitted by a DAG node during execution.

    The 'metrics' dict contains small numeric/string summaries only.
    Large data (HTTP bodies, JS files, screenshots) goes to the artifact
    store and is referenced by ID via 'artifact_ids'.
    """
    scan_id:      str
    run_id:       str
    node_id:      str
    node_type:    str = ""
    event_type:   NodeEventType
    message:      str = ""
    metrics:      dict[str, Any] = Field(default_factory=dict)
    artifact_ids: list[str]      = Field(default_factory=list)
    duration_ms:  float          = 0.0
    timestamp:    datetime       = Field(default_factory=lambda: datetime.now(UTC))

    class Config:
        use_enum_values = True


class ScanSummary(BaseModel):
    """Final summary emitted when a scan completes."""
    scan_id:          str
    target_url:       str
    profile:          str
    status:           str
    duration_s:       float
    urls_crawled:     int = 0
    forms_found:      int = 0
    inputs_analyzed:  int = 0
    reflections:      int = 0
    candidates:       int = 0
    llm_likely:       int = 0
    confirmed_findings: int = 0
    technologies:     list[str] = Field(default_factory=list)
    degraded:         bool = False                 # True if pre-flight checks failed
    degradation_reason: str = ""                   # Why this scan is degraded
