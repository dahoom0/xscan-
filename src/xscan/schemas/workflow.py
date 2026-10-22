"""Workflow, WorkflowNode, NodeResult, and WorkflowRun schemas."""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class NodeStatus(StrEnum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    SKIPPED   = "skipped"


class WorkflowNode(BaseModel):
    """A single node in the workflow DAG definition."""
    id: str                                       # unique within workflow
    type: str                                     # registered node type name
    depends_on: list[str] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)
    capability: str | None = None              # required tool capability, if any
    timeout: int = 300                            # seconds
    retry: int = 0


class Workflow(BaseModel):
    """Workflow definition loaded from YAML."""
    name: str
    version: str = "1.0"
    description: str = ""
    inputs: dict[str, Any] = Field(default_factory=dict)
    nodes: list[WorkflowNode] = Field(default_factory=list)

    def node_by_id(self, node_id: str) -> WorkflowNode | None:
        return next((n for n in self.nodes if n.id == node_id), None)


class NodeResult(BaseModel):
    """Output produced by a single DAG node execution."""
    node_id: str
    status: NodeStatus = NodeStatus.PENDING
    started_at: datetime | None = None
    finished_at: datetime | None = None
    output: dict[str, Any] = Field(default_factory=dict)
    artifact_ids: list[str] = Field(default_factory=list)
    error: str | None = None
    metrics: dict[str, Any] = Field(default_factory=dict)

    @property
    def duration_s(self) -> float | None:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None


class WorkflowRun(BaseModel):
    """Runtime state for one execution of a Workflow."""
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    scan_id: str
    workflow_name: str
    workflow_version: str = "1.0"
    status: NodeStatus = NodeStatus.PENDING
    started_at: datetime | None = None
    finished_at: datetime | None = None
    node_results: dict[str, NodeResult] = Field(default_factory=dict)
    degraded: bool = False                        # True if pre-flight checks failed non-critically
    degradation_reason: str = ""                  # Details on what was degraded

    def is_node_complete(self, node_id: str) -> bool:
        r = self.node_results.get(node_id)
        return r is not None and r.status == NodeStatus.COMPLETED

    def is_node_failed(self, node_id: str) -> bool:
        r = self.node_results.get(node_id)
        return r is not None and r.status == NodeStatus.FAILED
