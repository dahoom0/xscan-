"""
NodeEmitter mixin
=================
Gives every NodeBase subclass a clean API for emitting structured events.

Usage inside a node::

    self.emit_started(ctx)
    self.emit_progress(ctx, "Crawling page 3 of 20")
    self.emit_completed(ctx, metrics={"urls": 7, "forms": 2}, duration_ms=3100)

Events are published on the process-wide EventBus so:
  - The terminal renderer receives and displays them
  - The scan store persists them
  - Telemetry can aggregate them

Nodes never call print() or logging.info() for user-visible output.
All user-visible output flows through emit_*.
"""
from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from xscan.core.events import NodeEvent, NodeEventType
from xscan.events import bus
from xscan.schemas.events import DomainEvent, EventType

if TYPE_CHECKING:
    from xscan.nodes.base import ExecutionContext


class NodeEmitter:
    """Mixin for structured event emission from DAG nodes."""

    # Subclasses set this; falls back to class name
    node_type: str = "unknown"

    def emit_started(self, ctx: "ExecutionContext") -> float:
        """Emit a STARTED event and return the start timestamp (monotonic)."""
        self._publish(ctx, NodeEventType.STARTED)
        return time.monotonic()

    def emit_progress(
        self,
        ctx: "ExecutionContext",
        message: str,
        metrics: dict[str, Any] | None = None,
    ) -> None:
        self._publish(ctx, NodeEventType.PROGRESS, message=message, metrics=metrics or {})

    def emit_warning(
        self,
        ctx: "ExecutionContext",
        message: str,
    ) -> None:
        self._publish(ctx, NodeEventType.WARNING, message=message)

    def emit_completed(
        self,
        ctx: "ExecutionContext",
        metrics: dict[str, Any] | None = None,
        duration_ms: float = 0.0,
        artifact_ids: list[str] | None = None,
    ) -> None:
        self._publish(
            ctx, NodeEventType.COMPLETED,
            metrics=metrics or {},
            duration_ms=duration_ms,
            artifact_ids=artifact_ids or [],
        )

    def emit_failed(
        self,
        ctx: "ExecutionContext",
        error: str,
        duration_ms: float = 0.0,
    ) -> None:
        self._publish(ctx, NodeEventType.FAILED, message=error, duration_ms=duration_ms)

    # ------------------------------------------------------------------

    def _publish(
        self,
        ctx: "ExecutionContext",
        event_type: NodeEventType,
        message: str = "",
        metrics: dict[str, Any] | None = None,
        duration_ms: float = 0.0,
        artifact_ids: list[str] | None = None,
    ) -> None:
        node_event = NodeEvent(
            scan_id=ctx.scan_id,
            run_id=ctx.run_id,
            node_id=ctx.node_id,
            node_type=self.node_type,
            event_type=event_type,
            message=message,
            metrics=metrics or {},
            duration_ms=duration_ms,
            artifact_ids=artifact_ids or [],
        )
        bus.publish(DomainEvent(
            type=EventType.NODE_STARTED if event_type == NodeEventType.STARTED
                 else EventType.NODE_COMPLETED if event_type == NodeEventType.COMPLETED
                 else EventType.NODE_FAILED if event_type == NodeEventType.FAILED
                 else EventType.NODE_STARTED,  # reuse for progress/warning
            scan_id=ctx.scan_id,
            payload=node_event.model_dump(mode="json"),
        ))
