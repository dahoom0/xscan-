"""
NodeBase — contract every DAG node must implement.

A node:
  - Receives a typed ExecutionContext
  - Validates inputs via a Pydantic model
  - Runs its logic
  - Returns a NodeResult

Nodes MUST NOT:
  - Call other nodes directly (only the DAG scheduler does that)
  - Issue network operations without going through ScopeEngine
  - Create findings without evidence
  - Call LLM providers directly (use LLMGateway)
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime, UTC
from typing import Any, ClassVar

from xscan.schemas.workflow import NodeResult, NodeStatus
from xscan.core.scope.engine import ScopeEngine
from xscan.core.scope.policy import PolicyEngine


class ExecutionContext:
    """
    Everything a node needs to run — injected by the DAG scheduler.

    Nodes access inputs, scope, policy, and the event bus through this
    object.  They do NOT import singletons directly.
    """

    def __init__(
        self,
        scan_id: str,
        node_id: str,
        run_id: str,
        inputs: dict[str, Any],
        scope: ScopeEngine,
        policy: PolicyEngine,
        config: dict[str, Any] | None = None,
        no_llm: bool = False,
    ) -> None:
        self.scan_id = scan_id
        self.node_id = node_id
        self.run_id = run_id
        self.inputs = inputs
        self.scope = scope
        self.policy = policy
        self.config = config or {}
        self.no_llm = no_llm
        self.logger = logging.getLogger(f"xscan.node.{node_id}")

    def get(self, key: str, default: Any = None) -> Any:
        """Convenience accessor for inputs dict."""
        return self.inputs.get(key, default)


class NodeBase(ABC):
    """
    Abstract base class for all XScan DAG nodes.

    Subclass contract:
      - Set ``node_type`` class variable to a unique string
      - Implement ``execute(ctx) -> dict[str, Any]``
        where the returned dict contains the node's output keys

    The base class wraps execute() with timing, error handling,
    and NodeResult construction.
    """

    node_type: ClassVar[str] = "base"

    def run(self, ctx: ExecutionContext) -> NodeResult:
        """
        Called by the DAG scheduler.  Do not override — override execute().
        """
        result = NodeResult(
            node_id=ctx.node_id,
            status=NodeStatus.RUNNING,
            started_at=datetime.now(UTC),
        )
        try:
            output = self.execute(ctx)
            result = result.model_copy(update={
                "status": NodeStatus.COMPLETED,
                "output": output or {},
                "finished_at": datetime.now(UTC),
            })
        except Exception as exc:
            ctx.logger.exception("Node %s failed: %s", ctx.node_id, exc)
            result = result.model_copy(update={
                "status": NodeStatus.FAILED,
                "error": str(exc),
                "finished_at": datetime.now(UTC),
            })
        return result

    @abstractmethod
    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        """
        Node logic.  Return a dict of output key/value pairs.
        Raise any exception on failure — NodeBase.run() will catch it.
        """
        ...
