"""
DAGEngine
=========
Executes a Workflow as a deterministic DAG.

Execution model:
  1. Build WorkflowGraph from Workflow definition
  2. Compute execution waves (parallel-ready node groups)
  3. For each wave, run each node sequentially (parallel support: future)
  4. Checkpoint node result immediately after completion or failure
  5. Feed node outputs into subsequent nodes' inputs
  6. On resume: skip nodes whose NodeResult.status == COMPLETED

Rules enforced here:
  - Every node receives a fresh ExecutionContext
  - Node outputs are threaded through the shared state dict
  - Failed nodes stop the wave (fail-fast); remaining waves are skipped
  - Scope and Policy are injected — nodes cannot bypass them
"""
from __future__ import annotations

import logging
from datetime import datetime, UTC
from typing import Any, Callable

from xscan.core.dag.graph import WorkflowGraph
from xscan.core.dag.node_registry import NodeRegistry, registry as _global_registry
from xscan.core.dag.checkpoint import Checkpoint
from xscan.core.scope.engine import ScopeEngine
from xscan.core.scope.policy import PolicyEngine
from xscan.errors import DAGError, NodeExecutionError
from xscan.nodes.base import ExecutionContext
from xscan.schemas.workflow import NodeResult, NodeStatus, Workflow, WorkflowRun

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str, str, str], None]  # (stage, node_id, message)


class DAGEngine:
    """
    Executes a Workflow.

    Usage::

        engine = DAGEngine(
            workflow=workflow,
            scope=ScopeEngine.from_target(scan_id, target_url),
            policy=PolicyEngine(),
            checkpoint=Checkpoint(db),
        )
        run = engine.execute(scan_id, inputs={"target_url": "https://example.com"})
    """

    def __init__(
        self,
        workflow: Workflow,
        scope: ScopeEngine,
        policy: PolicyEngine,
        checkpoint: Checkpoint,
        node_registry: NodeRegistry | None = None,
        progress_cb: ProgressCallback | None = None,
        no_llm: bool = False,
        resume_run_id: str | None = None,
    ) -> None:
        self._workflow = workflow
        self._scope = scope
        self._policy = policy
        self._checkpoint = checkpoint
        self._registry = node_registry or _global_registry
        self._progress_cb = progress_cb or (lambda stage, nid, msg: None)
        self._no_llm = no_llm
        self._resume_run_id = resume_run_id

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def execute(self, scan_id: str, inputs: dict[str, Any] | None = None) -> WorkflowRun:
        """
        Execute the full workflow.  Returns a completed (or failed) WorkflowRun.
        """
        graph = WorkflowGraph.from_workflow(self._workflow)

        # Resume or create run
        run = self._init_run(scan_id, graph)
        already_done = {
            nid for nid, r in run.node_results.items()
            if r.status == NodeStatus.COMPLETED
        }
        if already_done:
            logger.info("Resuming run %s — skipping %d completed nodes", run.id, len(already_done))

        # Shared state: starts with caller-supplied inputs, grows as nodes produce outputs
        state: dict[str, Any] = dict(inputs or {})

        # Execute wave by wave
        run = run.model_copy(update={
            "status": NodeStatus.RUNNING,
            "started_at": run.started_at or datetime.now(UTC),
        })
        self._checkpoint.save_run(run)

        try:
            for wave in graph.execution_waves():
                wave_failed = False
                for node_id in wave:
                    if node_id in already_done:
                        self._progress_cb("skip", node_id, "already completed — skipping")
                        continue

                    result = self._run_node(node_id, graph, run.id, scan_id, state)
                    run.node_results[node_id] = result
                    self._checkpoint.save_node(run.id, result)

                    if result.status == NodeStatus.COMPLETED:
                        # Merge outputs into shared state
                        state.update(result.output)
                    else:
                        wave_failed = True
                        logger.error("Node %s failed — stopping wave", node_id)
                        break

                if wave_failed:
                    run = run.model_copy(update={
                        "status": NodeStatus.FAILED,
                        "finished_at": datetime.now(UTC),
                    })
                    self._checkpoint.save_run(run)
                    return run

        except KeyboardInterrupt:
            run = run.model_copy(update={
                "status": NodeStatus.FAILED,
                "finished_at": datetime.now(UTC),
            })
            self._checkpoint.save_run(run)
            raise

        run = run.model_copy(update={
            "status": NodeStatus.COMPLETED,
            "finished_at": datetime.now(UTC),
        })
        self._checkpoint.save_run(run)
        logger.info("Workflow '%s' completed  run=%s", self._workflow.name, run.id)
        return run

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _init_run(self, scan_id: str, graph: WorkflowGraph) -> WorkflowRun:
        """Return a new or resumed WorkflowRun."""
        if self._resume_run_id:
            existing = self._checkpoint.load_run(self._resume_run_id)
            if existing:
                return existing
            logger.warning("Resume run %s not found — starting fresh", self._resume_run_id)

        return WorkflowRun(
            scan_id=scan_id,
            workflow_name=self._workflow.name,
            workflow_version=self._workflow.version,
            status=NodeStatus.PENDING,
        )

    def _run_node(
        self,
        node_id: str,
        graph: WorkflowGraph,
        run_id: str,
        scan_id: str,
        state: dict[str, Any],
    ) -> NodeResult:
        """Instantiate, contextualise, and run one node."""
        wf_node = graph.node(node_id)

        if not self._registry.is_registered(wf_node.type):
            logger.warning("No implementation for node type '%s' — skipping", wf_node.type)
            return NodeResult(
                node_id=node_id,
                status=NodeStatus.SKIPPED,
                error=f"Node type '{wf_node.type}' not registered",
            )

        node_cls = self._registry.get(wf_node.type)
        node_instance = node_cls()

        ctx = ExecutionContext(
            scan_id=scan_id,
            node_id=node_id,
            run_id=run_id,
            inputs=dict(state),          # snapshot — nodes get their own copy
            scope=self._scope,
            policy=self._policy,
            config=dict(wf_node.config),
            no_llm=self._no_llm,
        )

        self._progress_cb("run", node_id, f"Running node '{node_id}' [{wf_node.type}]")
        logger.info("DAG running node %s [%s]  run=%s", node_id, wf_node.type, run_id)

        result = node_instance.run(ctx)

        self._progress_cb(
            result.status,
            node_id,
            f"Node '{node_id}' {result.status}"
            + (f": {result.error}" if result.error else ""),
        )
        return result
