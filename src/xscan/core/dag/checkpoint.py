"""
DAG Checkpoint
==============
Saves and loads WorkflowRun state so scans can be resumed after
interruption.

Storage: WorkflowRepository (SQLite-backed).
Each node result is persisted immediately after it completes or fails.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from xscan.schemas.workflow import NodeResult, NodeStatus, WorkflowRun

if TYPE_CHECKING:
    from xscan.storage.database import Database

logger = logging.getLogger(__name__)


class MemoryCheckpoint:
    """
    In-memory checkpoint — no database writes.
    Used when the user has not requested persistent storage (no --output flag).
    The DAG engine cannot tell the difference; it just calls save_run/save_node.
    """

    def __init__(self) -> None:
        self._runs: dict[str, WorkflowRun] = {}
        self._nodes: dict[str, dict[str, NodeResult]] = {}

    def save_run(self, run: WorkflowRun) -> None:
        self._runs[run.id] = run

    def save_node(self, run_id: str, result: NodeResult) -> None:
        self._nodes.setdefault(run_id, {})[result.node_id] = result

    def load_run(self, run_id: str) -> WorkflowRun | None:
        return self._runs.get(run_id)

    def load_latest_for_scan(self, scan_id: str) -> WorkflowRun | None:
        for run in reversed(list(self._runs.values())):
            if run.scan_id == scan_id:
                return run
        return None

    def completed_nodes(self, run_id: str) -> set[str]:
        run = self.load_run(run_id)
        if not run:
            return set()
        return {
            node_id
            for node_id, result in run.node_results.items()
            if result.status == NodeStatus.COMPLETED
        }


class Checkpoint:
    """
    Saves WorkflowRun state to the database after every node completion.

    Usage::

        cp = Checkpoint(db)
        cp.save_run(run)
        cp.save_node(run_id, node_result)
        run = cp.load_run(run_id)  # resume
    """

    def __init__(self, db: "Database") -> None:
        from xscan.storage.repositories.workflow import WorkflowRepository
        self._repo = WorkflowRepository(db)

    def save_run(self, run: WorkflowRun) -> None:
        self._repo.save_run(run)
        logger.debug("Checkpoint saved run %s  status=%s", run.id, run.status)

    def save_node(self, run_id: str, result: NodeResult) -> None:
        self._repo.save_node_result(run_id, result)
        logger.debug(
            "Checkpoint saved node %s  run=%s  status=%s",
            result.node_id, run_id, result.status,
        )

    def load_run(self, run_id: str) -> WorkflowRun | None:
        return self._repo.get_run(run_id)

    def load_latest_for_scan(self, scan_id: str) -> WorkflowRun | None:
        return self._repo.get_latest_run_for_scan(scan_id)

    def completed_nodes(self, run_id: str) -> set[str]:
        """Return the set of node IDs that have already completed successfully."""
        run = self.load_run(run_id)
        if not run:
            return set()
        return {
            node_id
            for node_id, result in run.node_results.items()
            if result.status == NodeStatus.COMPLETED
        }
