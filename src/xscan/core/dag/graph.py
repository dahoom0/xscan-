"""
WorkflowGraph
=============
Builds and validates the directed acyclic graph from a Workflow definition.

Responsibilities:
  - Build adjacency structures from WorkflowNode.depends_on
  - Detect cycles (raises WorkflowValidationError)
  - Produce a topological execution order
  - Identify which nodes can run in parallel at each step
"""
from __future__ import annotations

from collections import defaultdict, deque

from xscan.errors import WorkflowValidationError
from xscan.schemas.workflow import Workflow, WorkflowNode


class WorkflowGraph:
    """
    Immutable DAG built from a Workflow definition.

    Usage::

        graph = WorkflowGraph.from_workflow(workflow)
        graph.validate()
        for wave in graph.execution_waves():
            # nodes in same wave can run in parallel
            run_parallel(wave)
    """

    def __init__(self, workflow: Workflow) -> None:
        self.workflow = workflow
        self._nodes: dict[str, WorkflowNode] = {n.id: n for n in workflow.nodes}
        # id → set of ids that must complete before this node runs
        self._deps: dict[str, set[str]] = {
            n.id: set(n.depends_on) for n in workflow.nodes
        }
        # reverse: id → set of ids that depend on this node
        self._rdeps: dict[str, set[str]] = defaultdict(set)
        for node_id, deps in self._deps.items():
            for dep in deps:
                self._rdeps[dep].add(node_id)

    @classmethod
    def from_workflow(cls, workflow: Workflow) -> "WorkflowGraph":
        g = cls(workflow)
        g.validate()
        return g

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(self) -> None:
        """Raise WorkflowValidationError if the graph is invalid."""
        self._check_unknown_deps()
        self._check_cycles()

    def _check_unknown_deps(self) -> None:
        for node_id, deps in self._deps.items():
            for dep in deps:
                if dep not in self._nodes:
                    raise WorkflowValidationError(
                        f"Node '{node_id}' depends on unknown node '{dep}'."
                    )

    def _check_cycles(self) -> None:
        """Kahn's algorithm — if we can't produce a full topo sort, there's a cycle."""
        in_degree: dict[str, int] = {n: 0 for n in self._nodes}
        for node_id, deps in self._deps.items():
            in_degree[node_id] = len(deps)

        queue: deque[str] = deque(n for n, d in in_degree.items() if d == 0)
        visited = 0
        while queue:
            node = queue.popleft()
            visited += 1
            for dependent in self._rdeps.get(node, set()):
                in_degree[dependent] -= 1
                if in_degree[dependent] == 0:
                    queue.append(dependent)

        if visited != len(self._nodes):
            raise WorkflowValidationError(
                f"Workflow '{self.workflow.name}' contains a cycle."
            )

    # ------------------------------------------------------------------
    # Execution ordering
    # ------------------------------------------------------------------

    def topological_order(self) -> list[str]:
        """Return node IDs in a valid linear execution order."""
        in_degree: dict[str, int] = {
            n: len(deps) for n, deps in self._deps.items()
        }
        queue: deque[str] = deque(sorted(n for n, d in in_degree.items() if d == 0))
        order: list[str] = []
        while queue:
            node = queue.popleft()
            order.append(node)
            for dep in sorted(self._rdeps.get(node, set())):
                in_degree[dep] -= 1
                if in_degree[dep] == 0:
                    queue.append(dep)
        return order

    def execution_waves(self) -> list[list[str]]:
        """
        Return groups of node IDs that can execute in parallel.
        Each wave contains nodes whose dependencies are all in earlier waves.
        """
        remaining_deps: dict[str, set[str]] = {
            n: set(deps) for n, deps in self._deps.items()
        }
        waves: list[list[str]] = []
        while remaining_deps:
            ready = sorted(n for n, deps in remaining_deps.items() if not deps)
            if not ready:
                raise WorkflowValidationError("Cannot compute execution waves — cycle detected.")
            waves.append(ready)
            for node_id in ready:
                del remaining_deps[node_id]
            for node_id in remaining_deps:
                remaining_deps[node_id] -= set(ready)
        return waves

    def dependencies_of(self, node_id: str) -> set[str]:
        return self._deps.get(node_id, set())

    def dependents_of(self, node_id: str) -> set[str]:
        return self._rdeps.get(node_id, set())

    def node(self, node_id: str) -> WorkflowNode:
        if node_id not in self._nodes:
            raise KeyError(f"Node '{node_id}' not in workflow '{self.workflow.name}'")
        return self._nodes[node_id]
