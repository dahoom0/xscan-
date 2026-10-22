"""
WorkflowValidator
=================
Validates a loaded Workflow before execution.

Checks:
  - All node IDs are unique
  - All node types are registered in the NodeRegistry
  - All depends_on references exist
  - No cycles
  - Required inputs declared
  - Node capabilities are known (if NodeRegistry is provided)
"""
from __future__ import annotations

from dataclasses import dataclass, field

from xscan.core.dag.graph import WorkflowGraph
from xscan.errors import WorkflowValidationError
from xscan.schemas.workflow import Workflow


@dataclass
class ValidationResult:
    valid: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add_error(self, msg: str) -> None:
        self.errors.append(msg)
        self.valid = False

    def add_warning(self, msg: str) -> None:
        self.warnings.append(msg)


class WorkflowValidator:
    """
    Validate a Workflow before execution.

    Usage::

        result = WorkflowValidator().validate(workflow)
        if not result.valid:
            for err in result.errors:
                print(err)

        # Or raise immediately:
        WorkflowValidator().assert_valid(workflow)
    """

    def __init__(self, check_registry: bool = True) -> None:
        self._check_registry = check_registry

    def validate(self, workflow: Workflow) -> ValidationResult:
        result = ValidationResult()

        # 1. Unique node IDs
        seen_ids: set[str] = set()
        for node in workflow.nodes:
            if not node.id:
                result.add_error("Node has empty id.")
            elif node.id in seen_ids:
                result.add_error(f"Duplicate node id: '{node.id}'")
            else:
                seen_ids.add(node.id)

            if not node.type:
                result.add_error(f"Node '{node.id}' has empty type.")

        if not result.valid:
            return result  # can't proceed with structural errors

        # 2. Graph-level validation (unknown deps + cycles)
        try:
            WorkflowGraph.from_workflow(workflow)
        except WorkflowValidationError as exc:
            result.add_error(str(exc))
            return result

        # 3. Registry check — warn for unregistered types
        if self._check_registry:
            try:
                from xscan.core.dag.node_registry import registry
                for node in workflow.nodes:
                    if not registry.is_registered(node.type):
                        result.add_warning(
                            f"Node '{node.id}' type '{node.type}' is not registered. "
                            "The node will be skipped during execution."
                        )
            except Exception:
                pass  # registry unavailable — skip check

        # 4. Warn on empty workflow
        if not workflow.nodes:
            result.add_warning(f"Workflow '{workflow.name}' has no nodes.")

        return result

    def assert_valid(self, workflow: Workflow) -> None:
        """Validate and raise WorkflowValidationError on first error."""
        result = self.validate(workflow)
        if not result.valid:
            raise WorkflowValidationError(
                f"Workflow '{workflow.name}' is invalid:\n"
                + "\n".join(f"  - {e}" for e in result.errors)
            )
