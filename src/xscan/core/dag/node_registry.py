"""
NodeRegistry
============
Maps node_type strings (from workflow YAML) to NodeBase subclasses.

Usage::

    @registry.register("technology-detect")
    class TechnologyNode(NodeBase):
        node_type = "technology-detect"
        ...

    node_class = registry.get("technology-detect")
    result = node_class().run(ctx)
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from xscan.errors import DAGError

if TYPE_CHECKING:
    from xscan.nodes.base import NodeBase


class NodeRegistry:
    """Process-wide registry mapping node_type → NodeBase subclass."""

    def __init__(self) -> None:
        self._map: dict[str, type["NodeBase"]] = {}

    def register(self, node_type: str):
        """Decorator: register a NodeBase subclass under node_type."""
        def decorator(cls: type["NodeBase"]) -> type["NodeBase"]:
            self._map[node_type] = cls
            return cls
        return decorator

    def get(self, node_type: str) -> type["NodeBase"]:
        if node_type not in self._map:
            raise DAGError(
                f"Unknown node type '{node_type}'. "
                f"Registered types: {sorted(self._map)}"
            )
        return self._map[node_type]

    def all_types(self) -> list[str]:
        return sorted(self._map)

    def is_registered(self, node_type: str) -> bool:
        return node_type in self._map


# Module-level singleton
registry = NodeRegistry()
