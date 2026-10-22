"""ToolService — delegates to the tool registry."""
from __future__ import annotations

from typing import Any


class ToolService:
    def list(self) -> list[dict[str, Any]]:
        from xscan.tools.registry import tool_registry
        return tool_registry.list_with_health()

    def check(self, name: str | None = None, all_tools: bool = False) -> list[dict[str, Any]]:
        from xscan.tools.registry import tool_registry
        if all_tools or name is None:
            return tool_registry.check_all()
        return [tool_registry.check_one(name)]

    def inspect(self, name: str) -> dict[str, Any]:
        from xscan.tools.registry import tool_registry
        return tool_registry.inspect(name)
