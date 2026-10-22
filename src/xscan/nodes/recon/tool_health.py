"""
tool-health node
================
Pre-flight validation of required and optional tools.

Inputs:  (none) — uses config
Outputs: tool_status (dict[str, ToolHealth])
         available_tools (list[str])
         missing_tools (list[str])
         tool_count_total (int)
         tool_count_available (int)
         tool_count_missing (int)
"""
from __future__ import annotations

import time
from typing import Any

from xscan.core.dag.node_registry import registry
from xscan.nodes.base import ExecutionContext, NodeBase
from xscan.nodes.emitter import NodeEmitter
from xscan.runtime.resolver import get_runtime
from xscan.schemas.tool import ToolHealth, ToolStatus


@registry.register("tool-health")
class ToolHealthNode(NodeBase, NodeEmitter):
    node_type = "tool-health"

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        t0 = self.emit_started(ctx)

        # Configuration for required and optional tools
        required_tools: list[str] = ctx.config.get("required_tools", [
            "subfinder",
            "assetfinder",
            "httpx",
        ])
        optional_tools: list[str] = ctx.config.get("optional_tools", [
            "amass",
            "ffuf",
            "gowitness",
            "nuclei",
        ])

        runtime = get_runtime()
        tool_status: dict[str, ToolHealth] = {}
        available: list[str] = []
        missing: list[str] = []

        # Check required tools
        for tool_name in required_tools:
            status = self._check_tool(runtime, tool_name)
            tool_status[tool_name] = status
            
            if status.status == ToolStatus.INSTALLED:
                available.append(tool_name)
                self.emit_progress(ctx, f"✓ {tool_name}: {status.version or 'available'}")
            else:
                missing.append(tool_name)
                self.emit_warning(ctx, f"✗ {tool_name}: {status.status.value}")

        # Check optional tools (warn only if running in strict mode)
        for tool_name in optional_tools:
            status = self._check_tool(runtime, tool_name)
            tool_status[tool_name] = status
            
            if status.status == ToolStatus.INSTALLED:
                available.append(tool_name)
                self.emit_progress(ctx, f"✓ {tool_name}: {status.version or 'available'}")
            else:
                # Track missing optional tools but don't warn
                missing.append(tool_name)
                self.emit_progress(ctx, f"⊘ {tool_name}: {status.status.value} (optional)")

        # Convert ToolHealth objects to dicts for JSON serialization
        tool_status_dict = {
            name: health.model_dump(mode="json")
            for name, health in tool_status.items()
        }

        ms = (time.monotonic() - t0) * 1000
        self.emit_completed(ctx, metrics={
            "tool_count_total":     len(required_tools) + len(optional_tools),
            "tool_count_available": len(available),
            "tool_count_missing":   len(missing),
        }, duration_ms=ms)

        return {
            "tool_status":        tool_status_dict,
            "available_tools":    available,
            "missing_tools":      missing,
            "tool_count_total":   len(required_tools) + len(optional_tools),
            "tool_count_available": len(available),
            "tool_count_missing":   len(missing),
        }

    def _check_tool(self, runtime, tool_name: str) -> ToolHealth:
        """Check availability and version of a tool."""
        binary_path = runtime.which(tool_name)
        
        if binary_path is None:
            return ToolHealth(
                status=ToolStatus.MISSING,
                error=f"Binary '{tool_name}' not found in PATH"
            )

        # Try to get version
        version = ""
        try:
            # Most tools support --version or -version
            for version_flag in ["--version", "-version", "version"]:
                try:
                    result = runtime.run(
                        [binary_path, version_flag],
                        timeout=10
                    )
                    if result.success and result.stdout:
                        # Extract first line or first 50 chars
                        version = result.stdout.strip().split("\n")[0][:80]
                        break
                except Exception:
                    continue
        except Exception as exc:
            # Version check failed, but tool exists
            return ToolHealth(
                status=ToolStatus.INSTALLED,
                binary_path=binary_path,
                version="unknown",
                error=str(exc)[:100]
            )

        return ToolHealth(
            status=ToolStatus.INSTALLED,
            binary_path=binary_path,
            version=version
        )
