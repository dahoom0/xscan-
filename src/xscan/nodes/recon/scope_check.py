"""
scope-check node
================
Validates that the target URL is within the authorised scope before any
active work begins. Every workflow must start with this node.

Inputs:  target_url (str)
Outputs: target_url (str), scope_validated (bool), host (str)
"""
from __future__ import annotations
import time
from typing import Any
from xscan.nodes.base import NodeBase, ExecutionContext
from xscan.nodes.emitter import NodeEmitter
from xscan.core.dag.node_registry import registry


@registry.register("scope-check")
class ScopeCheckNode(NodeBase, NodeEmitter):
    node_type = "scope-check"

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        t0 = self.emit_started(ctx)

        target_url: str = ctx.get("target_url", "")
        if not target_url:
            self.emit_failed(ctx, "target_url is required")
            raise ValueError("scope-check: target_url is required in inputs")

        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        ctx.scope.assert_allowed(target_url, operation="scope-check")

        from urllib.parse import urlparse
        host = urlparse(target_url).hostname or target_url

        ms = (time.monotonic() - t0) * 1000
        self.emit_completed(ctx, metrics={"host": host}, duration_ms=ms)
        return {
            "target_url":      target_url,
            "host":            host,
            "scope_validated": True,
        }
