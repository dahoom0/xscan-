"""
dom-source-sink-event node — Phase D
======================================
Runs source, sink, and event detection across all JS files in one pass.
Registered as three logical outputs: sources, sinks, events.

Inputs:  js_files (list[dict])
Outputs: dom_sources (list[dict])
         dom_sinks   (list[dict])
         dom_events  (list[dict])
"""
from __future__ import annotations
import time
from typing import Any

from xscan.core.dag.node_registry import registry
from xscan.nodes.base import NodeBase, ExecutionContext
from xscan.nodes.emitter import NodeEmitter
from xscan.nodes.dom.sources import detect_sources
from xscan.nodes.dom.sinks   import detect_sinks
from xscan.nodes.dom.events  import detect_events


@registry.register("dom-source-sink-event")
class DomSourceSinkEventNode(NodeBase, NodeEmitter):
    node_type = "dom-source-sink-event"

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        t0 = self.emit_started(ctx)

        js_files: list[dict] = ctx.get("js_files", [])

        all_sources = []
        all_sinks   = []
        all_events  = []

        for js_file in js_files:
            url     = js_file.get("url", "")
            content = js_file.get("content", "")
            all_sources.extend(o.model_dump(mode="json") for o in detect_sources(content, url))
            all_sinks.extend(  o.model_dump(mode="json") for o in detect_sinks(content, url))
            all_events.extend( o.model_dump(mode="json") for o in detect_events(content, url))

        ms = (time.monotonic() - t0) * 1000
        self.emit_completed(ctx, metrics={
            "dom_sources": len(all_sources),
            "dom_sinks":   len(all_sinks),
            "dom_events":  len(all_events),
        }, duration_ms=ms)

        return {
            "dom_sources": all_sources,
            "dom_sinks":   all_sinks,
            "dom_events":  all_events,
        }
