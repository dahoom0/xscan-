"""
taint-graph-builder node — Phase E
====================================
Constructs TaintGraph from dom_sources, dom_sinks, dom_events.
Produces taint_paths for downstream candidate generation.

Inputs:  target_url, dom_sources, dom_sinks, dom_events, ast_records
Outputs: taint_paths (list[dict])
         taint_path_count (int)
         analysis_incomplete (bool)
"""
from __future__ import annotations
import time
from typing import Any

from xscan.core.dag.node_registry import registry
from xscan.evidence.taint import TaintGraph
from xscan.nodes.base import NodeBase, ExecutionContext
from xscan.nodes.emitter import NodeEmitter
from xscan.schemas.xss import (
    DOMSourceObservation, DOMSinkObservation, DOMEventObservation,
)


@registry.register("taint-graph-builder")
class TaintGraphBuilderNode(NodeBase, NodeEmitter):
    node_type = "taint-graph-builder"

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        t0 = self.emit_started(ctx)

        target_url   = ctx.get("target_url", "")
        raw_sources  = ctx.get("dom_sources",  [])
        raw_sinks    = ctx.get("dom_sinks",    [])
        raw_events   = ctx.get("dom_events",   [])
        ast_records  = ctx.get("ast_records",  [])

        max_paths    = int(ctx.config.get("max_paths",  20))
        max_nodes    = int(ctx.config.get("max_nodes",  500))
        max_depth    = int(ctx.config.get("max_depth",  8))

        # Deserialise
        sources = [DOMSourceObservation(**s) for s in raw_sources]
        sinks   = [DOMSinkObservation(**s)   for s in raw_sinks]
        events  = [DOMEventObservation(**e)  for e in raw_events]

        tg = TaintGraph(
            target_url=target_url,
            max_paths=max_paths,
            max_nodes=max_nodes,
            max_depth=max_depth,
        )
        tg.build(sources, sinks, events, ast_records)

        # Log paths
        for path in tg.paths:
            self.emit_progress(
                ctx,
                f"  Taint path: {path.source_label} -> {path.sink_label_str}"
                f"  depth={path.depth}  payloads={len(path.payloads)}",
            )

        ms = (time.monotonic() - t0) * 1000
        self.emit_completed(ctx, metrics={
            "taint_paths":          len(tg.paths),
            "analysis_incomplete":  int(tg.analysis_incomplete),
        }, duration_ms=ms)

        return {
            "taint_paths":          tg.to_dict_list(),
            "taint_path_count":     len(tg.paths),
            "analysis_incomplete":  tg.analysis_incomplete,
        }
