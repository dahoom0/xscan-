"""
directory-discovery node
=========================
Runs FFUF against each live web service to discover paths/endpoints.

Policy controls:
  max_requests, rate_limit, wordlist — never from LLM output.
  Each URL passes ScopeEngine before FFUF runs.

Inputs:  live_urls (list[str]), assets (list[dict])
Outputs: discovered_paths (list[dict]), path_count (int)
"""
from __future__ import annotations
import time
from typing import Any

from xscan.core.dag.node_registry import registry
from xscan.nodes.base import NodeBase, ExecutionContext
from xscan.nodes.emitter import NodeEmitter
from xscan.runtime.resolver import get_runtime
from xscan.schemas.recon import DiscoveredPath, ReconToolStatus


@registry.register("directory-discovery")
class DirectoryDiscoveryNode(NodeBase, NodeEmitter):
    node_type = "directory-discovery"

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        t0 = self.emit_started(ctx)

        live_urls:    list[str]  = ctx.get("live_urls", [])
        endpoint_count: int      = ctx.get("endpoint_count", 0)
        wordlist:     str | None = ctx.config.get("wordlist")
        max_hosts:    int        = int(ctx.config.get("max_hosts", 10))
        max_requests: int        = int(ctx.config.get("max_requests", 500))
        rate_limit:   int        = int(ctx.config.get("rate_limit", 30))
        extensions:   list[str]  = ctx.config.get("extensions", [])
        skip_if_endpoints: bool  = bool(ctx.config.get("skip_if_endpoints", True))

        if not live_urls:
            self.emit_progress(ctx, "No live URLs to scan — skipping directory discovery")
            ms = (time.monotonic() - t0) * 1000
            self.emit_completed(ctx, metrics={"paths": 0}, duration_ms=ms)
            return {"discovered_paths": [], "path_count": 0, "ffuf_observations": []}

        # Skip ffuf if endpoints already discovered (unless explicitly configured)
        if skip_if_endpoints and endpoint_count > 0:
            self.emit_progress(ctx, f"Endpoints already discovered ({endpoint_count}) — skipping directory discovery")
            ms = (time.monotonic() - t0) * 1000
            self.emit_completed(ctx, metrics={"paths": 0, "skipped": True}, duration_ms=ms)
            return {"discovered_paths": [], "path_count": 0, "ffuf_observations": []}

        from xscan.tools.adapters.ffuf import FfufAdapter
        runtime = get_runtime()
        adapter = FfufAdapter(runtime)

        all_paths: list[DiscoveredPath] = []
        observations: list[dict] = []

        for url in live_urls[:max_hosts]:
            try:
                ctx.scope.assert_allowed(url, operation="directory_discovery")
            except Exception as e:
                self.emit_warning(ctx, f"  Scope blocked: {url[:60]}  {e}")
                continue

            self.emit_progress(ctx, f"  FFUF: {url[:70]}")
            paths, obs = adapter.discover(
                base_url=url,
                wordlist_path=wordlist,
                extensions=extensions,
                max_requests=max_requests,
                rate_limit=rate_limit,
            )
            observations.append(obs.model_dump(mode="json"))

            if obs.status == ReconToolStatus.TOOL_UNAVAILABLE:
                self.emit_warning(ctx, f"  ffuf not installed — install with: xscan install ffuf")
                break

            all_paths.extend(paths)
            self.emit_progress(ctx, f"    {obs.status}  {len(paths)} paths")

        ms = (time.monotonic() - t0) * 1000
        self.emit_completed(ctx, metrics={
            "hosts_scanned": min(len(live_urls), max_hosts),
            "paths":         len(all_paths),
        }, duration_ms=ms)

        return {
            "discovered_paths": [p.model_dump(mode="json") for p in all_paths],
            "path_count":       len(all_paths),
            "ffuf_observations": observations,
        }
