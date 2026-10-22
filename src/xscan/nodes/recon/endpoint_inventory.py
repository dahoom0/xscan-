"""
endpoint-inventory node
========================
Merges URLs from crawler, FFUF, HTTP probes, and JS discovery
into canonical Endpoint objects.

Same URL from multiple sources → ONE Endpoint with multiple sources.

Inputs:  urls (crawler), discovered_paths (ffuf), live_urls (probes),
         target_url
Outputs: endpoints (list[dict]), endpoint_urls (list[str]),
         endpoint_count (int)
"""
from __future__ import annotations
import time
from typing import Any
from urllib.parse import urlparse

from xscan.core.dag.node_registry import registry
from xscan.nodes.base import NodeBase, ExecutionContext
from xscan.nodes.emitter import NodeEmitter
from xscan.schemas.recon import Endpoint


@registry.register("endpoint-inventory")
class EndpointInventoryNode(NodeBase, NodeEmitter):
    node_type = "endpoint-inventory"

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        t0 = self.emit_started(ctx)

        crawler_urls:   list[str]  = ctx.get("urls", [])
        ffuf_paths:     list[dict] = ctx.get("discovered_paths", [])
        live_urls:      list[str]  = ctx.get("live_urls", [])
        target_url:     str        = ctx.get("target_url", "")

        # canonical map: normalized_url -> Endpoint
        inventory: dict[str, Endpoint] = {}

        def _add(url: str, source: str) -> None:
            norm = _normalize_url(url)
            if not norm:
                return
            # Scope check
            try:
                ctx.scope.assert_allowed(norm, operation="endpoint_inventory")
            except Exception:
                return
            if norm not in inventory:
                parsed = urlparse(norm)
                # Extract parameter *names* only (not key=value pairs)
                params: list[str] = []
                if parsed.query:
                    for part in parsed.query.split("&"):
                        if "=" in part:
                            params.append(part.split("=", 1)[0])
                        elif part:
                            params.append(part)
                inventory[norm] = Endpoint(
                    url=norm,
                    hostname=parsed.hostname or "",
                    path=parsed.path,
                    parameters=params,
                    in_scope=True,
                )
            inventory[norm].add_source(source)

        # Add from all sources
        for u in crawler_urls:
            _add(u, "crawler")
        for p in ffuf_paths:
            _add(p.get("url", ""), "ffuf")
        for u in live_urls:
            _add(u, "probe")
        if target_url:
            _add(target_url, "target")

        endpoints = list(inventory.values())

        ms = (time.monotonic() - t0) * 1000
        self.emit_completed(ctx, metrics={
            "endpoints":  len(endpoints),
            "from_crawler": sum(1 for e in endpoints if "crawler" in e.sources),
            "from_ffuf":    sum(1 for e in endpoints if "ffuf" in e.sources),
        }, duration_ms=ms)

        return {
            "endpoints":      [e.model_dump(mode="json") for e in endpoints],
            "endpoint_urls":  [e.url for e in endpoints],
            "endpoint_count": len(endpoints),
        }


def _normalize_url(url: str) -> str:
    """Strip fragment, normalise scheme."""
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    return parsed._replace(fragment="").geturl()
