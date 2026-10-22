"""
subdomain-enum node
====================
Runs Subfinder, Assetfinder, and Amass in parallel (via DAG waves)
to enumerate subdomains of the target domain.

Each tool runs independently and produces a ReconToolObservation.
Results are NOT deduplicated here — that is asset-fusion's job.

Inputs:  target_url, host
Outputs: subdomain_observations (list[dict])
         raw_hostnames          (list[str])   — all discovered, pre-dedup
"""
from __future__ import annotations
import time
from typing import Any

from xscan.core.dag.node_registry import registry
from xscan.nodes.base import NodeBase, ExecutionContext
from xscan.nodes.emitter import NodeEmitter
from xscan.runtime.resolver import get_runtime
from xscan.schemas.recon import ReconToolStatus


def _run_tool(adapter_cls, target: str, ctx: ExecutionContext, **kwargs):
    from xscan.schemas.recon import ReconToolStatus
    try:
        runtime  = get_runtime()
        adapter  = adapter_cls(runtime)
        obs      = adapter.run(target, **kwargs)
        return obs
    except Exception as exc:
        from xscan.schemas.recon import ReconToolObservation
        obs = ReconToolObservation(
            tool=adapter_cls.tool_name if hasattr(adapter_cls, "tool_name") else "unknown",
            target=target,
            status=ReconToolStatus.EXECUTION_FAILED,
            observation=str(exc)[:200],
        )
        return obs


@registry.register("subdomain-enum")
class SubdomainEnumNode(NodeBase, NodeEmitter):
    node_type = "subdomain-enum"

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        t0 = self.emit_started(ctx)

        target_url: str  = ctx.get("target_url", "")
        host:       str  = ctx.get("host", "")
        target = host or target_url

        passive_only: bool = ctx.config.get("passive_only", False)
        tools_cfg:    list[str] = ctx.config.get("tools", ["subfinder", "assetfinder"])

        from xscan.tools.adapters.subfinder    import SubfinderAdapter
        from xscan.tools.adapters.assetfinder  import AssetfinderAdapter
        from xscan.tools.adapters.amass        import AmassAdapter

        TOOL_MAP = {
            "subfinder":   SubfinderAdapter,
            "assetfinder": AssetfinderAdapter,
            "amass":       AmassAdapter,
        }

        observations = []
        all_hostnames: list[str] = []

        for tool_name in tools_cfg:
            adapter_cls = TOOL_MAP.get(tool_name)
            if not adapter_cls:
                self.emit_warning(ctx, f"Unknown subdomain tool: {tool_name}")
                continue

            self.emit_progress(ctx, f"Running {tool_name} against {target[:60]}")
            kwargs: dict[str, Any] = {}
            if tool_name == "amass" and passive_only:
                kwargs["passive"] = True

            obs = _run_tool(adapter_cls, target, ctx, **kwargs)
            observations.append(obs.model_dump(mode="json"))

            if obs.has_results:
                all_hostnames.extend(obs.results)
                self.emit_progress(ctx, f"  {tool_name}: {len(obs.results)} hostnames")
            else:
                self.emit_progress(ctx, f"  {tool_name}: {obs.status}  {obs.observation[:80]}")

        # Also include the original host
        if host and host not in all_hostnames:
            all_hostnames.append(host)

        ms = (time.monotonic() - t0) * 1000
        self.emit_completed(ctx, metrics={
            "tools_run":    len(observations),
            "raw_hostnames": len(all_hostnames),
        }, duration_ms=ms)

        return {
            "subdomain_observations": observations,
            "raw_hostnames":          list(dict.fromkeys(all_hostnames)),
        }
