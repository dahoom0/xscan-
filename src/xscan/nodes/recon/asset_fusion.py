"""
asset-fusion node
=================
Merges raw hostnames from all subdomain enumeration tools into
canonical ReconAsset objects.

Rules:
  - Same hostname from N tools = ONE ReconAsset with N sources
  - Strict hostname boundary validation (prevent scope creep attacks)
  - ScopeEngine is authoritative — not substring matching
  - Out-of-scope assets are retained but flagged (not dropped)
  - Provenance (which tool found what) is always preserved

Inputs:  raw_hostnames (list[str]), subdomain_observations (list[dict]),
         target_url, host
Outputs: assets (list[dict]), assets_in_scope (int), assets_out_of_scope (int)
"""
from __future__ import annotations
import time
from typing import Any
from urllib.parse import urlparse

from xscan.core.dag.node_registry import registry
from xscan.nodes.base import NodeBase, ExecutionContext
from xscan.nodes.emitter import NodeEmitter
from xscan.schemas.recon import ReconAsset, ReconToolObservation


def _validate_scope_boundary(hostname: str, target_domain: str) -> tuple[bool, str]:
    """
    Strict hostname boundary check to prevent scope creep attacks.
    
    Examples:
      _validate_scope_boundary("api.example.com", "example.com") → (True, "subdomain")
      _validate_scope_boundary("example.com", "example.com") → (True, "exact match")
      _validate_scope_boundary("evilexample.com", "example.com") → (False, "different domain")
      _validate_scope_boundary("example.com.evil.net", "example.com") → (False, "parent domain different")
    
    Returns: (is_valid_boundary, reason_string)
    """
    if not hostname or not target_domain:
        return False, "missing hostname or target_domain"
    
    hostname_lower = hostname.lower()
    target_lower = target_domain.lower()
    
    # Exact match
    if hostname_lower == target_lower:
        return True, "exact match"
    
    # Subdomain match: hostname ends with ".target"
    if hostname_lower.endswith("." + target_lower):
        return True, f"subdomain of {target_domain}"
    
    # Any other case is out of scope
    # This prevents: evilexample.com (suffix match), example.com.evil.net (parent different), etc.
    return False, f"not a subdomain of {target_domain}"


@registry.register("asset-fusion")
class AssetFusionNode(NodeBase, NodeEmitter):
    node_type = "asset-fusion"

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        t0 = self.emit_started(ctx)

        raw_hostnames: list[str]  = ctx.get("raw_hostnames", [])
        obs_raw:       list[dict] = ctx.get("subdomain_observations", [])
        target_url:    str        = ctx.get("target_url", "")
        host:          str        = ctx.get("host", urlparse(target_url).hostname or "")

        # Rebuild tool observations for provenance
        tool_obs: list[ReconToolObservation] = []
        for o in obs_raw:
            try:
                tool_obs.append(ReconToolObservation(**o))
            except Exception:
                pass

        # Build canonical asset map: normalized_hostname -> ReconAsset
        asset_map: dict[str, ReconAsset] = {}

        for obs in tool_obs:
            for hostname in obs.results:
                norm = ReconAsset.normalise_hostname(hostname)
                if not norm:
                    continue
                if norm not in asset_map:
                    asset_map[norm] = ReconAsset(
                        hostname=norm,
                        normalized_hostname=norm,
                        root_domain=_root_domain(norm),
                    )
                asset_map[norm].add_source(obs.tool)

        # Also add hostnames that came from raw_hostnames but not tool observations
        for h in raw_hostnames:
            norm = ReconAsset.normalise_hostname(h)
            if norm and norm not in asset_map:
                asset_map[norm] = ReconAsset(
                    hostname=norm,
                    normalized_hostname=norm,
                    root_domain=_root_domain(norm),
                    sources=["direct"],
                )

        # Extract target domain from host (e.g., "www.example.com" → "example.com")
        target_domain = _root_domain(host) if host else ""

        # Apply ScopeEngine — it is authoritative
        # Also apply strict hostname boundary validation
        in_scope = 0
        out_of_scope = 0
        for norm, asset in asset_map.items():
            # First: strict boundary check (prevent scope creep attacks)
            is_valid_boundary, boundary_reason = _validate_scope_boundary(norm, target_domain)
            
            # Second: ScopeEngine check (allows fine-grained policy control)
            test_url = f"https://{norm}"
            scope_allowed = ctx.scope.is_allowed(test_url)

            # Asset is in-scope only if BOTH boundary check AND scope engine allow it
            if is_valid_boundary and scope_allowed:
                asset.in_scope = True
                asset.scope_reason = f"{boundary_reason}; allowed_by_scope"
                in_scope += 1
            else:
                asset.in_scope = False
                if not is_valid_boundary:
                    asset.scope_reason = f"boundary_violation: {boundary_reason}"
                elif not scope_allowed:
                    asset.scope_reason = "denied_by_scope"
                else:
                    asset.scope_reason = "unknown_reason"
                out_of_scope += 1

        assets = list(asset_map.values())

        ms = (time.monotonic() - t0) * 1000
        self.emit_completed(ctx, metrics={
            "assets_total":       len(assets),
            "assets_in_scope":    in_scope,
            "assets_out_of_scope": out_of_scope,
        }, duration_ms=ms)

        return {
            "assets":              [a.model_dump(mode="json") for a in assets],
            "assets_in_scope":    in_scope,
            "assets_out_of_scope": out_of_scope,
            "asset_count":        len(assets),
        }


def _root_domain(hostname: str) -> str:
    """Extract root domain from hostname (simple heuristic)."""
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname
