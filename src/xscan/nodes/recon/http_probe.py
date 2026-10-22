"""
http-probe node
===============
Probes in-scope assets over HTTP/S to determine which are live web services.

Uses Python httpx directly for reliability (no binary dependency for probing).
Falls back to projectdiscovery-httpx binary when available for richer metadata.

Inputs:  assets (list[dict]), target_url
Outputs: probes (list[dict]), live_urls (list[str]), live_count (int)
"""
from __future__ import annotations
import time
from typing import Any

from xscan.core.dag.node_registry import registry
from xscan.nodes.base import NodeBase, ExecutionContext
from xscan.nodes.emitter import NodeEmitter
from xscan.schemas.recon import (
    ReconAsset, HttpProbeResult, HttpProbeStatus,
)


@registry.register("http-probe")
class HttpProbeNode(NodeBase, NodeEmitter):
    node_type = "http-probe"

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        t0 = self.emit_started(ctx)

        raw_assets:  list[dict] = ctx.get("assets", [])
        target_url:  str        = ctx.get("target_url", "")
        timeout:     int        = int(ctx.config.get("timeout", 8))
        max_hosts:   int        = int(ctx.config.get("max_hosts", 100))

        # Deserialise assets
        assets: list[ReconAsset] = []
        for a in raw_assets:
            try:
                assets.append(ReconAsset(**a))
            except Exception:
                pass

        # Always include the original target
        if target_url:
            from urllib.parse import urlparse
            parsed_target = urlparse(target_url)
            orig_host = parsed_target.hostname or ""
            orig_port = parsed_target.port        # may be None
            orig_scheme = parsed_target.scheme or "http"
            if orig_host and not any(a.hostname == orig_host for a in assets):
                assets.insert(0, ReconAsset(
                    hostname=orig_host,
                    normalized_hostname=orig_host,
                    in_scope=True,
                    sources=["target"],
                ))

        # Only probe in-scope assets
        to_probe = [a for a in assets if a.in_scope][:max_hosts]

        probes: list[HttpProbeResult] = []
        import httpx

        for asset in to_probe:
            hostname = asset.hostname

            # If this asset is the original target and has a non-standard port,
            # probe only that specific scheme+port rather than guessing 80/443.
            if (target_url and orig_host and hostname == orig_host and orig_port
                    and orig_port not in (80, 443)):
                probe_url = f"{orig_scheme}://{hostname}:{orig_port}"
                try:
                    ctx.scope.assert_allowed(probe_url, operation="http_probe")
                    probe = self._probe(probe_url, hostname, timeout)
                    probes.append(probe)
                    if probe.live:
                        asset.live = True
                        asset.http_status = probe.http_status_code
                        asset.https_available = orig_scheme == "https"
                        if probe_url not in asset.urls:
                            asset.urls.append(probe_url)
                        self.emit_progress(ctx, f"  LIVE  {probe_url}  [{probe.http_status_code}]  {probe.title[:40]}")
                except Exception:
                    pass
                continue  # skip the generic scheme loop for this host

            for scheme in ("https", "http"):
                url = f"{scheme}://{hostname}"
                try:
                    ctx.scope.assert_allowed(url, operation="http_probe")
                except Exception:
                    continue

                probe = self._probe(url, hostname, timeout)
                probes.append(probe)

                if probe.live:
                    asset.live = True
                    asset.http_status = probe.http_status_code
                    if scheme == "https":
                        asset.https_available = True
                    if url not in asset.urls:
                        asset.urls.append(url)
                    self.emit_progress(ctx, f"  LIVE  {url}  [{probe.http_status_code}]  {probe.title[:40]}")
                    break
                else:
                    if scheme == "https":
                        continue

        live_count = sum(1 for p in probes if p.live)
        live_urls  = [p.url for p in probes if p.live]

        ms = (time.monotonic() - t0) * 1000
        self.emit_completed(ctx, metrics={
            "probed":     len(to_probe),
            "live":       live_count,
            "dead":       len(to_probe) - live_count,
        }, duration_ms=ms)

        # Merge updated asset data back
        updated_assets = []
        asset_map = {a.hostname: a for a in assets}
        for a in assets:
            updated_assets.append(a.model_dump(mode="json"))

        return {
            "probes":      [p.model_dump(mode="json") for p in probes],
            "live_urls":   live_urls,
            "live_count":  live_count,
            "assets":      updated_assets,   # updated with live/https flags
        }

    @staticmethod
    def _probe(url: str, hostname: str, timeout: int) -> HttpProbeResult:
        import httpx, re
        result = HttpProbeResult(url=url, hostname=hostname)
        try:
            resp = httpx.get(
                url,
                follow_redirects=True,
                timeout=timeout,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; XScan/1.0)"},
            )
            sc = resp.status_code
            result.http_status_code = sc
            result.live = True
            result.server = resp.headers.get("server", "")[:80]
            result.content_type = resp.headers.get("content-type", "")[:80]
            result.content_length = int(resp.headers.get("content-length", 0) or 0)
            result.headers = {k.lower(): v for k, v in resp.headers.items()}
            m = re.search(r'<title[^>]*>([^<]+)</title>', resp.text, re.I)
            result.title = m.group(1).strip()[:100] if m else ""
            result.https_available = url.startswith("https://")
            if sc in (301, 302, 303, 307, 308):
                result.status = HttpProbeStatus.REDIRECT
                result.redirect_location = resp.headers.get("location", "")
            elif 200 <= sc < 300:
                result.status = HttpProbeStatus.LIVE
            elif sc == 403:
                result.status = HttpProbeStatus.FORBIDDEN
            elif sc == 404:
                result.status = HttpProbeStatus.NOT_FOUND
            elif sc >= 500:
                result.status = HttpProbeStatus.SERVER_ERROR
            else:
                result.status = HttpProbeStatus.LIVE
        except httpx.ConnectError:
            result.status = HttpProbeStatus.CONNECTION_FAILED
            result.live   = False
        except httpx.TimeoutException:
            result.status = HttpProbeStatus.TIMEOUT
            result.live   = False
        except Exception as exc:
            result.status = HttpProbeStatus.UNKNOWN
            result.live   = False
        return result
