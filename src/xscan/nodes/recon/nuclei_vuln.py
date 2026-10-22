"""
nuclei-vuln node
================
Runs Nuclei vulnerability scanner against discovered hosts using template tags.

Supports vulnerability categories:
  cve, exposure, panel, misconfiguration, vuln, xss, wordpress, lfi, tech, default-login, kev

Policy controls:
  tags (which templates to run), rate_limit, severity_filter

Inputs:  live_urls (list[str]), target_url
Outputs: vulnerabilities (list[dict]), vuln_count (int), severity_breakdown (dict)
"""
from __future__ import annotations
import json
import time
from typing import Any

from xscan.core.dag.node_registry import registry
from xscan.nodes.base import NodeBase, ExecutionContext
from xscan.nodes.emitter import NodeEmitter
from xscan.runtime.resolver import get_runtime
from xscan.schemas.recon import ReconToolStatus


# Predefined Nuclei template tag categories
NUCLEI_CATEGORIES = {
    "cve": "Known vulnerabilities associated with CVE identifiers",
    "exposure": "Exposed files, credentials, configuration data, and sensitive information",
    "panel": "Admin panels and exposed management interfaces",
    "misconfiguration": "Insecure server and application configurations",
    "vuln": "General vulnerability checks",
    "xss": "Cross-site scripting detection templates",
    "wordpress": "WordPress core, plugin, and theme security issues",
    "lfi": "Local file inclusion vulnerability checks",
    "tech": "Technology and service identification",
    "default-login": "Checks for known default credentials",
    "kev": "Known exploited vulnerabilities",
}


@registry.register("nuclei-vuln")
class NucleiVulnNode(NodeBase, NodeEmitter):
    node_type = "nuclei-vuln"

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        t0 = self.emit_started(ctx)

        live_urls: list[str] = ctx.get("live_urls", [])
        target_url: str = ctx.get("target_url", "")
        
        # Configuration
        tags: list[str] = ctx.config.get("tags", ["cve", "misconfiguration", "exposure"])
        rate_limit: int = int(ctx.config.get("rate_limit", 5))
        severity: list[str] = ctx.config.get("severity", ["critical", "high", "medium"])
        enabled: bool = bool(ctx.config.get("enabled", True))

        if not enabled:
            self.emit_progress(ctx, "Nuclei vulnerability scanning disabled")
            ms = (time.monotonic() - t0) * 1000
            self.emit_completed(ctx, metrics={"vulns": 0, "disabled": True}, duration_ms=ms)
            return {
                "vulnerabilities": [],
                "vuln_count": 0,
                "severity_breakdown": {},
                "nuclei_observations": [],
            }

        if not live_urls:
            self.emit_progress(ctx, "No live URLs to scan — skipping Nuclei scanning")
            ms = (time.monotonic() - t0) * 1000
            self.emit_completed(ctx, metrics={"vulns": 0}, duration_ms=ms)
            return {
                "vulnerabilities": [],
                "vuln_count": 0,
                "severity_breakdown": {},
                "nuclei_observations": [],
            }

        # Validate tags
        invalid_tags = [t for t in tags if t not in NUCLEI_CATEGORIES]
        if invalid_tags:
            self.emit_warning(ctx, f"Unknown Nuclei tags: {invalid_tags}")
            tags = [t for t in tags if t in NUCLEI_CATEGORIES]
            if not tags:
                self.emit_warning(ctx, "No valid Nuclei tags specified — skipping scan")
                ms = (time.monotonic() - t0) * 1000
                self.emit_completed(ctx, metrics={"vulns": 0}, duration_ms=ms)
                return {
                    "vulnerabilities": [],
                    "vuln_count": 0,
                    "severity_breakdown": {},
                    "nuclei_observations": [],
                }

        self.emit_progress(ctx, f"Running Nuclei scan with tags: {', '.join(tags)}")
        self.emit_progress(ctx, f"Rate limit: {rate_limit} req/s | Severity filter: {', '.join(severity)}")

        from xscan.tools.adapters.nuclei import NucleiAdapter

        runtime = get_runtime()
        adapter = NucleiAdapter(runtime)

        all_vulns: list[dict] = []
        observations: list[dict] = []

        # Scope-check all URLs first
        urls_to_scan = []
        for url in live_urls[:20]:  # limit to first 20 hosts
            try:
                ctx.scope.assert_allowed(url, operation="nuclei_scan")
                urls_to_scan.append(url)
            except Exception as e:
                self.emit_warning(ctx, f"Scope blocked: {url[:60]}")
                continue

        if not urls_to_scan:
            self.emit_warning(ctx, "No URLs passed scope validation")
            ms = (time.monotonic() - t0) * 1000
            self.emit_completed(ctx, metrics={"vulns": 0}, duration_ms=ms)
            return {
                "vulnerabilities": [],
                "vuln_count": 0,
                "severity_breakdown": {},
                "nuclei_observations": [],
            }

        # Run Nuclei scan
        try:
            vulns, obs = adapter.scan(
                urls=urls_to_scan,
                tags=tags,
                severity_filter=severity,
                rate_limit=rate_limit,
            )
            observations.append(obs.model_dump(mode="json"))

            if obs.status == ReconToolStatus.TOOL_UNAVAILABLE:
                self.emit_warning(
                    ctx,
                    "nuclei not installed — install with: xscan install nuclei",
                )
                ms = (time.monotonic() - t0) * 1000
                self.emit_completed(ctx, metrics={"vulns": 0}, duration_ms=ms)
                return {
                    "vulnerabilities": [],
                    "vuln_count": 0,
                    "severity_breakdown": {},
                    "nuclei_observations": observations,
                }

            all_vulns.extend(vulns)
        except Exception as e:
            self.emit_warning(ctx, f"Nuclei scan error: {e}")
            ms = (time.monotonic() - t0) * 1000
            self.emit_completed(ctx, metrics={"vulns": 0, "error": str(e)}, duration_ms=ms)
            return {
                "vulnerabilities": [],
                "vuln_count": 0,
                "severity_breakdown": {},
                "nuclei_observations": observations,
            }

        # Breakdown by severity
        severity_breakdown: dict[str, int] = {}
        for vuln in all_vulns:
            sev = vuln.get("severity", "info")
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

        self.emit_progress(ctx, f"Found {len(all_vulns)} vulnerabilities")
        for sev, count in severity_breakdown.items():
            self.emit_progress(ctx, f"  {sev}: {count}")

        ms = (time.monotonic() - t0) * 1000
        self.emit_completed(
            ctx,
            metrics={
                "vulns": len(all_vulns),
                "urls_scanned": len(urls_to_scan),
                **severity_breakdown,
            },
            duration_ms=ms,
        )

        return {
            "vulnerabilities": all_vulns,
            "vuln_count": len(all_vulns),
            "severity_breakdown": severity_breakdown,
            "nuclei_observations": observations,
            "tags_used": tags,
            "urls_scanned": len(urls_to_scan),
        }
