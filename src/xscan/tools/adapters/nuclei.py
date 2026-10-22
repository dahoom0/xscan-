"""
nuclei adapter
==============
Adapter for ProjectDiscovery's Nuclei vulnerability scanner.

Runs Nuclei with specified template tags and severity filters.
Parses JSON output and returns structured vulnerability results.
"""
from __future__ import annotations
import json
import subprocess
from typing import Any

from xscan.schemas.recon import ReconToolStatus, ReconToolObservation
from xscan.runtime.resolver import Runtime


class NucleiAdapter:
    """Adapter for Nuclei vulnerability scanner."""

    def __init__(self, runtime: Runtime):
        self.runtime = runtime

    def scan(
        self,
        urls: list[str],
        tags: list[str],
        severity_filter: list[str] | None = None,
        rate_limit: int = 5,
    ) -> tuple[list[dict], ReconToolObservation]:
        """
        Run Nuclei vulnerability scan.

        Args:
            urls: List of target URLs to scan
            tags: Nuclei template tags (e.g., ["cve", "exposure"])
            severity_filter: Filter results by severity (e.g., ["critical", "high"])
            rate_limit: Request rate limit per second

        Returns:
            (list of vulnerability dicts, ReconToolObservation)
        """
        obs = ReconToolObservation(tool="nuclei", results=[])

        if not urls:
            obs.status = ReconToolStatus.COMPLETED
            return [], obs

        # Build Nuclei command
        try:
            cmd = ["nuclei", "-json"]

            # Add URLs
            for url in urls:
                cmd.extend(["-u", url])

            # Add tags
            if tags:
                cmd.extend(["-tags", ",".join(tags)])

            # Add severity filter
            if severity_filter:
                cmd.extend(["-severity", ",".join(severity_filter)])

            # Add rate limit
            cmd.extend(["-rl", str(rate_limit)])

            # Run scan
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout
            )

            vulns = []

            # Parse JSON output (one JSON object per line)
            if result.stdout:
                for line in result.stdout.strip().split("\n"):
                    if not line:
                        continue
                    try:
                        vuln_data = json.loads(line)
                        vulns.append(vuln_data)
                        obs.results.append(vuln_data.get("template", "unknown"))
                    except json.JSONDecodeError:
                        pass

            obs.status = ReconToolStatus.COMPLETED
            return vulns, obs

        except FileNotFoundError:
            obs.status = ReconToolStatus.TOOL_UNAVAILABLE
            obs.error = "nuclei not found in PATH"
            return [], obs

        except subprocess.TimeoutExpired:
            obs.status = ReconToolStatus.TIMEOUT
            obs.error = "Nuclei scan timeout after 10 minutes"
            return [], obs

        except Exception as e:
            obs.status = ReconToolStatus.ERROR
            obs.error = str(e)
            return [], obs
