"""
ProjectDiscovery httpx adapter — HTTP probing of hostnames.
Note: This adapter uses the projectdiscovery-httpx binary,
      NOT the Python httpx package. See ToolRegistry for distinction.
"""
from __future__ import annotations
import json
import re
from datetime import datetime, UTC

from xscan.runtime.base import ExecutionRuntime
from xscan.schemas.recon import (
    HttpProbeResult, HttpProbeStatus, ReconToolObservation, ReconToolStatus
)


class HttpxProbeAdapter:
    """
    Runs projectdiscovery httpx against a list of hostnames.
    Returns a list of HttpProbeResult, one per hostname.
    """

    tool_name = "projectdiscovery-httpx"
    default_timeout = 60

    def __init__(self, runtime: ExecutionRuntime) -> None:
        self._runtime = runtime

    def probe_list(
        self,
        hostnames: list[str],
        timeout: int = 10,
        threads: int = 25,
    ) -> tuple[list[HttpProbeResult], ReconToolObservation]:
        """
        Probe multiple hostnames. Returns (results, observation).
        """
        obs = ReconToolObservation(
            tool=self.tool_name,
            capability="http_probe",
            target=f"{len(hostnames)} hostnames",
        )
        t0 = datetime.now(UTC)

        binary = self._runtime.which("httpx")
        if not binary:
            obs.status = ReconToolStatus.TOOL_UNAVAILABLE
            obs.observation = "projectdiscovery httpx binary not found"
            obs.finished_at = datetime.now(UTC)
            return [], obs

        # httpx accepts hostnames via stdin — pipe them
        input_data = "\n".join(hostnames)

        # Build command
        cmd = [
            "httpx",
            "-json",
            "-silent",
            f"-timeout", str(timeout),
            f"-threads", str(threads),
            "-title",
            "-tech-detect",
            "-status-code",
            "-content-length",
            "-server",
        ]

        # For runtime that supports stdin, use a temp approach
        result = self._runtime.run(
            cmd + ["-l", "/dev/stdin"],
            timeout=self.default_timeout,
        )
        # Fallback: pass each host individually if stdin not supported
        if result.exit_code != 0 or not result.stdout.strip():
            results = []
            for hostname in hostnames[:50]:  # cap to prevent enormous scans
                r = self._probe_single(hostname, timeout)
                results.append(r)
            obs.status = ReconToolStatus.COMPLETED_WITH_RESULTS if results else ReconToolStatus.COMPLETED_NO_RESULTS
            obs.results = [r.url for r in results if r.live]
            obs.duration_ms = (datetime.now(UTC) - t0).total_seconds() * 1000
            obs.finished_at = datetime.now(UTC)
            return results, obs

        results = self._parse_json_output(result.stdout)
        obs.status = ReconToolStatus.COMPLETED_WITH_RESULTS if results else ReconToolStatus.COMPLETED_NO_RESULTS
        obs.results = [r.url for r in results if r.live]
        obs.raw_output = result.stdout[:2000]
        obs.duration_ms = (datetime.now(UTC) - t0).total_seconds() * 1000
        obs.finished_at = datetime.now(UTC)
        return results, obs

    def _probe_single(self, hostname: str, timeout: int = 10) -> HttpProbeResult:
        """Probe one hostname directly via Python httpx (fallback)."""
        import httpx as _httpx
        result = HttpProbeResult(url=f"https://{hostname}", hostname=hostname)
        try:
            resp = _httpx.get(
                f"https://{hostname}",
                follow_redirects=True,
                timeout=timeout,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; XScan/1.0)"},
            )
            result.http_status_code = resp.status_code
            result.live = True
            result.https_available = True
            result.server = resp.headers.get("server", "")
            result.content_type = resp.headers.get("content-type", "")
            result.content_length = len(resp.content)
            # Extract title
            import re as _re
            m = _re.search(r'<title[^>]*>([^<]+)</title>', resp.text, _re.I)
            result.title = m.group(1).strip()[:100] if m else ""
            result.status = HttpProbeStatus.LIVE
            if resp.status_code in (301, 302, 303, 307, 308):
                result.redirect_location = resp.headers.get("location", "")
                result.status = HttpProbeStatus.REDIRECT
        except _httpx.ConnectError:
            result.status = HttpProbeStatus.CONNECTION_FAILED
        except _httpx.TimeoutException:
            result.status = HttpProbeStatus.TIMEOUT
        except Exception:
            result.status = HttpProbeStatus.UNKNOWN
        return result

    @staticmethod
    def _parse_json_output(stdout: str) -> list[HttpProbeResult]:
        results = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = data.get("url", data.get("input", ""))
            if not url:
                continue
            sc = data.get("status-code", data.get("status_code", 0))
            probe = HttpProbeResult(
                url=url,
                hostname=data.get("host", ""),
                http_status_code=sc,
                title=data.get("title", "")[:100],
                server=data.get("webserver", ""),
                content_length=data.get("content-length"),
                technologies=data.get("tech", []),
                live=200 <= sc < 500 if sc else False,
            )
            if sc in (301, 302, 303, 307, 308):
                probe.status = HttpProbeStatus.REDIRECT
                probe.redirect_location = data.get("location", "")
            elif 200 <= sc < 300:
                probe.status = HttpProbeStatus.LIVE
            elif sc == 403:
                probe.status = HttpProbeStatus.FORBIDDEN
            elif sc == 404:
                probe.status = HttpProbeStatus.NOT_FOUND
            elif sc >= 500:
                probe.status = HttpProbeStatus.SERVER_ERROR
            results.append(probe)
        return results
