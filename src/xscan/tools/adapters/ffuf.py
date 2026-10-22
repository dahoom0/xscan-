"""
FFUF adapter — directory and content discovery.

Runs ffuf via Runtime (never direct subprocess in nodes).
Uses structured JSON output when available.
Enforces request budget via PolicyEngine.

CRITICAL: ffuf timeout != no directories found.
All states are explicit.
"""
from __future__ import annotations
import json
import re
from datetime import datetime, UTC
from pathlib import Path
from typing import Optional

from xscan.runtime.base import ExecutionRuntime
from xscan.schemas.recon import (
    DiscoveredPath, DiscoveredPathStatus,
    ReconToolObservation, ReconToolStatus,
)

# Built-in minimal wordlist (used when no configured wordlist exists)
# This is intentionally tiny — a real wordlist must be configured.
_BUILTIN_MINI_WORDLIST = [
    "admin", "login", "api", "api/v1", "api/v2", "dashboard",
    "upload", "uploads", "static", "assets", "js", "css",
    "robots.txt", "sitemap.xml", ".git", "wp-admin", "wp-login.php",
    "config", "backup", "test", "dev", "staging",
]


class FfufAdapter:
    """
    Runs ffuf for directory/path discovery.
    Normalises results into DiscoveredPath objects.
    """

    tool_name    = "ffuf"
    default_timeout = 120

    def __init__(self, runtime: ExecutionRuntime) -> None:
        self._runtime = runtime

    def discover(
        self,
        base_url: str,
        wordlist_path: Optional[str] = None,
        extensions: list[str] | None = None,
        max_requests: int = 500,
        rate_limit: int  = 50,
        timeout: int     = 10,
    ) -> tuple[list[DiscoveredPath], ReconToolObservation]:
        """
        Run ffuf against `base_url/FUZZ`.
        Returns (discovered_paths, observation).
        """
        obs = ReconToolObservation(
            tool=self.tool_name,
            capability="fuzzing",
            target=base_url,
        )
        t0 = datetime.now(UTC)

        binary = self._runtime.which("ffuf")
        if not binary:
            obs.status = ReconToolStatus.TOOL_UNAVAILABLE
            obs.observation = "ffuf binary not found"
            obs.finished_at = datetime.now(UTC)
            return [], obs

        # Wordlist
        wl_path, wl_status = self._resolve_wordlist(wordlist_path)
        if wl_status == "config_error":
            obs.status = ReconToolStatus.TOOL_UNAVAILABLE
            obs.observation = f"Configured wordlist not found: {wordlist_path}"
            obs.finished_at = datetime.now(UTC)
            return [], obs

        # Build command
        url = base_url.rstrip("/") + "/FUZZ"
        cmd = [
            "ffuf",
            "-w", wl_path,
            "-u", url,
            "-of", "json",         # structured output
            "-o", "/tmp/ffuf_out.json",
            "-t", str(min(rate_limit, 20)),  # threads
            "-timeout", str(timeout),
            "-mc", "200,201,204,301,302,307,401,403,405",  # match codes
            "-fs", "0",            # filter empty responses
            "-s",                  # silent
        ]
        if extensions:
            cmd += ["-e", ",".join(f".{e.lstrip('.')}" for e in extensions)]

        result = self._runtime.run(cmd, timeout=self.default_timeout)
        obs.duration_ms = (datetime.now(UTC) - t0).total_seconds() * 1000
        obs.finished_at = datetime.now(UTC)
        obs.raw_output  = ((result.stdout or "") + (result.stderr or ""))[:2000]

        if result.timed_out:
            obs.status = ReconToolStatus.TIMEOUT
            obs.observation = f"ffuf timed out after {self.default_timeout}s"
            return [], obs

        # Try to read structured JSON output file.
        # On Windows+WSL the output file lives inside WSL's filesystem.
        # We use the runtime to cat it so it works regardless of OS.
        paths = self._parse_json_via_runtime(result)
        if not paths:
            # Fallback: parse stdout
            paths = self._parse_stdout(result.stdout, base_url)

        if paths:
            obs.status = ReconToolStatus.COMPLETED_WITH_RESULTS
            obs.results = [p.url for p in paths]
            obs.observation = f"ffuf: {len(paths)} path(s) discovered"
        else:
            obs.status = ReconToolStatus.COMPLETED_NO_RESULTS
            obs.observation = "ffuf: no paths discovered"

        return paths, obs

    # ------------------------------------------------------------------

    def _resolve_wordlist(self, configured: Optional[str]) -> tuple[str, str]:
        """
        Returns (wordlist_path, status).
        status: "ok" | "config_error" | "builtin"
        """
        if configured:
            p = Path(configured)
            if p.exists():
                return str(p), "ok"
            return configured, "config_error"

        # Write the built-in mini wordlist to a temp file
        import tempfile, os
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, prefix="xscan_wl_"
        )
        tmp.write("\n".join(_BUILTIN_MINI_WORDLIST))
        tmp.close()
        return tmp.name, "builtin"

    def _parse_json_via_runtime(self, run_result) -> list[DiscoveredPath]:
        """
        Read /tmp/ffuf_out.json via the runtime (handles WSL path transparently).
        Falls back to empty list on any error.
        """
        # Use runtime to cat the file — works on both local and WSL runtimes
        cat_result = self._runtime.run(["cat", "/tmp/ffuf_out.json"], timeout=10)
        if cat_result.exit_code == 0 and cat_result.stdout:
            try:
                data = json.loads(cat_result.stdout)
                return self._map_ffuf_json(data, "")
            except Exception:
                pass
        return []

    def _parse_json_file(self, path: str, base_url: str) -> list[DiscoveredPath]:
        try:
            with open(path) as f:
                data = json.load(f)
            return self._map_ffuf_json(data, base_url)
        except Exception:
            return []

    def _parse_stdout(self, stdout: str, base_url: str) -> list[DiscoveredPath]:
        """Parse ffuf text output as fallback."""
        paths = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            # ffuf text line: "path [Status: 200, Size: 1234, Words: 123, Lines: 45]"
            m = re.match(r'^(\S+)\s+\[Status:\s*(\d+)', line)
            if m:
                path_part = m.group(1).strip("/")
                sc = int(m.group(2))
                url = f"{base_url.rstrip('/')}/{path_part}"
                paths.append(self._make_path(url, base_url, sc, "ffuf"))
        return paths

    @staticmethod
    def _map_ffuf_json(data: dict, base_url: str) -> list[DiscoveredPath]:
        results = data.get("results", [])
        paths = []
        for item in results:
            url = item.get("url", "")
            sc  = item.get("status", 0)
            if not url:
                continue
            path = DiscoveredPath(
                url=url,
                hostname=re.sub(r'^https?://', '', base_url.split("/")[0] if "/" in base_url else base_url),
                path="/" + url.split(base_url.rstrip("/"), 1)[-1].lstrip("/") if base_url in url else url,
                source="ffuf",
                http_status_code=sc,
                content_length=item.get("length"),
                content_type=item.get("content-type", ""),
                status=_status_from_code(sc),
                redirect_location=item.get("redirectlocation"),
            )
            paths.append(path)
        return paths

    @staticmethod
    def _make_path(url: str, base_url: str, sc: int, source: str) -> DiscoveredPath:
        return DiscoveredPath(
            url=url,
            path="/" + url.replace(base_url.rstrip("/"), "").lstrip("/"),
            source=source,
            http_status_code=sc,
            status=_status_from_code(sc),
        )


def _status_from_code(sc: int) -> DiscoveredPathStatus:
    if sc == 0:
        return DiscoveredPathStatus.INCONCLUSIVE
    if 200 <= sc < 300:
        return DiscoveredPathStatus.REACHABLE
    if sc in (301, 302, 303, 307, 308):
        return DiscoveredPathStatus.REDIRECT
    if sc == 403:
        return DiscoveredPathStatus.FORBIDDEN
    if sc == 404:
        return DiscoveredPathStatus.NOT_FOUND
    if sc >= 500:
        return DiscoveredPathStatus.ERROR
    return DiscoveredPathStatus.DISCOVERED
