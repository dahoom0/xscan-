"""
tool-xss-scan node — Phase H (tool observation normalization)
==============================================================
Runs installed XSS tools (XSStrike, dalfox) on reflection candidates.
Produces typed ToolObservation objects — never raw dicts.

CRITICAL FAILURE SEMANTICS (spec section 20):
  NO_PARAMETERS  != no vulnerability
  NO_CANDIDATES  != safe
  EXECUTION_FAILED != safe
  TIMEOUT        != safe

Every result state is explicitly recorded.

Inputs:  target_url, xss_candidates | candidates (list[dict]),
         urls_with_params (list[str])
Outputs: tool_observations (list[dict])  — serialised ToolObservation
         tools_used        (list[str])
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from xscan.config.defaults import XSCAN_HOME
from xscan.core.dag.node_registry import registry
from xscan.nodes.base import NodeBase, ExecutionContext
from xscan.nodes.emitter import NodeEmitter
from xscan.schemas.xss import ToolObservation, ToolStatus

_BIN       = XSCAN_HOME / "bin"
_TOOLS_DIR = XSCAN_HOME / "tools"


def _find_binary(name: str) -> Path | None:
    for p in [_BIN / name, _BIN / (name + ".exe")]:
        if p.exists():
            return p
    found = shutil.which(name)
    return Path(found) if found else None


@registry.register("tool-xss-scan")
class ToolXssScanNode(NodeBase, NodeEmitter):
    node_type = "tool-xss-scan"

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        t0 = self.emit_started(ctx)

        # Accept both new (xss_candidates) and legacy (candidates) keys
        raw_candidates: list[dict] = (
            ctx.get("xss_candidates") or ctx.get("candidates") or []
        )
        urls_with_params: list[str] = ctx.get("urls_with_params", [])
        target_url:       str       = ctx.get("target_url", "")

        observations: list[ToolObservation] = []
        tools_used:   list[str] = []

        # Collect URLs to test
        test_urls: list[str] = []
        for c in raw_candidates[:10]:
            u = c.get("best_test_url") or c.get("request_url") or c.get("url", "")
            if u:
                test_urls.append(u)
        for u in urls_with_params[:5]:
            if u not in test_urls:
                test_urls.append(u)

        if not test_urls:
            self.emit_progress(ctx, "No parameterised URLs to test with external tools")
            ms = (time.monotonic() - t0) * 1000
            self.emit_completed(ctx, metrics={"tools_used": 0, "tool_observations": 0})
            return {"tool_observations": [], "tools_used": []}

        # ── XSStrike ──────────────────────────────────────────────────
        xsstrike_py = _TOOLS_DIR / "xsstrike" / "xsstrike.py"
        if xsstrike_py.exists():
            self.emit_progress(ctx, f"Running XSStrike ({len(test_urls)} URLs)...")
            tools_used.append("xsstrike")
            for url in test_urls[:5]:
                obs = self._run_xsstrike(xsstrike_py, url, ctx)
                observations.append(obs)
                self.emit_progress(ctx, f"  xsstrike: {url[:60]} -> {obs.status}")

        # ── dalfox ────────────────────────────────────────────────────
        dalfox = _find_binary("dalfox")
        if dalfox:
            self.emit_progress(ctx, f"Running dalfox ({len(test_urls)} URLs)...")
            tools_used.append("dalfox")
            for url in test_urls[:5]:
                obs = self._run_dalfox(dalfox, url, ctx)
                observations.append(obs)
                self.emit_progress(ctx, f"  dalfox: {url[:60]} -> {obs.status}")

        if not tools_used:
            self.emit_progress(ctx, "No XSS tools installed — skipping tool scan")
            self.emit_progress(ctx, "  Install: xscan install xsstrike dalfox")

        ms = (time.monotonic() - t0) * 1000
        self.emit_completed(ctx, metrics={
            "tools_used":       len(tools_used),
            "tool_observations": len(observations),
            "candidates_found":  sum(1 for o in observations if o.has_candidates),
        }, duration_ms=ms)

        return {
            "tool_observations": [o.model_dump(mode="json") for o in observations],
            "tools_used":        tools_used,
            # Legacy key for report node backward compat
            "tool_findings":     [
                {"tool": o.tool, "url": o.target_url, "payload": o.payloads[0] if o.payloads else "",
                 "raw": o.raw_output}
                for o in observations if o.has_candidates
            ],
        }

    # ------------------------------------------------------------------

    def _run_xsstrike(self, xsstrike_py: Path, url: str, ctx: ExecutionContext) -> ToolObservation:
        obs = ToolObservation(tool="xsstrike", target_url=url, endpoint=url)
        try:
            ctx.scope.assert_allowed(url, operation="http_request")
        except Exception as e:
            obs.status      = ToolStatus.EXECUTION_FAILED
            obs.observation = f"scope_blocked: {e}"
            return obs

        try:
            result = subprocess.run(
                [sys.executable, str(xsstrike_py), "--url", url,
                 "--skip", "--skip-dom", "--timeout", "10"],
                capture_output=True, text=True, timeout=60,
                cwd=str(xsstrike_py.parent),
            )
            raw = (result.stdout or "") + (result.stderr or "")
            obs.raw_output = raw[:500]

            if result.returncode != 0 and not raw:
                obs.status      = ToolStatus.EXECUTION_FAILED
                obs.observation = f"exit_code={result.returncode}"
                return obs

            if "No parameter" in raw or "No params" in raw.lower():
                obs.status      = ToolStatus.NO_PARAMETERS
                obs.observation = "XSStrike: no parameters found"
                return obs

            # Structured evidence only. Matching loose keywords such as "XSS"
            # flags the tool's own banner ("XSStrike v3.1.5") as a finding.
            import re
            payloads = [m.group(1).strip()[:120]
                        for m in re.finditer(r"Payload: (.+)", raw)]
            has_marker = (
                bool(payloads)
                or "[V]" in raw
                or "POC" in raw
                or bool(re.search(r"\bis vulnerable\b", raw, re.I))
            )
            if has_marker:
                obs.status      = ToolStatus.CANDIDATE
                obs.observation = "XSStrike: potential candidate detected"
                obs.payloads    = payloads[:10]
            else:
                obs.status      = ToolStatus.NO_CANDIDATES
                obs.observation = "XSStrike: no candidates"

        except subprocess.TimeoutExpired:
            obs.status      = ToolStatus.TIMEOUT
            obs.observation = "XSStrike timed out after 60s"
        except Exception as exc:
            obs.status      = ToolStatus.EXECUTION_FAILED
            obs.observation = str(exc)[:200]

        return obs

    def _run_dalfox(self, dalfox: Path, url: str, ctx: ExecutionContext) -> ToolObservation:
        obs = ToolObservation(tool="dalfox", target_url=url, endpoint=url)
        try:
            ctx.scope.assert_allowed(url, operation="http_request")
        except Exception as e:
            obs.status      = ToolStatus.EXECUTION_FAILED
            obs.observation = f"scope_blocked: {e}"
            return obs

        try:
            result = subprocess.run(
                [str(dalfox), "url", url, "--silence", "--no-color",
                 "--timeout", "10", "--format", "json"],
                capture_output=True, text=True, timeout=60,
            )
            raw = (result.stdout or "") + (result.stderr or "")
            obs.raw_output = raw[:500]

            if "no parameter" in raw.lower():
                obs.status      = ToolStatus.NO_PARAMETERS
                obs.observation = "dalfox: no parameters found"
                return obs

            candidates_found = False
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    payload = item.get("poc", item.get("payload", ""))
                    if payload:
                        obs.payloads.append(payload[:120])
                        candidates_found = True
                except json.JSONDecodeError:
                    if "[V]" in line or "POC" in line:
                        candidates_found = True
                        obs.payloads.append(line[:120])

            if candidates_found:
                obs.status      = ToolStatus.CANDIDATE
                obs.observation = f"dalfox: {len(obs.payloads)} candidate(s)"
            elif result.returncode == 0:
                obs.status      = ToolStatus.NO_CANDIDATES
                obs.observation = "dalfox: no candidates"
            else:
                obs.status      = ToolStatus.EXECUTION_FAILED
                obs.observation = f"dalfox exit {result.returncode}"

        except subprocess.TimeoutExpired:
            obs.status      = ToolStatus.TIMEOUT
            obs.observation = "dalfox timed out after 60s"
        except Exception as exc:
            obs.status      = ToolStatus.EXECUTION_FAILED
            obs.observation = str(exc)[:200]

        return obs
