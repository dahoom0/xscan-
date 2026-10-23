"""
Response Reflection Detector Node
==================================
Detects when request parameters are echoed back in response bodies,
identifying a critical source of reflected XSS (particularly eval-on-AJAX).

This node handles the response-reflection source class:
  - Request param sent in URL/form
  - Same value appears in JSON/HTML/JS response body
  - Processed by eval(), DOM sink, or other dangerous function

Inputs:
  - urls_with_params (list[str]): Parameterized URLs to probe
  - target_url (str): Base target URL

Outputs:
  - response_reflections (list[dict]): Detected reflections with source→sink info
  - reflection_sources (list[dict]): Parameters that are reflected
  - high_risk_reflections (list[dict]): Reflections in eval() or Function context
"""
from __future__ import annotations

import json
import re
import time
from typing import Any
from urllib.parse import parse_qs, quote, urlparse

import httpx

from xscan.core.dag.node_registry import registry
from xscan.nodes.base import ExecutionContext, NodeBase
from xscan.nodes.emitter import NodeEmitter

_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"
)

# Patterns that indicate dangerous sinks consuming response data
_DANGEROUS_PATTERNS = [
    (r"eval\s*\(", "eval"),
    (r"new\s+Function\s*\(", "Function constructor"),
    (r"setTimeout\s*\(\s*['\"]", "setTimeout with string"),
    (r"setInterval\s*\(\s*['\"]", "setInterval with string"),
    (r"innerHTML\s*=", "innerHTML"),
    (r"\.write\s*\(", "document.write"),
    (r"insertAdjacentHTML", "insertAdjacentHTML"),
]


@registry.register("response-reflection-detect")
class ResponseReflectionDetectorNode(NodeBase):
    """Detect parameter reflection in API responses."""

    def __init__(self) -> None:
        """Initialize the detector."""
        self._emitter = NodeEmitter()
        self._probed: set[str] = set()

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        """
        Probe URLs for parameter reflection in responses.

        Args:
            ctx: Execution context containing urls_with_params

        Returns:
            Dictionary with response_reflections and reflection_sources
        """
        urls_with_params = ctx.get("urls_with_params", [])

        if not urls_with_params:
            return {
                "response_reflections": [],
                "reflection_sources": [],
                "high_risk_reflections": [],
                "probes_sent": 0,
            }

        t0 = self._emitter.emit_started(ctx)
        reflections: list[dict[str, Any]] = []
        reflection_sources: list[dict[str, Any]] = []
        high_risk: list[dict[str, Any]] = []

        # Limit probes
        urls_to_probe = urls_with_params[:20]  # Top 20 parameterized URLs

        with httpx.Client(
            follow_redirects=True,
            timeout=ctx.config.get("http_timeout", 10),
            verify=False,
            headers={"User-Agent": _UA},
        ) as client:

            for url in urls_to_probe:
                if url in self._probed:
                    continue
                self._probed.add(url)

                try:
                    ctx.scope.assert_allowed(url, operation="http_request")
                except Exception:
                    continue

                # Extract parameters from URL
                parsed = urlparse(url)
                params = parse_qs(parsed.query)

                if not params:
                    continue

                # Probe each parameter for reflection
                for param_name, param_values in params.items():
                    if not param_values:
                        continue

                    # Create probe value with markers
                    probe_value = f"xscProbe{param_name}Marker"

                    # Build probe URL with test value
                    probe_url = self._build_probe_url(url, param_name, probe_value)

                    try:
                        resp = client.get(probe_url, timeout=10)

                        if resp.status_code != 200:
                            continue

                        content_type = resp.headers.get("content-type", "")

                        # Check for reflection in response body
                        if probe_value in resp.text:
                            # Found reflection — analyze context
                            reflection_data = self._analyze_reflection(
                                probe_value,
                                resp.text,
                                param_name,
                                content_type,
                                url,
                            )

                            if reflection_data:
                                reflections.append(reflection_data)

                                # Track source
                                reflection_sources.append({
                                    "url": url,
                                    "parameter": param_name,
                                    "reflection_type": "response_body",
                                    "content_type": content_type,
                                    "is_json": "json" in content_type,
                                })

                                # Check risk level
                                if reflection_data["dangerous_sink_found"]:
                                    high_risk.append(reflection_data)

                    except httpx.TimeoutException:
                        pass
                    except httpx.RequestError:
                        pass

        ms = (time.monotonic() - t0) * 1000
        self._emitter.emit_completed(
            ctx,
            metrics={
                "probes_sent": len(self._probed),
                "reflections_found": len(reflections),
                "high_risk_reflections": len(high_risk),
            },
            duration_ms=ms,
        )

        return {
            "response_reflections": reflections,
            "reflection_sources": reflection_sources,
            "high_risk_reflections": high_risk,
            "probes_sent": len(self._probed),
        }

    def _analyze_reflection(
        self,
        probe_value: str,
        response_body: str,
        param_name: str,
        content_type: str,
        url: str,
    ) -> dict[str, Any] | None:
        """
        Analyze a reflection point and check for dangerous sinks.

        Args:
            probe_value: The value we injected
            response_body: The response body containing the reflection
            param_name: Parameter name
            content_type: Response content type
            url: Original URL

        Returns:
            Reflection metadata dict or None if analysis fails
        """
        # Find the reflection position
        pos = response_body.find(probe_value)
        if pos < 0:
            return None

        # Extract context around reflection
        context_start = max(0, pos - 100)
        context_end = min(len(response_body), pos + len(probe_value) + 100)
        context_before = response_body[context_start:pos]
        context_after = response_body[pos + len(probe_value):context_end]

        # Detect dangerous sinks
        dangerous_sink_found = False
        dangerous_sinks = []

        for pattern, sink_name in _DANGEROUS_PATTERNS:
            # Check if sink appears in response body (rough heuristic)
            if re.search(pattern, response_body, re.I):
                dangerous_sink_found = True
                dangerous_sinks.append(sink_name)

        # Check if it's in a JSON-like context
        is_json_context = self._is_json_response(response_body, content_type)

        # Check if it's in a script context
        is_script_context = self._is_script_context(
            response_body, param_name, probe_value
        )

        return {
            "url": url,
            "parameter": param_name,
            "probe_value": probe_value,
            "position": pos,
            "context_before": context_before[-50:],  # Last 50 chars
            "context_after": context_after[:50],     # First 50 chars
            "content_type": content_type,
            "is_json": is_json_context,
            "is_script": is_script_context,
            "dangerous_sink_found": dangerous_sink_found,
            "dangerous_sinks": dangerous_sinks,
            "risk_level": "critical" if dangerous_sink_found else "medium",
        }

    @staticmethod
    def _is_json_response(response_body: str, content_type: str) -> bool:
        """Check if response is JSON-formatted."""
        if "application/json" in content_type:
            return True
        # Try to parse first 1000 chars as JSON
        try:
            json.loads(response_body[:1000])
            return True
        except (json.JSONDecodeError, ValueError):
            return False

    @staticmethod
    def _is_script_context(
        response_body: str, param_name: str, probe_value: str
    ) -> bool:
        """
        Check if the reflection appears in a JavaScript context.
        """
        # Simple heuristic: look for <script> tags
        if "<script" in response_body.lower():
            return True

        # Check if response looks like JS code (contains var, function, etc.)
        return bool(re.search(r"(var|let|const|function|=|return)\s", response_body))

    @staticmethod
    def _build_probe_url(base_url: str, param_name: str, probe_value: str) -> str:
        """
        Build URL with probe value injected into specified parameter.

        Args:
            base_url: Original URL
            param_name: Parameter name to modify
            probe_value: Probe value to inject

        Returns:
            URL with probe value in the specified parameter
        """
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)

        # Set probe value for this parameter
        params[param_name] = [probe_value]

        # Rebuild query string
        query_parts = []
        for k, v_list in params.items():
            for v in v_list:
                query_parts.append(f"{quote(k, safe='')}={quote(v, safe='')}")
        query_string = "&".join(query_parts)

        # Reconstruct URL
        new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"
        if parsed.fragment:
            new_url += f"#{parsed.fragment}"

        return new_url
