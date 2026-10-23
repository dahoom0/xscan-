"""
Escape Probe Analyzer Node
===========================
Detects escape-aware vulnerabilities by probing character-by-character
to identify which special characters are escaped and which are not.

This is crucial for catching subtle vulnerabilities like:
  - Backslash not escaped while quotes are (PortSwigger DOM XSS lab)
  - Single quotes escaped but double quotes not
  - HTML entities escaped but raw markup not

The classic vulnerability this detects:
  JSON response has: {"search": "input"}
  Quotes ARE escaped: {"search": "input\\"value"}
  Backslash is NOT escaped: {"search": "input\\\\value"}  ← double backslash!
  Result: \\ acts as escape char, allowing " to close the string

Inputs:
  - response_reflections (list[dict]): Detected reflections to probe
  - urls_with_params (list[str]): URLs to probe for escape differences

Outputs:
  - escape_vulnerabilities (list[dict]): Character combinations that bypass escaping
  - escape_profiles (list[dict]): Per-parameter escape behavior
"""
from __future__ import annotations

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

# Test characters to probe for escaping behavior
# Each character will be sent as the parameter value and we'll see if it's escaped
_ESCAPE_TEST_CHARS = [
    '"',    # double quote
    "'",    # single quote
    "\\",   # backslash
    "<",    # less-than
    ">",    # greater-than
    "&",    # ampersand
    ";",    # semicolon
    "/",    # forward slash
    "\n",   # newline
]

# More complex payloads that test for double-escaping and bypass techniques
_ESCAPE_TEST_PAYLOADS = [
    '\\"',      # backslash + quote (tests double-escape)
    '\\\\"',    # double backslash + quote
    '\\\\\\"',  # triple backslash + quote
    "\\n",      # literal backslash-n
    "</script>", # script close tag
    "';alert(1);//", # classic JS injection
]


@registry.register("escape-probe-analyzer")
class EscapeProbeAnalyzerNode(NodeBase):
    """Analyze character escaping behavior to detect bypass techniques."""

    def __init__(self) -> None:
        """Initialize the analyzer."""
        self._emitter = NodeEmitter()
        self._tested: set[str] = set()

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        """
        Probe URLs for escape behavior and identify bypass opportunities.

        Args:
            ctx: Execution context

        Returns:
            Dictionary with escape_vulnerabilities and escape_profiles
        """
        urls_with_params = ctx.get("urls_with_params", [])

        if not urls_with_params:
            return {
                "escape_vulnerabilities": [],
                "escape_profiles": [],
                "probes_sent": 0,
            }

        t0 = self._emitter.emit_started(ctx)
        vulnerabilities: list[dict[str, Any]] = []
        escape_profiles: list[dict[str, Any]] = []

        # Limit probes
        urls_to_probe = urls_with_params[:10]

        with httpx.Client(
            follow_redirects=True,
            timeout=ctx.config.get("http_timeout", 10),
            verify=False,
            headers={"User-Agent": _UA},
        ) as client:

            for url in urls_to_probe:
                if url in self._tested:
                    continue
                self._tested.add(url)

                try:
                    ctx.scope.assert_allowed(url, operation="http_request")
                except Exception:
                    continue

                # Extract parameter from URL
                parsed = urlparse(url)
                params = parse_qs(parsed.query)

                if not params:
                    continue

                # Test each parameter
                for param_name in params:
                    profile = self._probe_parameter_escaping(
                        client, url, param_name, parsed
                    )

                    if profile:
                        escape_profiles.append(profile)

                        # Check for exploitable escape behavior
                        if profile["bypasses_detected"]:
                            vulnerabilities.append({
                                "url": url,
                                "parameter": param_name,
                                "escaping_profile": profile["profile"],
                                "escaped_chars": profile["escaped_chars"],
                                "unescaped_chars": profile["unescaped_chars"],
                                "bypass_techniques": profile["bypass_techniques"],
                                "risk_level": "critical"
                                if profile["critical_bypasses"]
                                else "high",
                            })

        ms = (time.monotonic() - t0) * 1000
        self._emitter.emit_completed(
            ctx,
            metrics={
                "urls_probed": len(self._tested),
                "escape_profiles": len(escape_profiles),
                "vulnerabilities_found": len(vulnerabilities),
            },
            duration_ms=ms,
        )

        return {
            "escape_vulnerabilities": vulnerabilities,
            "escape_profiles": escape_profiles,
            "probes_sent": len(self._tested),
        }

    def _probe_parameter_escaping(
        self, client: httpx.Client, base_url: str, param_name: str, parsed_url: Any
    ) -> dict[str, Any] | None:
        """
        Probe a single parameter to map its escaping behavior.

        Returns a dict mapping test characters to whether they were escaped.
        """
        escaped_chars = []
        unescaped_chars = []
        bypass_techniques = []
        critical_bypasses = False

        # Test each escape character
        for test_char in _ESCAPE_TEST_CHARS:
            try:
                probe_url = self._build_probe_url(base_url, param_name, test_char)
                resp = client.get(probe_url, timeout=10)

                if resp.status_code != 200:
                    continue

                # Check if the test character appears unescaped in response
                if test_char in resp.text:
                    # Check for common escape sequences
                    escaped = False
                    for escape_seq in [f"\\{test_char}", f"&#{ord(test_char)};"]:
                        if escape_seq in resp.text:
                            escaped = True
                            break

                    if escaped:
                        escaped_chars.append(test_char)
                    else:
                        unescaped_chars.append(test_char)

            except Exception:
                pass

        # Test more complex payloads
        for payload in _ESCAPE_TEST_PAYLOADS:
            try:
                probe_url = self._build_probe_url(base_url, param_name, payload)
                resp = client.get(probe_url, timeout=10)

                if resp.status_code != 200:
                    continue

                # Check if payload structure survived
                # If backslash appears unescaped before quote, it could bypass escaping
                if (
                    "\\" in payload
                    and '"' in payload
                    and "\\" in resp.text
                    and '"' in resp.text
                    and ("\\\\" in resp.text or '\\"' in resp.text)
                ):
                    # Check the pattern: if \\ appears before " in response,
                    # it might enable a bypass
                    bypass_techniques.append(f"double_backslash: {payload}")
                    critical_bypasses = True

            except Exception:
                pass

        # If we found unescaped special characters, it's worth reporting
        if unescaped_chars:
            return {
                "parameter": param_name,
                "escaped_chars": escaped_chars,
                "unescaped_chars": unescaped_chars,
                "bypass_techniques": bypass_techniques,
                "critical_bypasses": critical_bypasses,
                "profile": {
                    "escapes_quotes": '"' in escaped_chars or "'" in escaped_chars,
                    "escapes_backslash": "\\" in escaped_chars,
                    "escapes_angle_brackets": "<" in escaped_chars or ">" in escaped_chars,
                    "bypasses_detected": critical_bypasses or (
                        "\\" not in escaped_chars and '"' in unescaped_chars
                    ),
                },
            }

        return None

    @staticmethod
    def _build_probe_url(
        base_url: str, param_name: str, test_value: str
    ) -> str:
        """
        Build URL with test value injected.
        """
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)

        # Set test value
        params[param_name] = [test_value]

        # Rebuild query
        query_parts = []
        for k, v_list in params.items():
            for v in v_list:
                query_parts.append(f"{quote(k, safe='')}={quote(v, safe='')}")
        query_string = "&".join(query_parts)

        new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"
        if parsed.fragment:
            new_url += f"#{parsed.fragment}"

        return new_url
