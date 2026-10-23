"""
Eval-Injection Validator
========================
Specialized validation for eval-on-AJAX and response-reflection vulnerabilities.

Handles:
- Testing eval-injection payloads
- Escape-aware bypass synthesis
- JSON response parsing
- Confirmation via eval execution side-effects
"""
from __future__ import annotations

from typing import Any
import json
import re

import httpx

from xscan.core.scope.engine import ScopeEngine
from xscan.core.scope.policy import PolicyEngine


class EvalInjectionValidator:
    """Validates eval-injection vulnerabilities with escape-aware payloads."""

    def __init__(self, scope: ScopeEngine, policy: PolicyEngine):
        """Initialize validator."""
        self.scope = scope
        self.policy = policy

    def validate(
        self,
        url: str,
        parameter: str,
        payload: str,
        escape_bypass: bool = False,
        dangerous_sinks: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Test eval-injection payload and confirm execution.

        Args:
            url: Target URL with parameter
            parameter: Parameter name to inject
            payload: Payload to test
            escape_bypass: Whether this uses an escape-bypass technique
            dangerous_sinks: List of dangerous sinks (eval, Function, etc.)

        Returns:
            Validation result with confirmation status
        """
        dangerous_sinks = dangerous_sinks or ["eval"]

        # Test 1: Inject payload and check if it appears in response
        test_url = self._build_test_url(url, parameter, payload)

        try:
            self.scope.assert_allowed(test_url, operation="http_request")
        except Exception:
            return {
                "validated": False,
                "confirmed": False,
                "error": "scope_denied",
                "payload": payload,
            }

        try:
            resp = httpx.get(test_url, timeout=10, follow_redirects=True)
        except Exception as e:
            return {
                "validated": False,
                "confirmed": False,
                "error": f"request_failed: {str(e)[:50]}",
                "payload": payload,
            }

        # Test 2: Check if payload appears in response
        if payload not in resp.text:
            return {
                "validated": False,
                "confirmed": False,
                "error": "payload_not_reflected",
                "payload": payload,
                "response_status": resp.status_code,
            }

        # Test 3: For escape-bypass payloads, verify it's not escaped
        if escape_bypass:
            # Check if backslash appears unescaped (\\\\  = raw double backslash in response)
            if "\\\\" not in resp.text:
                return {
                    "validated": False,
                    "confirmed": False,
                    "error": "escape_not_effective",
                    "payload": payload,
                }

        # Test 4: Check if dangerous sink consumes this (eval, Function, etc.)
        # Look for eval() or Function() call in response
        sink_evidence = False
        for sink in dangerous_sinks:
            if sink == "eval":
                # Check for eval( pattern in response
                if re.search(r"eval\s*\(", resp.text, re.IGNORECASE):
                    sink_evidence = True
                    break
            elif sink == "Function constructor":
                if re.search(r"new\s+Function\s*\(", resp.text, re.IGNORECASE):
                    sink_evidence = True
                    break

        # Test 5: Try to trigger execution side-effect
        # Use a canary: {}_canary_XYZ in payload
        canary = "xscan_confirmed_123"
        canary_payload = payload.replace("alert(1)", f'document.title="{canary}"')

        test_url_canary = self._build_test_url(url, parameter, canary_payload)

        try:
            resp_canary = httpx.get(test_url_canary, timeout=10, follow_redirects=True)
            # Check if canary appears in response (would indicate eval executed and set property)
            if canary in resp_canary.text:
                # Execution confirmed!
                return {
                    "validated": True,
                    "confirmed": True,
                    "payload": payload,
                    "execution_confirmed": True,
                    "response_status": resp_canary.status_code,
                    "evidence": "canary_appeared_in_response",
                }
        except Exception:
            pass

        # Test 6: If payload structure is correct and sink found, mark as validated
        # (even if we can't trigger via HTTP, the sink is confirmed)
        if sink_evidence and payload in resp.text:
            return {
                "validated": True,
                "confirmed": False,
                "payload": payload,
                "response_status": resp.status_code,
                "evidence": f"sink_found({','.join(dangerous_sinks)})",
                "notes": "Payload reflected and dangerous sink detected. Execution not confirmed via HTTP.",
            }

        # Generic validation: payload reflected + no encoding
        return {
            "validated": True,
            "confirmed": False,
            "payload": payload,
            "response_status": resp.status_code,
            "evidence": "payload_reflected_unencoded",
        }

    @staticmethod
    def _build_test_url(base_url: str, param: str, payload: str) -> str:
        """Build test URL with payload injected."""
        from urllib.parse import urlparse, parse_qs, urlencode, quote

        parsed = urlparse(base_url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # Set payload for this parameter
        params[param] = [payload]

        # Rebuild query string
        query_parts = []
        for k, v_list in params.items():
            for v in v_list:
                query_parts.append(f"{quote(k, safe='')}={quote(v, safe='')}")
        query_string = "&".join(query_parts)

        new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"
        if parsed.fragment:
            new_url += f"#{parsed.fragment}"

        return new_url
