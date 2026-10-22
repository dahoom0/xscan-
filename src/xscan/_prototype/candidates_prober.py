"""
XSS Prober
==========
Injects probe strings into every discovered URL parameter and form input,
then checks whether the probe is reflected unencoded in the response.

Two-phase approach:
  1. Canary probe  — a unique harmless marker to test for reflection
  2. Payload probe — actual XSS payloads on confirmed-reflection targets

This produces low false-positive XssCandidate objects for LLM analysis.
"""
from __future__ import annotations

import hashlib
import re
import time
from typing import Callable, Optional
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from xscan.core.models import Form, HttpRequest, HttpResponse, XssCandidate
from xscan.http.client import ScanClient

# ── Payloads ─────────────────────────────────────────────────────────────────

# Canary: unique string unlikely to appear naturally
CANARY_TEMPLATE = "xsc4n{token}"

# XSS payloads — progressively more evasive
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '<svg onload=alert(1)>',
    '"><svg onload=alert(1)>',
    "';alert(1)//",
    '"+alert(1)+"',
]

# Fast payloads for "fast" profile — just the most common
XSS_PAYLOADS_FAST = XSS_PAYLOADS[:3]


def _canary(param: str) -> str:
    token = hashlib.md5(f"{param}{time.time()}".encode()).hexdigest()[:8]
    return CANARY_TEMPLATE.format(token=token)


class XssProber:
    """
    Probe URLs and forms for XSS reflection.

    Usage::

        prober = XssProber(client, profile="balanced")
        candidates = prober.probe_urls(urls, progress_cb=...)
        candidates += prober.probe_forms(forms, progress_cb=...)
    """

    def __init__(
        self,
        client: ScanClient,
        profile: str = "balanced",
    ) -> None:
        self._client = client
        self._payloads = XSS_PAYLOADS_FAST if profile == "fast" else XSS_PAYLOADS
        self.requests_sent = 0

    # ------------------------------------------------------------------
    # URL parameter probing
    # ------------------------------------------------------------------

    def probe_urls(
        self,
        urls: list[str],
        progress_cb: Optional[Callable[[str], None]] = None,
    ) -> list[XssCandidate]:
        candidates: list[XssCandidate] = []
        for url in urls:
            params = self._extract_params(url)
            if not params:
                continue
            for param in params:
                c = self._probe_url_param(url, param, progress_cb)
                candidates.extend(c)
        return candidates

    # ------------------------------------------------------------------
    # Form probing
    # ------------------------------------------------------------------

    def probe_forms(
        self,
        forms: list[Form],
        progress_cb: Optional[Callable[[str], None]] = None,
    ) -> list[XssCandidate]:
        candidates: list[XssCandidate] = []
        for form in forms:
            for inp in form.inputs:
                param = inp.get("name", "")
                if not param:
                    continue
                c = self._probe_form_input(form, param, progress_cb)
                candidates.extend(c)
        return candidates

    # ------------------------------------------------------------------
    # Internal — URL param
    # ------------------------------------------------------------------

    def _probe_url_param(
        self,
        url: str,
        param: str,
        progress_cb: Optional[Callable[[str], None]] = None,
    ) -> list[XssCandidate]:
        candidates: list[XssCandidate] = []

        # Phase 1: canary reflection test
        canary = _canary(param)
        test_url = self._inject_url_param(url, param, canary)
        resp = self._client.get(test_url)
        self.requests_sent += 1

        if resp.status_code == 0 or canary not in resp.body:
            return []  # Not reflected at all — skip payloads

        if progress_cb:
            progress_cb(f"  Reflected param [{param}] on {url[:60]}")

        # Phase 2: try XSS payloads
        for payload in self._payloads:
            payload_url = self._inject_url_param(url, param, payload)
            resp2 = self._client.get(payload_url)
            self.requests_sent += 1
            if resp2.status_code == 0:
                continue
            snippet = self._find_reflection(resp2.body, payload)
            if snippet:
                candidates.append(XssCandidate(
                    url=url,
                    parameter=param,
                    method="GET",
                    payload=payload,
                    evidence=snippet,
                    reflected=True,
                    request=HttpRequest("GET", payload_url),
                    response=resp2,
                ))
                break  # One confirmed payload is enough per param

        return candidates

    # ------------------------------------------------------------------
    # Internal — form input
    # ------------------------------------------------------------------

    def _probe_form_input(
        self,
        form: Form,
        param: str,
        progress_cb: Optional[Callable[[str], None]] = None,
    ) -> list[XssCandidate]:
        candidates: list[XssCandidate] = []

        # Phase 1: canary
        canary = _canary(param)
        data = self._build_form_data(form, param, canary)
        resp = self._submit_form(form, data)
        self.requests_sent += 1

        if resp.status_code == 0 or canary not in resp.body:
            return []

        if progress_cb:
            progress_cb(f"  Reflected form param [{param}] → {form.action[:60]}")

        # Phase 2: payloads
        for payload in self._payloads:
            data2 = self._build_form_data(form, param, payload)
            resp2 = self._submit_form(form, data2)
            self.requests_sent += 1
            if resp2.status_code == 0:
                continue
            snippet = self._find_reflection(resp2.body, payload)
            if snippet:
                candidates.append(XssCandidate(
                    url=form.action,
                    parameter=param,
                    method=form.method,
                    payload=payload,
                    evidence=snippet,
                    reflected=True,
                    form=form,
                    request=HttpRequest(form.method, form.action, body=str(data2)),
                    response=resp2,
                ))
                break

        return candidates

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _submit_form(self, form: Form, data: dict) -> HttpResponse:
        if form.method == "POST":
            return self._client.post(form.action, data=data)
        else:
            return self._client.get(form.action, params=data)

    @staticmethod
    def _extract_params(url: str) -> list[str]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())

    @staticmethod
    def _inject_url_param(url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return urlunparse(parsed._replace(query=new_query))

    @staticmethod
    def _build_form_data(form: Form, inject_param: str, value: str) -> dict:
        data: dict[str, str] = {}
        for inp in form.inputs:
            name = inp.get("name", "")
            if not name:
                continue
            data[name] = value if name == inject_param else inp.get("value", "test")
        return data

    @staticmethod
    def _find_reflection(body: str, payload: str) -> str:
        """Return a 120-char context snippet around the first reflection, or ''."""
        idx = body.find(payload)
        if idx == -1:
            return ""
        start = max(0, idx - 40)
        end   = min(len(body), idx + len(payload) + 40)
        return body[start:end].replace("\n", " ").strip()
