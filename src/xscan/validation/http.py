"""
HTTP Validator
==============
Executes test cases via HTTP and produces Observations.
No browser — pure HTTP reflection checking.

Rules:
  - Every request passes through ScopeEngine
  - Hard limits: MAX_ATTEMPTS=5, MAX_REQUESTS=20 per candidate
  - Returns Observations only — never creates Findings directly
"""
from __future__ import annotations

import html
import threading
import time
from typing import Optional
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

import httpx

from xscan.core.scope.engine import ScopeEngine
from xscan.nodes.analysis.context import ContextAnalyser
from xscan.validation.observation import Observation

MAX_ATTEMPTS  = 5
MAX_REQUESTS  = 20
MAX_RUNTIME_S = 60

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"

# Global stop flag — set to True when Ctrl+C is pressed so all validators
# can exit their loops between requests without waiting for a socket timeout.
_STOP_REQUESTED: threading.Event = threading.Event()


def request_stop() -> None:
    """Signal all running validators to stop at the next safe point."""
    _STOP_REQUESTED.set()


def clear_stop() -> None:
    """Clear the stop flag (called at scan start)."""
    _STOP_REQUESTED.clear()


def is_stop_requested() -> bool:
    return _STOP_REQUESTED.is_set()


class HTTPValidator:
    """
    Execute test cases against a reflected-input parameter.

    Usage::

        validator = HTTPValidator(scope_engine)
        obs = validator.execute(
            url="https://example.com/search",
            param="q",
            method="GET",
            payload='"><img src=x onerror=alert(1)>',
            attempt=1,
            baseline_body=baseline_resp,
        )
    """

    def __init__(self, scope: ScopeEngine) -> None:
        self._scope    = scope
        self._analyser = ContextAnalyser()
        self._requests = 0

    def execute(
        self,
        url: str,
        param: str,
        method: str,
        payload: str,
        attempt: int,
        form_data: Optional[dict] = None,
        baseline_body: str = "",
    ) -> Observation:
        obs = Observation(attempt=attempt, payload=payload, url_sent="")

        # Honour global stop flag (set by Ctrl+C handler)
        if is_stop_requested():
            obs.error = "scan_interrupted"
            return obs

        if self._requests >= MAX_REQUESTS:
            obs.error = "MAX_REQUESTS exceeded"
            return obs

        # Build request
        if method == "POST" and form_data:
            req_url = url
            data    = dict(form_data)
            data[param] = payload
        else:
            req_url = self._inject_param(url, param, payload)
            data    = {}

        obs.url_sent = req_url

        # Scope check
        try:
            self._scope.assert_allowed(req_url, operation="http_request")
        except Exception as exc:
            obs.error = f"scope_blocked: {exc}"
            return obs

        t0 = time.monotonic()
        try:
            with httpx.Client(follow_redirects=True, timeout=8, verify=False,
                              headers={"User-Agent": _UA}) as client:
                if method == "POST" and data:
                    resp = client.post(req_url, data=data)
                else:
                    resp = client.get(req_url)
            self._requests += 1
        except Exception as exc:
            obs.error = str(exc)
            obs.duration_ms = (time.monotonic() - t0) * 1000
            return obs

        obs.duration_ms  = round((time.monotonic() - t0) * 1000, 1)
        obs.http_status  = resp.status_code
        body             = resp.text

        # Reflection analysis
        if payload in body:
            obs.payload_reflected = True
            analysis = self._analyser.analyse(body, payload)
            obs.reflection_context = analysis.context
            obs.reflection_snippet = analysis.full_snippet[:200]
        elif html.escape(payload) in body:
            obs.payload_encoded = True
        elif body and payload not in body:
            obs.payload_stripped = True

        # Response changed vs baseline
        if baseline_body:
            obs.response_changed = body != baseline_body

        return obs

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        parsed  = urlparse(url)
        params  = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_q   = urlencode({k: v[0] for k, v in params.items()})
        return urlunparse(parsed._replace(query=new_q))
