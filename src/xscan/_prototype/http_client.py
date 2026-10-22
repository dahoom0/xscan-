"""
XScan HTTP Client
=================
Thin httpx wrapper used by all scan stages.
Handles:
  - Follow redirects
  - Custom user-agent
  - Timeout management
  - SSL verification toggle
  - Request/response capture for evidence
"""
from __future__ import annotations

import time
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

from xscan.core.models import HttpRequest, HttpResponse

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)
DEFAULT_TIMEOUT = 15
MAX_RESPONSE_BODY = 500_000   # 500 KB — don't buffer huge responses


class ScanClient:
    """
    HTTP client for scan operations.

    Usage::

        client = ScanClient(base_url="https://example.com")
        resp = client.get("/search?q=test")
        resp = client.post("/login", data={"user": "a", "pass": "b"})
    """

    def __init__(
        self,
        base_url: str = "",
        timeout: int = DEFAULT_TIMEOUT,
        verify_ssl: bool = False,
        proxies: Optional[str] = None,
        cookies: Optional[dict] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._cookies = cookies or {}

        transport = httpx.HTTPTransport(verify=verify_ssl, retries=1)
        self._client = httpx.Client(
            headers={"User-Agent": DEFAULT_UA},
            follow_redirects=True,
            timeout=timeout,
            transport=transport,
            cookies=self._cookies,
            **({"proxy": proxies} if proxies else {}),
        )

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def get(
        self,
        path_or_url: str,
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
    ) -> HttpResponse:
        url = self._resolve(path_or_url)
        t0 = time.monotonic()
        try:
            r = self._client.get(url, params=params, headers=headers or {})
            return self._wrap(r, time.monotonic() - t0)
        except (httpx.TimeoutException, httpx.RequestError) as exc:
            return HttpResponse(status_code=0, url=url, body=f"[error] {exc}")

    def post(
        self,
        path_or_url: str,
        data: Optional[dict] = None,
        json: Optional[dict] = None,
        headers: Optional[dict] = None,
    ) -> HttpResponse:
        url = self._resolve(path_or_url)
        t0 = time.monotonic()
        try:
            r = self._client.post(url, data=data, json=json, headers=headers or {})
            return self._wrap(r, time.monotonic() - t0)
        except (httpx.TimeoutException, httpx.RequestError) as exc:
            return HttpResponse(status_code=0, url=url, body=f"[error] {exc}")

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "ScanClient":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _resolve(self, path_or_url: str) -> str:
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            return path_or_url
        return urljoin(self.base_url + "/", path_or_url.lstrip("/"))

    @staticmethod
    def _wrap(r: httpx.Response, elapsed: float) -> HttpResponse:
        body = ""
        try:
            body = r.text[:MAX_RESPONSE_BODY]
        except Exception:
            pass
        return HttpResponse(
            status_code=r.status_code,
            url=str(r.url),
            headers=dict(r.headers),
            body=body,
            elapsed_ms=round(elapsed * 1000, 1),
        )
