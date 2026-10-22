"""
XScan Spider
============
Pure-Python web crawler using httpx + BeautifulSoup.
Discovers URLs and HTML forms within the target scope.

Does NOT use any external tools — works out of the box.
"""
from __future__ import annotations

import re
from collections import deque
from typing import Callable, Optional
from urllib.parse import urljoin, urlparse, urlunparse, urlencode, parse_qs

from bs4 import BeautifulSoup

from xscan.core.models import Form, HttpResponse
from xscan.http.client import ScanClient

# Input types we care about for injection testing
INJECTABLE_INPUT_TYPES = {
    "text", "search", "url", "email", "number",
    "tel", "password", "hidden", "textarea", "", None,
}


class Spider:
    """
    Crawl a target and collect URLs + forms.

    Usage::

        spider = Spider(base_url, client, max_pages=50)
        urls, forms = spider.crawl(progress_cb=lambda msg: print(msg))
    """

    def __init__(
        self,
        base_url: str,
        client: ScanClient,
        max_pages: int = 50,
        max_depth: int = 3,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._origin = self._extract_origin(base_url)
        self._client = client
        self.max_pages = max_pages
        self.max_depth = max_depth

    def crawl(
        self,
        progress_cb: Optional[Callable[[str], None]] = None,
    ) -> tuple[list[str], list[Form]]:
        """
        BFS crawl starting from base_url.

        Returns (discovered_urls, discovered_forms).
        """
        visited: set[str] = set()
        all_forms: list[Form] = []
        # queue items: (url, depth)
        queue: deque[tuple[str, int]] = deque([(self.base_url, 0)])

        while queue and len(visited) < self.max_pages:
            url, depth = queue.popleft()
            url = self._normalise(url)

            if url in visited:
                continue
            if not self._in_scope(url):
                continue

            visited.add(url)

            if progress_cb:
                progress_cb(f"Crawling [{len(visited)}/{self.max_pages}]  {url[:80]}")

            resp = self._client.get(url)
            if resp.status_code == 0:
                continue
            if "text/html" not in resp.headers.get("content-type", ""):
                continue

            # Parse page
            soup = BeautifulSoup(resp.body, "html.parser")

            # Collect links
            if depth < self.max_depth:
                for link in soup.find_all("a", href=True):
                    href = link["href"].strip()
                    resolved = urljoin(url, href)
                    resolved = self._normalise(resolved)
                    if resolved not in visited and self._in_scope(resolved):
                        queue.append((resolved, depth + 1))

                # Also pick up form actions
                for form_tag in soup.find_all("form"):
                    action = form_tag.get("action", "")
                    if action:
                        resolved = urljoin(url, action)
                        if resolved not in visited and self._in_scope(resolved):
                            queue.append((resolved, depth + 1))

            # Collect forms
            for form_tag in soup.find_all("form"):
                form = self._parse_form(form_tag, url)
                if form:
                    all_forms.append(form)

        return sorted(visited), all_forms

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_form(self, form_tag, source_url: str) -> Optional[Form]:
        action = form_tag.get("action", source_url)
        resolved_action = urljoin(source_url, action)
        method = (form_tag.get("method", "get") or "get").upper()

        inputs = []
        for tag in form_tag.find_all(["input", "textarea", "select"]):
            itype = tag.get("type", "").lower()
            if tag.name == "textarea":
                itype = "textarea"
            if tag.name == "select":
                itype = "select"
            # Skip submit/button/image/reset/checkbox/radio for injection
            if itype in ("submit", "button", "image", "reset", "file"):
                continue
            name = tag.get("name", "")
            if not name:
                continue
            inputs.append({
                "name":  name,
                "type":  itype,
                "value": tag.get("value", ""),
            })

        if not inputs:
            return None

        return Form(
            action=resolved_action,
            method=method,
            inputs=inputs,
            source_url=source_url,
        )

    def _in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        return (
            parsed.scheme in ("http", "https")
            and self._extract_origin(url) == self._origin
        )

    @staticmethod
    def _normalise(url: str) -> str:
        """Strip fragment."""
        p = urlparse(url)
        return urlunparse(p._replace(fragment=""))

    @staticmethod
    def _extract_origin(url: str) -> str:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"
