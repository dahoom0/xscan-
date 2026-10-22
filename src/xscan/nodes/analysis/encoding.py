"""
Encoding Analyser
=================
Probes exactly which characters are transformed by the server
before reflection. Used to determine what a breakout strategy needs.

For each special character, sends a probe and checks:
  - Is it reflected raw?
  - Is it HTML-entity encoded?
  - Is it URL-encoded?
  - Is it stripped/blocked?

Returns EncodingProfile used by the test planner.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

import httpx

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"

_PROBE_CHARS = {
    "<":  "&lt;",
    ">":  "&gt;",
    '"':  "&quot;",
    "'":  "&#x27;",
    "&":  "&amp;",
    "/":  "&#x2F;",
    "`":  "&#x60;",
    ";":  "&#x3B;",
    "(":  "&#x28;",
    ")":  "&#x29;",
    "-":  None,   # rarely encoded
    ".":  None,
}

CHAR_STATUS = {
    "raw":     "NOT encoded — appears literally in response",
    "html":    "HTML entity encoded",
    "url":     "URL encoded",
    "stripped":"removed from response",
    "blocked": "request blocked (WAF?)",
    "unknown": "unknown",
}


@dataclass
class CharResult:
    char: str
    status: str          # raw | html | url | stripped | blocked | unknown
    html_entity: str = ""

    @property
    def breakable(self) -> bool:
        return self.status == "raw"


@dataclass
class EncodingProfile:
    """Complete encoding behaviour for a parameter."""
    parameter: str
    url: str
    method: str = "GET"
    results: dict[str, CharResult] = field(default_factory=dict)

    @property
    def raw_chars(self) -> list[str]:
        return [c for c, r in self.results.items() if r.status == "raw"]

    @property
    def encoded_chars(self) -> list[str]:
        return [c for c, r in self.results.items() if r.status in ("html", "url")]

    @property
    def stripped_chars(self) -> list[str]:
        return [c for c, r in self.results.items() if r.status == "stripped"]

    def summary(self) -> str:
        parts = []
        if self.raw_chars:
            parts.append(f"raw: {self.raw_chars}")
        if self.encoded_chars:
            parts.append(f"encoded: {self.encoded_chars}")
        if self.stripped_chars:
            parts.append(f"stripped: {self.stripped_chars}")
        return "  ".join(parts) if parts else "no special chars tested"

    def can_break_html_attribute(self) -> bool:
        return '"' in self.raw_chars or "'" in self.raw_chars

    def can_break_html_text(self) -> bool:
        return "<" in self.raw_chars

    def can_break_script_string(self) -> bool:
        return '"' in self.raw_chars or "'" in self.raw_chars or "`" in self.raw_chars


class EncodingAnalyser:
    """
    Test which characters a server encodes before reflecting them.

    Usage::

        ea = EncodingAnalyser(client)
        profile = ea.probe(url="https://example.com/search", param="q")
    """

    def __init__(self, client: httpx.Client) -> None:
        self._client = client

    def probe(
        self,
        url: str,
        param: str,
        method: str = "GET",
        form_data: Optional[dict] = None,
    ) -> EncodingProfile:
        profile = EncodingProfile(parameter=param, url=url, method=method)

        for char, html_entity in _PROBE_CHARS.items():
            probe_value = f"xscP{char}xscP"
            try:
                if method == "POST" and form_data is not None:
                    data = dict(form_data)
                    data[param] = probe_value
                    resp = self._client.post(url, data=data)
                else:
                    resp = self._get_with_param(url, param, probe_value)

                if resp.status_code == 0:
                    profile.results[char] = CharResult(char=char, status="unknown")
                    continue
                if resp.status_code in (403, 406, 429):
                    profile.results[char] = CharResult(char=char, status="blocked")
                    continue

                body = resp.text
                raw_probe = f"xscP{char}xscP"

                if raw_probe in body:
                    profile.results[char] = CharResult(char=char, status="raw")
                elif html_entity and f"xscP{html_entity}xscP" in body:
                    profile.results[char] = CharResult(
                        char=char, status="html", html_entity=html_entity
                    )
                elif f"xscP%{ord(char):02X}xscP" in body or \
                     f"xscP%{ord(char):02x}xscP" in body:
                    profile.results[char] = CharResult(char=char, status="url")
                elif "xscPxscP" in body:
                    profile.results[char] = CharResult(char=char, status="stripped")
                else:
                    profile.results[char] = CharResult(char=char, status="unknown")

            except Exception:
                profile.results[char] = CharResult(char=char, status="unknown")

        return profile

    @staticmethod
    def _get_with_param(url: str, param: str, value: str) -> httpx.Response:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        new_url = urlunparse(parsed._replace(query=new_query))
        # Use a one-shot client to avoid polluting the shared session
        with httpx.Client(follow_redirects=True, timeout=10, verify=False,
                          headers={"User-Agent": _UA}) as c:
            return c.get(new_url)
