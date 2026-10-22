"""
crawler node — BFS web crawler with structured event emission.
Migrated from prototype crawler/spider.py.

Inputs:  target_url (str)
Outputs: urls (list[str]), forms (list[dict]), urls_with_params (list[str]),
         crawl_count (int), is_spa (bool), spa_framework (str)
Config:  max_pages (int, 60), max_depth (int, 3), spa_mode (bool, auto-detect)

SPA detection:
  When the fetched HTML contains Angular/React/Vue/Ember app-root markers
  but has no links or forms, the crawler automatically switches to SPA mode
  and probes well-known REST API patterns to discover inputs.
"""
from __future__ import annotations

import re
import time
from collections import deque
from typing import Any
from urllib.parse import quote, urljoin, urlparse, urlunparse

import httpx
from bs4 import BeautifulSoup

from xscan.core.dag.node_registry import registry
from xscan.nodes.base import ExecutionContext, NodeBase
from xscan.nodes.emitter import NodeEmitter

_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"
)

# ── SPA fingerprints ──────────────────────────────────────────────────────────
# (body_regex, framework_name)
_SPA_SIGNATURES: list[tuple[str, str]] = [
    (r"<app-root",                    "Angular"),
    (r"ng-version",                   "Angular"),
    (r'id=["\']app["\']',             "React"),
    (r'id=["\']root["\']',            "React"),
    (r"__NEXT_DATA__",                "Next.js"),
    (r"<div id=[\"']app[\"']",        "Vue.js"),
    (r"createApp\(",                  "Vue.js"),
    (r"ember-application",            "Ember"),
    (r"<svelte-",                     "Svelte"),
]

# ── Well-known REST/API probe paths ───────────────────────────────────────────
# Each entry: (path, param_name, description)
#
# IMPORTANT — evidence-first principle:
#   Only probe paths that are known to exist in widely-deployed applications.
#   Do NOT invent versioned variants (/api/v1/, /api/v2/) as guesses —
#   those produce false positives when servers return 500 error pages that
#   echo the URL back in JSON (which gets misclassified as a reflection).
#
#   A probe is accepted ONLY when the server returns a 200/201/422 response
#   with an application/json or text/html Content-Type (not a framework error).
_REST_PROBES: list[tuple[str, str, str]] = [
    # Generic search — single canonical path, no versioned variants
    ("/search",                 "q",       "generic search"),
    ("/api/search",             "q",       "api search"),

    # OWASP Juice Shop — exact paths from its REST API
    ("/rest/products/search",   "q",       "juice shop product search"),
    ("/api/Feedbacks/",         "",        "juice shop feedbacks"),
    ("/api/Complaints/",        "",        "juice shop complaints"),
    ("/api/Users/",             "",        "juice shop users"),
    ("/api/Products/",          "",        "juice shop products"),

    # DVWA — exact vuln routes
    ("/vulnerabilities/xss_r/", "name",    "dvwa reflected xss"),
    ("/vulnerabilities/xss_s/", "txtName", "dvwa stored xss"),
    ("/vulnerabilities/xss_d/", "default", "dvwa dom xss"),

    # WebGoat
    ("/WebGoat/xss/",           "param",   "webgoat xss"),

    # Common web patterns only — no invented API variants
    ("/feedback",               "message", "feedback page"),
    ("/contact",                "message", "contact page"),
]

# HTTP statuses that indicate an endpoint actually exists and returns
# application content (not a framework error / redirect wall / 404).
_VALID_API_STATUSES: frozenset[int] = frozenset({200, 201, 206, 422})

# Content-Type prefixes that indicate a real application response
# (not a generic HTML error page served for every unknown path).
_VALID_CONTENT_TYPES: tuple[str, ...] = (
    "application/json",
    "text/html",         # kept for HTML form pages, but only when status is valid
)


def _is_framework_error(body_start: str, path: str) -> bool:
    """
    Return True if a response body looks like a framework-generated error page
    rather than real application content.

    These patterns indicate the endpoint doesn't exist and the framework
    is echoing back an error — which causes false-positive reflections
    when the probe value appears in the echoed URL.

    Examples:
      Express:    "cannot get /api/v1/search"
      Juice Shop: "unexpected path: /api/v1/search"
      Rails:      "routing error"
      Django:     "page not found (404)"
    """
    _ERROR_PATTERNS = (
        "cannot get ",
        "cannot post ",
        "unexpected path",
        "not found",
        "routing error",
        "page not found",
        "no route matches",
        "unknown action",
        "stack trace",
        "stacktrace",
    )
    # If the path itself appears in the body start it's being echoed by an
    # error handler (e.g. Express "Cannot GET /api/v1/search")
    if path.lower() in body_start:
        return True
    return any(p in body_start for p in _ERROR_PATTERNS)


@registry.register("crawler")
class CrawlerNode(NodeBase, NodeEmitter):

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        t0 = self.emit_started(ctx)

        target_url: str = ctx.get("target_url", "")
        if not target_url:
            raise ValueError("crawler: target_url required")

        max_pages: int = int(ctx.config.get("max_pages", 60))
        max_depth: int = int(ctx.config.get("max_depth", 3))
        # spa_mode: None=auto-detect, True=force, False=force-off
        # Can be set via workflow config OR passed as a top-level input (--spa flag)
        spa_mode_cfg = ctx.config.get("spa_mode", ctx.get("spa_mode", None))
        origin = self._origin(target_url)

        # Seed URLs — start from endpoint_urls / live_urls if a prior recon run
        # produced them (recon-only → xss-balanced handoff).
        seed_urls: list[str] = [target_url]
        recon_endpoints: list[str] = ctx.get("endpoint_urls", []) or []
        recon_live:      list[str] = ctx.get("live_urls", []) or []
        for u in recon_endpoints + recon_live:
            if u not in seed_urls and self._in_scope(self._strip_fragment(u), origin):
                seed_urls.append(u)

        visited: set[str] = set()
        forms_found: list[dict] = []
        queue: deque[tuple[str, int]] = deque((u, 0) for u in seed_urls)
        is_spa = False
        spa_framework = ""

        with httpx.Client(
            follow_redirects=True,
            timeout=ctx.config.get("http_timeout", 12),
            verify=False,
            headers={"User-Agent": _UA},
        ) as client:

            while queue and len(visited) < max_pages:
                url, depth = queue.popleft()
                url = self._strip_fragment(url)

                if url in visited or not self._in_scope(url, origin):
                    continue
                try:
                    ctx.scope.assert_allowed(url, operation="http_request")
                except Exception:
                    continue

                visited.add(url)

                if len(visited) % 5 == 0:
                    self.emit_progress(ctx, f"Crawling page {len(visited)}/{max_pages}")

                try:
                    resp = client.get(url)
                except Exception:
                    continue

                ct = resp.headers.get("content-type", "")
                if "text/html" not in ct:
                    continue

                soup = BeautifulSoup(resp.text, "html.parser")
                body_html = resp.text

                # ── SPA auto-detection on first page ─────────────────────
                if len(visited) == 1 and spa_mode_cfg is not False:
                    detected_fw = self._detect_spa(body_html)
                    if detected_fw:
                        is_spa = True
                        spa_framework = detected_fw

                if depth < max_depth:
                    for a in soup.find_all("a", href=True):
                        href = str(a["href"]).strip()
                        # Include hash-router links (/#/path) as virtual pages
                        resolved = urljoin(url, href)
                        # Keep fragment for SPA route tracking
                        resolved_no_frag = self._strip_fragment(resolved)
                        if resolved_no_frag not in visited and self._in_scope(resolved_no_frag, origin):
                            queue.append((resolved_no_frag, depth + 1))

                for form in soup.find_all("form"):
                    action = form.get("action", "") or url
                    resolved_action = urljoin(url, str(action))
                    method = (form.get("method", "get") or "get").upper()
                    inputs = []
                    for tag in form.find_all(["input", "textarea", "select"]):
                        itype = (tag.get("type", "") or "").lower()
                        if tag.name == "textarea":
                            itype = "textarea"
                        if tag.name == "select":
                            itype = "select"
                        if itype in ("submit", "button", "image", "reset", "file"):
                            continue
                        name = tag.get("name", "")
                        if name:
                            inputs.append({
                                "name":  name,
                                "type":  itype,
                                "value": tag.get("value", "") or "",
                            })
                    if inputs:
                        forms_found.append({
                            "action":     resolved_action,
                            "method":     method,
                            "inputs":     inputs,
                            "source_url": url,
                        })

            # ── SPA probe: discover API endpoints when no inputs found ────
            force_spa = spa_mode_cfg is True
            if (is_spa or force_spa) and not forms_found:
                spa_urls, spa_forms = self._probe_spa_endpoints(
                    client, target_url, origin, ctx
                )
                visited.update(spa_urls)
                forms_found.extend(spa_forms)

                if spa_forms:
                    self.emit_progress(
                        ctx,
                        f"SPA mode ({spa_framework or 'unknown'}): "
                        f"found {len(spa_forms)} injectable API endpoint(s)"
                    )
                else:
                    self.emit_warning(
                        ctx,
                        f"SPA detected ({spa_framework or 'unknown framework'}) — "
                        "static crawler found 0 inputs. "
                        "Use Playwright (--profile deep) for full JS rendering."
                    )

        urls_list = sorted(visited)
        urls_with_params = [u for u in urls_list if "?" in u]

        # ── GET forms ARE parameterised URLs ──────────────────────────
        # A GET form's action + inputs is exactly a URL with parameters, but
        # the crawler only records it as a form. Parameter-only analysis stages
        # (DOM/CSTI detection, sanitizer + tooling probes) read urls_with_params
        # and would otherwise never see a reflected GET-form parameter — e.g.
        # the classic AngularJS ``?search=`` client-side template-injection lab.
        for form in forms_found:
            if (form.get("method") or "GET").upper() != "GET":
                continue
            action = str(form.get("action") or target_url)
            for inp in form.get("inputs", []):
                name = str(inp.get("name") or "")
                if not name:
                    continue
                value = str(inp.get("value") or "")
                sep = "&" if "?" in action else "?"
                urls_with_params.append(f"{action}{sep}{quote(name)}={quote(value)}")

        # Deduplicate the merged list, preserving discovery order.
        seen_params: set[str] = set()
        deduped_params: list[str] = []
        for u in urls_with_params:
            if u not in seen_params:
                seen_params.add(u)
                deduped_params.append(u)
        urls_with_params = deduped_params

        inputs_count = sum(len(f["inputs"]) for f in forms_found)

        ms = (time.monotonic() - t0) * 1000
        self.emit_completed(ctx, metrics={
            "urls_discovered":  len(urls_list),
            "forms":            len(forms_found),
            "inputs":           inputs_count,
            "param_urls":       len(urls_with_params),
        }, duration_ms=ms)

        return {
            "urls":             urls_list,
            "forms":            forms_found,
            "urls_with_params": urls_with_params,
            "crawl_count":      len(visited),
            "inputs_count":     inputs_count,
            "is_spa":           is_spa,
            "spa_framework":    spa_framework,
        }

    # ------------------------------------------------------------------
    # SPA helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_spa(html: str) -> str:
        """Return framework name if the page looks like a SPA shell, else ''."""
        for pattern, framework in _SPA_SIGNATURES:
            if re.search(pattern, html, re.I):
                return framework
        return ""

    def _probe_spa_endpoints(
        self,
        client: httpx.Client,
        target_url: str,
        origin: str,
        ctx: ExecutionContext,
    ) -> tuple[set[str], list[dict]]:
        """
        Probe well-known REST/API paths and build synthetic form records
        ONLY for endpoints that return a valid application response.

        A valid response is:
          - HTTP status in _VALID_API_STATUSES (200, 201, 206, 422)
          - Content-Type is application/json or text/html
          - NOT a framework error page (body doesn't start with
            generic error markers like "Cannot GET", "Unexpected path",
            "<!DOCTYPE html>" from a catch-all error handler)

        Returns: (discovered_urls, synthetic_forms)
        """
        found_urls: set[str] = set()
        found_forms: list[dict] = []
        base = origin

        for path, param, description in _REST_PROBES:
            url = base + path
            try:
                ctx.scope.assert_allowed(url, operation="http_request")
            except Exception:
                continue

            try:
                probe_url = f"{url}?{param}=xscProbe" if param else url
                r = client.get(probe_url, timeout=6)

                # Strict allowlist — any other status means the endpoint
                # doesn't exist or requires auth we don't have
                if r.status_code not in _VALID_API_STATUSES:
                    continue

                # Verify the response looks like real application content
                ct = r.headers.get("content-type", "").lower()
                if not any(ct.startswith(t) for t in _VALID_CONTENT_TYPES):
                    continue

                # Reject framework error pages that happen to return 200/422
                # These echo the path/query back in the body, causing false
                # positive reflections (e.g. Express "Cannot GET /api/v1/...")
                body_start = r.text[:200].lower()
                if _is_framework_error(body_start, path):
                    continue

                found_urls.add(url)
                if param:
                    found_forms.append({
                        "action":      url,
                        "method":      "GET",
                        "inputs":      [{"name": param, "type": "text", "value": ""}],
                        "source_url":  url,
                        "description": description,
                        "is_api":      True,
                        "baseline_status": r.status_code,
                        "baseline_ct":     ct,
                    })
                    found_urls.add(probe_url)

                # POST+JSON: only add if endpoint explicitly accepts POST
                # (indicated by 200/201/422; 405 means method not allowed)
                if param:
                    try:
                        jr = client.post(
                            url,
                            json={param: "xscProbe"},
                            timeout=6,
                            headers={"Content-Type": "application/json"},
                        )
                        if jr.status_code in _VALID_API_STATUSES:
                            jct = jr.headers.get("content-type", "").lower()
                            jbody = jr.text[:200].lower()
                            if (any(jct.startswith(t) for t in _VALID_CONTENT_TYPES)
                                    and not _is_framework_error(jbody, path)):
                                found_forms.append({
                                    "action":       url,
                                    "method":       "POST",
                                    "inputs":       [{"name": param, "type": "text", "value": ""}],
                                    "source_url":   url,
                                    "description":  f"{description} (POST/JSON)",
                                    "is_api":       True,
                                    "content_type": "application/json",
                                    "baseline_status": jr.status_code,
                                    "baseline_ct":     jct,
                                })
                    except Exception:
                        pass

            except Exception:
                continue

        return found_urls, found_forms

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _origin(url: str) -> str:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    @staticmethod
    def _in_scope(url: str, origin: str) -> bool:
        p = urlparse(url)
        return p.scheme in ("http", "https") and f"{p.scheme}://{p.netloc}" == origin

    @staticmethod
    def _strip_fragment(url: str) -> str:
        p = urlparse(url)
        return urlunparse(p._replace(fragment=""))
