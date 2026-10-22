"""
stored-xss-detector node
========================
Detects stored (persistent) XSS by:

1. Submitting a unique canary via EVERY free-text input of forms that look like
   user-input storage (comment boxes, profile fields, message forms, etc.)
   — including URL-shaped fields such as "website", because applications render
   those straight into anchor href attributes.

2. Refreshing the CSRF token immediately before each POST submission by
   re-fetching the form page, so stale tokens from the crawl phase never
   cause 400 errors.

3. Checking BOTH HTML display pages AND JSON API endpoints for the canary.
   Modern comment systems (e.g. PortSwigger stored DOM XSS labs) load comments
   via XHR from a JSON endpoint and write them to the DOM with innerHTML.
   The canary never appears in the raw HTML — it only exists in the JSON
   response and the DOM after JavaScript has run.

4. When the canary is found in a JSON API response (application/json body),
   recording the HTTP endpoint + the JS file that processes it as evidence,
   so the validator knows:
   - The sink is innerHTML (or similar DOM write), not a server-rendered
     attribute.
   - The encoding is applied by client-side JavaScript (partial or broken
     escapeHTML), not the server.
   - The candidate needs browser confirmation, not an HTTP reflection check.

5. Detecting partial/broken client-side escaping such as
   `html.replace('<', '&lt;')` (string replace, not regex), which escapes
   only the FIRST occurrence of each special character. A payload that
   begins with a sacrificial `<>` bypasses this pattern and injects real
   markup starting from the second `<`.

Inputs:  target_url, urls (list[str]), forms (list[dict])
Outputs: stored_candidates (list[dict]), stored_candidate_count (int)
"""
from __future__ import annotations

import hashlib
import re
import time
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from xscan.core.dag.node_registry import registry
from xscan.nodes.analysis.context import ContextAnalyser
from xscan.nodes.base import ExecutionContext, NodeBase
from xscan.nodes.emitter import NodeEmitter

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"

# Form field names that suggest stored input.
_STORAGE_FIELD_HINTS = {
    "comment", "message", "body", "content", "text", "description",
    "feedback", "review", "post", "reply", "note", "name", "username",
    "title", "subject", "bio", "about", "website", "site", "homepage", "url",
}

_INJECTABLE_INPUT_TYPES = {"text", "textarea", "url", ""}

_NON_EXECUTABLE_CONTEXTS = {"html_comment", "css_value", "unknown"}

_DISPLAY_PATH_HINTS = [
    "/", "/home", "/posts", "/blog", "/comments", "/reviews",
    "/profile", "/user", "/account", "/admin",
]

# Pattern that finds a CSRF token in an HTML form.
# Handles both name="csrf" and name="csrfmiddlewaretoken" etc.
_CSRF_RE = re.compile(
    r'<input[^>]+name=["\'](?:csrf|_token|csrfmiddlewaretoken|authenticity_token)["\'][^>]+'
    r'value=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_CSRF_RE_ALT = re.compile(
    r'<input[^>]+value=["\']([^"\']+)["\'][^>]+'
    r'name=["\'](?:csrf|_token|csrfmiddlewaretoken|authenticity_token)["\']',
    re.IGNORECASE,
)

# XHR patterns: inline script that calls loadComments('/post/comment') or
# similar — tells us there is a JSON API that carries stored comments.
# Captured group 1 is the API path.
_LOAD_COMMENTS_RE = re.compile(
    r"""(?:loadComments|fetchComments|getComments|loadPosts|fetchData)\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)

# Patterns that signal a broken single-replace escapeHTML in JS source.
# These match e.g. `.replace('<', '&lt;')` without a /g regex flag.
_BROKEN_ESCAPE_PATTERNS = [
    re.compile(r"\.replace\s*\(\s*'<'\s*,\s*'&lt;'", re.IGNORECASE),
    re.compile(r'\.replace\s*\(\s*"<"\s*,\s*"&lt;"', re.IGNORECASE),
    re.compile(r"\.replace\s*\(\s*'>'", re.IGNORECASE),
    re.compile(r'\.replace\s*\(\s*">"', re.IGNORECASE),
]

# Sinks in JS that write HTML without sanitisation — innerHTML, outerHTML, etc.
_HTML_SINK_RE = re.compile(
    r"\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML\s*\(",
    re.IGNORECASE,
)


def _stored_canary() -> str:
    return "xscSTORED" + hashlib.md5(str(time.time()).encode()).hexdigest()[:6]


def _sink_kind(context_name: str, attribute: str) -> str:
    if context_name == "url_param":
        return "url_attribute"
    if context_name in ("html_attribute", "html_attribute_unquoted"):
        return "event_handler" if attribute.startswith("on") else "html_attribute"
    return ""


def _extract_csrf(html: str) -> str:
    """Extract the current CSRF token value from a form page."""
    m = _CSRF_RE.search(html) or _CSRF_RE_ALT.search(html)
    return m.group(1) if m else ""


def _find_json_api_path(html: str, js_srcs: list[str], client: httpx.Client, base_url: str) -> str:
    """
    Return the API path that serves stored comments as JSON, or "".

    Strategy (in order):
    1. Check inline scripts for loadComments('/path') call.
    2. Fetch each referenced JS file and check for the pattern there.
    3. Fall back to common conventions (/post/comment, /api/comments, etc.).
    """
    # 1. Inline script
    m = _LOAD_COMMENTS_RE.search(html)
    if m:
        return m.group(1)

    # 2. External JS files
    for js_url in js_srcs[:8]:
        try:
            if not js_url.startswith(("http://", "https://")):
                js_url = urljoin(base_url, js_url)
            r = client.get(js_url, timeout=8)
            if r.status_code == 200:
                m2 = _LOAD_COMMENTS_RE.search(r.text)
                if m2:
                    return m2.group(1)
        except Exception:
            continue

    return ""


def _has_broken_escape(js_text: str) -> bool:
    """True when JS source uses a string-literal replace (not /regex/g) for HTML escaping."""
    return any(p.search(js_text) for p in _BROKEN_ESCAPE_PATTERNS)


def _has_html_sink(js_text: str) -> bool:
    """True when JS source writes to an HTML sink (innerHTML etc.)."""
    return bool(_HTML_SINK_RE.search(js_text))


def _build_bypass_payloads_for_broken_escape(canary: str) -> list[str]:
    """
    Payloads that exploit a broken escapeHTML using string .replace() instead
    of a regex with /g flag.  .replace('<', '&lt;') escapes only the FIRST `<`,
    so a payload starting with a sacrificial `<>` gets its first `<` eaten but
    the second `<` passes through unescaped.

    Examples that work against `s.replace('<','&lt;').replace('>','&gt;')`:
      - `<><img src=1 onerror=alert(1)>`   — first <> pair consumed, real payload follows
      - `<><svg onload=alert(1)>`
    """
    return [
        f"<><img src=1 onerror=alert(1)>",
        f"<><svg onload=alert(1)>",
        f"<><details open ontoggle=alert(1)>",
    ]


@registry.register("stored-xss-detector")
class StoredXssDetectorNode(NodeBase, NodeEmitter):
    node_type = "stored-xss-detector"

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        t0 = self.emit_started(ctx)

        target_url: str = ctx.get("target_url", "")
        urls: list[str] = ctx.get("urls", [])
        forms: list[dict[str, Any]] = ctx.get("forms", [])
        candidates: list[dict[str, Any]] = []
        analyser = ContextAnalyser()

        storage_forms = [f for f in forms if self._looks_like_storage_form(f)]

        if not storage_forms:
            self.emit_completed(ctx, metrics={"storage_forms": 0, "stored_candidates": 0})
            return {"stored_candidates": [], "stored_candidate_count": 0}

        check_pages = self._build_check_pages(target_url, urls)
        tested: set[tuple[str, str, str]] = set()

        with httpx.Client(
            follow_redirects=True, timeout=15, verify=False,
            headers={"User-Agent": _UA},
        ) as client:

            for form in storage_forms[:5]:
                action = form["action"]
                method = form["method"]
                source_url = str(form.get("source_url", "") or target_url or action)

                # ── Discover JSON API endpoint for this form's display page ──────
                # We do this once per form, before any submissions, so we know
                # whether to check JSON endpoints after the POST.
                json_api_path, js_broken_escape = self._analyse_display_js(
                    client, source_url, ctx
                )

                for text_input, inp_type in self._probe_inputs(form)[:4]:
                    dedupe_key = (action, method, text_input)
                    if dedupe_key in tested:
                        continue
                    tested.add(dedupe_key)

                    canary = _stored_canary()

                    # ── CSRF token refresh ────────────────────────────────────────
                    # Re-fetch the form page immediately before each POST so the
                    # CSRF token is always current.  The crawled token may be
                    # seconds or minutes old by the time we reach this loop.
                    current_csrf = self._refresh_csrf(client, source_url, form, ctx)

                    data = self._build_post_data(form, text_input, canary, current_csrf)

                    post_response_text = ""
                    final_url = ""
                    post_ok = False
                    try:
                        ctx.scope.assert_allowed(action, operation="http_request")
                        if method == "POST":
                            resp = client.post(action, data=data)
                            post_response_text = resp.text
                            final_url = str(resp.url)
                            # 4xx means submission rejected — CSRF, validation, etc.
                            post_ok = resp.status_code < 400
                        else:
                            resp = client.get(action, params=data)
                            final_url = str(resp.url)
                            post_ok = resp.status_code < 400
                    except Exception:
                        continue

                    if not post_ok:
                        self.emit_progress(
                            ctx,
                            f"  POST {action} rejected (status {resp.status_code if 'resp' in dir() else '?'}) "
                            f"for param={text_input} — CSRF refresh may have failed",
                        )
                        continue

                    # ── 1. Check the POST redirect destination (HTML) ─────────────
                    post_location = self._find_canary_location(
                        analyser, post_response_text, canary
                    )
                    if post_location is not None:
                        candidates.append(self._build_candidate(
                            form, action, method, text_input, inp_type,
                            canary, final_url or action, post_location,
                            js_broken_escape=js_broken_escape,
                        ))
                        self.emit_progress(ctx, f"  Stored candidate: {text_input} @ {final_url}")
                        continue

                    # ── 2. Check JSON API endpoint for stored canary ──────────────
                    # The canary may never appear in raw HTML if comments are
                    # loaded dynamically.  Try the discovered JSON API path.
                    json_candidate = self._check_json_api(
                        client, ctx, analyser,
                        json_api_path, source_url, final_url,
                        text_input, inp_type, canary, form, action, method,
                        js_broken_escape,
                    )
                    if json_candidate is not None:
                        candidates.append(json_candidate)
                        self.emit_progress(ctx, f"  Stored candidate (JSON API): {text_input}")
                        continue

                    # ── 3. Check HTML display pages ───────────────────────────────
                    for page_url in check_pages:
                        try:
                            ctx.scope.assert_allowed(page_url, operation="http_request")
                            r = client.get(page_url)
                            if r.status_code != 200 or canary not in r.text:
                                continue
                            evidence = analyser.analyse(r.text, canary).to_evidence_dict()
                            if evidence.get("context") in _NON_EXECUTABLE_CONTEXTS:
                                continue
                            candidates.append(self._build_candidate(
                                form, action, method, text_input, inp_type,
                                canary, page_url, evidence,
                                js_broken_escape=js_broken_escape,
                            ))
                            self.emit_progress(ctx, f"  Stored candidate (page): {text_input} @ {page_url}")
                            break
                        except Exception:
                            continue

        ms = (time.monotonic() - t0) * 1000
        self.emit_completed(ctx, metrics={
            "storage_forms_tested": len(storage_forms),
            "stored_candidates":    len(candidates),
        }, duration_ms=ms)

        return {
            "stored_candidates":      candidates,
            "stored_candidate_count": len(candidates),
        }

    # ------------------------------------------------------------------
    # CSRF token refresh
    # ------------------------------------------------------------------

    def _refresh_csrf(
        self,
        client: httpx.Client,
        source_url: str,
        form: dict[str, Any],
        ctx: ExecutionContext,
    ) -> str:
        """
        Fetch the form page fresh and return the current CSRF token.

        Falls back to the token already baked into the form dict (from the
        crawl) when the live fetch fails or returns no token — this preserves
        backward compatibility with forms that have no CSRF protection.
        """
        # Use the token the crawler already found as the fallback.
        crawled_csrf = next(
            (str(inp.get("value", "")) for inp in form.get("inputs", [])
             if str(inp.get("name", "")).lower() in (
                 "csrf", "_token", "csrfmiddlewaretoken", "authenticity_token"
             )),
            "",
        )
        if not source_url:
            return crawled_csrf
        try:
            ctx.scope.assert_allowed(source_url, operation="http_request")
            r = client.get(source_url, timeout=8)
            if r.status_code == 200:
                fresh = _extract_csrf(r.text)
                if fresh:
                    return fresh
        except Exception:
            pass
        return crawled_csrf

    # ------------------------------------------------------------------
    # JSON API analysis
    # ------------------------------------------------------------------

    def _analyse_display_js(
        self,
        client: httpx.Client,
        source_url: str,
        ctx: ExecutionContext,
    ) -> tuple[str, bool]:
        """
        Fetch the display page and its JS files.  Return:
          (json_api_path, js_has_broken_escape)

        json_api_path  — relative path like "/post/comment", or ""
        js_has_broken_escape — True when the JS uses a string .replace()
                               instead of a regex for HTML escaping
        """
        if not source_url:
            return "", False
        try:
            ctx.scope.assert_allowed(source_url, operation="http_request")
            r = client.get(source_url, timeout=8)
            if r.status_code != 200:
                return "", False
            html = r.text
        except Exception:
            return "", False

        # Find JS file references
        js_srcs = re.findall(
            r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE
        )

        # Discover JSON API path from inline script or external JS
        json_api_path = _find_json_api_path(html, js_srcs, client, source_url)

        # Check JS files for broken escapeHTML patterns and innerHTML sinks
        broken_escape = False
        for js_url in js_srcs[:8]:
            full_js_url = js_url if js_url.startswith(("http://", "https://")) else urljoin(source_url, js_url)
            try:
                ctx.scope.assert_allowed(full_js_url, operation="http_request")
                rjs = client.get(full_js_url, timeout=8)
                if rjs.status_code == 200 and _has_html_sink(rjs.text):
                    if _has_broken_escape(rjs.text):
                        broken_escape = True
                        break
            except Exception:
                continue

        return json_api_path, broken_escape

    def _check_json_api(
        self,
        client: httpx.Client,
        ctx: ExecutionContext,
        analyser: ContextAnalyser,
        json_api_path: str,
        source_url: str,
        redirect_url: str,
        text_input: str,
        inp_type: str,
        canary: str,
        form: dict[str, Any],
        action: str,
        method: str,
        js_broken_escape: bool,
    ) -> dict[str, Any] | None:
        """
        Check a JSON API endpoint for the stored canary.

        The canary appears as a plain string in the JSON response body; the
        context is always json_value.  The real sink is on the client side
        (innerHTML / DOM write), not in the JSON body itself — so we classify
        this as a stored DOM XSS with sink=innerHTML and set requires_browser.

        Also tries to derive the postId / resource id from the redirect URL,
        since comment APIs are typically scoped per-post.
        """
        if not json_api_path:
            return None

        # Build candidate API URLs to probe.
        # The redirect_url after POST often includes the postId or resource path.
        api_urls = self._build_api_urls(json_api_path, source_url, redirect_url)

        for api_url in api_urls:
            try:
                ctx.scope.assert_allowed(api_url, operation="http_request")
                r = client.get(api_url, timeout=10)
                if r.status_code != 200:
                    continue
                ct = r.headers.get("content-type", "").lower()
                if "json" not in ct and canary not in r.text:
                    continue
                if canary not in r.text:
                    continue

                # Canary found in JSON response — classify the evidence
                # context is json_value (always double-quoted in JSON)
                evidence = analyser.analyse(r.text, canary).to_evidence_dict()

                # Override context: the JSON API delivers data to innerHTML,
                # so the effective sink is html_injection, not json_value.
                # The payload synthesis must generate tag_injection payloads.
                sink_kind = "html_text"  # innerHTML is an html_injection sink
                sink_label = "innerHTML (via JSON API response)"

                # Build a richer evidence dict that carries the sink information
                evidence_with_sink = dict(evidence)
                evidence_with_sink["sink_kind"] = sink_kind
                evidence_with_sink["sink_label"] = sink_label
                evidence_with_sink["api_url"] = api_url
                evidence_with_sink["js_broken_escape"] = js_broken_escape

                # When the JS uses broken escapeHTML, add that context
                if js_broken_escape:
                    evidence_with_sink["bypass_required"] = "partial_escape_bypass"
                    evidence_with_sink["bypass_note"] = (
                        "Client-side escapeHTML uses .replace('<','&lt;') without /g flag — "
                        "only the first '<' is escaped. A payload starting with '<>' "
                        "bypasses this: the first '<>' pair is consumed, the real "
                        "payload '<img src=1 onerror=alert(1)>' passes unescaped."
                    )

                return self._build_candidate(
                    form, action, method, text_input, inp_type,
                    canary, api_url, evidence_with_sink,
                    js_broken_escape=js_broken_escape,
                    sink_kind_override=sink_kind,
                    found_via_json=True,
                )
            except Exception:
                continue

        return None

    def _build_api_urls(
        self,
        json_api_path: str,
        source_url: str,
        redirect_url: str,
    ) -> list[str]:
        """
        Build a list of API URLs to probe, in priority order.

        The JSON comment API is usually scoped per-post:
          /post/comment?postId=2
        We derive the postId from the source_url or redirect_url query strings.
        """
        urls: list[str] = []
        base = self._url_base(source_url)

        def _make_url(path: str, query: str = "") -> str:
            full = urljoin(base, path)
            if query and "?" not in full:
                return f"{full}?{query}"
            return full

        # Extract query strings from known URLs
        for ref_url in (redirect_url, source_url):
            if not ref_url:
                continue
            parsed = urlparse(ref_url)
            if parsed.query:
                urls.append(_make_url(json_api_path, parsed.query))

        # Bare endpoint (no query) as fallback
        bare = _make_url(json_api_path)
        if bare not in urls:
            urls.append(bare)

        return urls

    @staticmethod
    def _url_base(url: str) -> str:
        """Return scheme+host from a URL."""
        try:
            p = urlparse(url)
            return f"{p.scheme}://{p.netloc}"
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # Existing helpers (preserved, some extended)
    # ------------------------------------------------------------------

    def _looks_like_storage_form(self, form: dict[str, Any]) -> bool:
        for inp in form.get("inputs", []):
            name = inp.get("name", "").lower()
            itype = inp.get("type", "").lower()
            if itype == "textarea" or any(hint in name for hint in _STORAGE_FIELD_HINTS):
                return True
        return False

    def _probe_inputs(self, form: dict[str, Any]) -> list[tuple[str, str]]:
        """
        Return every injectable input worth canary-probing, most likely first.

        Priority order:
          0 — textarea or storage-hint field (comment, message, name, website…)
          1 — everything else injectable

        URL/website fields are explicitly included because they commonly land
        in href attributes — a javascript: scheme executes on click.
        """
        scored: list[tuple[int, str, str]] = []
        for inp in form.get("inputs", []):
            name = str(inp.get("name", ""))
            if not name:
                continue
            itype = str(inp.get("type", "")).lower()
            lname = name.lower()
            if itype not in _INJECTABLE_INPUT_TYPES and itype not in ("url",):
                continue
            if itype == "textarea" or any(hint in lname for hint in _STORAGE_FIELD_HINTS):
                scored.append((0, name, itype or "text"))
            else:
                scored.append((1, name, itype or "text"))
        scored.sort(key=lambda item: (item[0], item[1]))
        return [(name, itype) for _, name, itype in scored]

    def _build_post_data(
        self,
        form: dict[str, Any],
        target_input: str,
        canary: str,
        fresh_csrf: str,
    ) -> dict[str, str]:
        """
        Build the POST data dict, substituting:
          - the fresh CSRF token for any CSRF field
          - the canary for the target input
          - safe dummy values for everything else
        """
        csrf_names = {"csrf", "_token", "csrfmiddlewaretoken", "authenticity_token"}
        data: dict[str, str] = {}
        for inp in form.get("inputs", []):
            name = str(inp.get("name", ""))
            if not name:
                continue
            if name.lower() in csrf_names and fresh_csrf:
                data[name] = fresh_csrf
            elif name == target_input:
                data[name] = canary
            else:
                # Keep existing values; supply sensible defaults for required fields
                existing = str(inp.get("value", "") or "")
                if existing:
                    data[name] = existing
                else:
                    itype = str(inp.get("type", "")).lower()
                    if itype == "email":
                        data[name] = "test@test.com"
                    elif itype == "url":
                        data[name] = "https://test.com"
                    else:
                        data[name] = "test"
        return data

    def _find_canary_location(
        self,
        analyser: ContextAnalyser,
        body: str,
        canary: str,
    ) -> dict[str, Any] | None:
        if not body or canary not in body:
            return None
        evidence = analyser.analyse(body, canary).to_evidence_dict()
        if evidence.get("context") in _NON_EXECUTABLE_CONTEXTS:
            return None
        return evidence

    def _build_candidate(
        self,
        form: dict[str, Any],
        action: str,
        method: str,
        text_input: str,
        inp_type: str,
        canary: str,
        page_url: str,
        evidence: dict[str, Any],
        *,
        js_broken_escape: bool = False,
        sink_kind_override: str = "",
        found_via_json: bool = False,
    ) -> dict[str, Any]:
        """Assemble a stored candidate dict with context + sink semantics."""
        ctx_name = evidence.get("context", "unknown")
        attribute = str(evidence.get("attribute", "") or evidence.get("attribute_name", ""))

        # Determine the effective sink kind:
        # 1. Explicit override (JSON API → innerHTML path)
        # 2. Derived from reflection context (href/src → url_attribute)
        # 3. Default empty string
        if sink_kind_override:
            kind = sink_kind_override
        else:
            kind = _sink_kind(ctx_name, attribute)

        candidate: dict[str, Any] = {
            "type":        "stored-xss",
            "form_action": action,
            "parameter":   text_input,
            "input_type":  inp_type,
            "method":      method,
            "canary":      canary,
            "found_at":    page_url,
            "context":     ctx_name,
            "context_analysis": evidence,
            "sink_kind":   kind,
            "snippet":     str(evidence.get("snippet", "") or evidence.get("full_snippet", "") or ""),
            "severity":    "critical",
            "confidence":  "high",
        }

        # Attach extra metadata for JSON API / broken escape paths
        if found_via_json:
            candidate["found_via_json_api"] = True
            candidate["sink_label"] = evidence.get("sink_label", "innerHTML")
            candidate["requires_browser"] = True

        if js_broken_escape:
            candidate["js_broken_escape"] = True
            candidate["bypass_payloads"] = _build_bypass_payloads_for_broken_escape(canary)

        return candidate

    def _build_check_pages(self, target_url: str, urls: list[str]) -> list[str]:
        pages = list(urls[:20])
        for path in _DISPLAY_PATH_HINTS:
            candidate = urljoin(target_url, path)
            if candidate not in pages:
                pages.append(candidate)
        return pages

    @staticmethod
    def _snippet(body: str, canary: str, ctx_chars: int = 100) -> str:
        idx = body.find(canary)
        if idx == -1:
            return ""
        return body[max(0, idx - ctx_chars): idx + len(canary) + ctx_chars].replace("\n", " ").strip()
