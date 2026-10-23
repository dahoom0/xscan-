"""
dom-xss-detector node
=====================
Static DOM XSS analysis across every crawled page.

DOM XSS never reaches the server: the tainted value is read in the browser and
written straight into a sink. So this node:

  1. Inventories the JavaScript of *all* crawled URLs (inline + external),
     not just the entry page.
  2. Matches source -> sink pairs using the knowledge registry
     (knowledge/sources.yaml, knowledge/sinks.yaml).
  3. Resolves the sink *context* — which attribute, what the sink does with its
     input — so the payload family matches the sink: a ``javascript:`` URI for
     an href sink, markup for innerHTML, a JS expression for eval.
  4. Binds each payload to the parameter the page actually reads, taken from the
     crawl (urls_with_params) and from the JS itself
     (``URLSearchParams.get('returnPath')``).
  5. Emits sink_kind / interaction / requires_browser so the browser
     confirmation node knows how to trigger the sink (click, event, submit).

Inputs:  target_url, urls (list[str]), urls_with_params (list[str]),
         js_files (list[dict]) — optional, reuses the js-extract inventory
Outputs: dom_candidates (list[dict]), dom_candidate_count (int)
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from dataclasses import replace as _dc_replace
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import httpx

from xscan.core.dag.node_registry import registry
from xscan.knowledge import xss_knowledge
from xscan.nodes.analysis.dom_xss_diagnostics import (
    DOMAnalysisMetrics,
    FileAnalysisMetrics,
    SourceAnalysisMetrics,
    log_file_analysis,
    log_overall_metrics,
)
from xscan.nodes.base import ExecutionContext, NodeBase
from xscan.nodes.emitter import NodeEmitter
from xscan.schemas.source_sink_registry import sink_registry, source_registry

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"

_MAX_PAGES = 10
_MAX_JS_PER_PAGE = 15
_MAX_CANDIDATES = 30
_MAX_PARAMS_PER_CANDIDATE = 2

# Attributes whose value is a URL — a javascript: URI is the exploit.
_URL_ATTRIBUTES = {
    "href", "src", "action", "formaction", "xlink:href", "data", "poster", "codebase",
}

# Attribute-name resolution for sinks that write to a named attribute.
_ATTR_NAME_RE = re.compile(r"\.attr\s*\(\s*['\"]([\w-]+)['\"]", re.I)
_ATTR_NAME_SET_RE = re.compile(
    r"\.setAttribute\s*\(\s*['\"]([\w-]+)['\"]", re.I
)

# Parameter names the page reads from the query string.
_PARAM_GET_RE = re.compile(
    r"URLSearchParams[^\n;]{0,80}?\.get\s*\(\s*['\"]([\w-]+)['\"]", re.I
)
_PARAM_SPLIT_RE = re.compile(r"[?&]([\w-]+)=", re.I)

# XHR / fetch endpoints: a sink fed by ``responseText`` / ``.json()`` means the
# reflection lives in the API response, not the HTML page — the validator must
# probe that endpoint or it will report the parameter as unreflected.
_API_ENDPOINT_RE = re.compile(
    r"(?:fetch|\.open|\.get|\.post|\$\.(?:get|post|ajax)|axios[.\[])[\s\S]{0,40}?"
    r"['\"]([^'\"\s]+\?(?:[\w%\-]+)=[^'\"\s]*)['\"]",
    re.I,
)
_XHR_RESPONSE_RE = re.compile(
    r"responseText|\.response\b|\.json\s*\(|responseXML", re.I
)
# When eval()/innerHTML is fed from responseText/responseJSON and an XHR call
# is visible in the SAME context window, the sink is driven by the *server
# response*, not directly by the browser source.  Static analysis cannot
# confirm whether the reflection is exploitable — it depends on what the server
# sends back.  Emit this flow as an api_eval_endpoint rather than a DOM
# candidate so the reflection pipeline (candidate-gen + EvalJsonFlowAnalyzer)
# handles it correctly.  Raising it as a DOM candidate leads to
# "no unencoded reflection found" false-negatives.
_EVAL_RESPONSE_SINK_RE = re.compile(
    r"eval\s*\([^)]*(?:this\.responseText|responseText|\.response)\s*\)",
    re.IGNORECASE,
)
# Location of the XHR endpoint: xhr.open('GET', '/path' + ...) or
# fetch('/path' + ...) or similar.  The full open() call without a hardcoded
# query string (path + location.search) is also matched.
_XHR_OPEN_PATH_RE = re.compile(
    r"""(?:xhr|request|http)\.open\s*\(\s*['"]GET['"]\s*,\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
_FETCH_PATH_RE = re.compile(
    r"""fetch\s*\(\s*['"]([^'"?]+)['"]""",
    re.IGNORECASE,
)

# $(function () {...}) / $(() => {...}) is jQuery's DOM-ready wiring, not a sink:
# the tainted value written inside the callback is the flow worth reporting.
_JQUERY_READY_RE = re.compile(
    r"\$\s*\(\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*=>|[\w$]+\s*=>)",
    re.I,
)

# The same page can be crawled under several URL spellings (with/without a
# trailing slash, different fragments). They are one page — matching it twice
# yields duplicate candidates with different test URLs for the same flow.
_PAGE_NORMALISE_RE = re.compile(r"#.*$")

# Bundled framework code is not application code: an AngularJS bundle contains
# dozens of $eval/.attr()/location handling snippets that light up source->sink
# regexes, producing untestable candidates against the framework itself. Only
# ANALYSE FIRST-PARTY script when it looks like a vendor bundle.
_VENDOR_URL_RE = re.compile(
    r"(?:angular|angularjs|jquery|react|vue(?:\.runtime)?|bootstrap|lodash|moment)"
    r"[\w.\-]*\.m?js(?:[?#]|$)",
    re.I,
)
_VENDOR_CONTENT_RE = re.compile(
    r"(?:window\.angular|angular\.version|\$\$minErr|angular\.Module)",
)


def _is_vendor_js(js_url: str, content: str) -> bool:
    """True when a script unit is bundled framework code, not application code."""
    if _VENDOR_URL_RE.search(js_url):
        return True
    # Content fallback: AngularJS internals (minErr machinery etc.) never
    # appear in first-party application scripts.
    return bool(_VENDOR_CONTENT_RE.search(content))


# An active AngularJS application: the template engine compiles the DOM, so
# reflected {{ ... }} expressions are evaluated client-side (CSTI).
_NG_APP_RE = re.compile(r"<[^>]+(?:data-)?ng-app\b", re.I)

# Reflection probes for the AngularJS template-injection detector.
_MAX_CSTI_PROBES = 6


def normalise_page_url(url: str) -> str:
    """Canonical form of a page URL: no fragment, no trailing slash."""
    stripped = _PAGE_NORMALISE_RE.sub("", url.strip())
    return stripped.rstrip("/") or stripped


# Payload families by sink kind — reviewed, hardcoded (never LLM-generated).
_PAYLOADS_BY_KIND: dict[str, list[str]] = {
    "url_attribute": [
        "javascript:alert(document.cookie)",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ],
    "html_text": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<script>alert(1)</script>",
    ],
    "html_attribute": [
        '" onmouseover="alert(1)',
        "' onmouseover='alert(1)'",
        '" autofocus onfocus="alert(1)',
    ],
    "event_handler": ["alert(1)", "javascript:alert(1)"],
    "js_execution": ["alert(1)", "';alert(1)//"],
    "selector": ["<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"],
    "selector_hashchange": [
        "<img src=x onerror=print()>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "navigation": ["javascript:alert(1)"],
}

_DEFAULT_PAYLOADS = ["<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"]

# AngularJS client-side template injection (CSTI): the server reflects a value
# into a page with an active ng-app scope, so ``{{ ... }}`` is evaluated by
# Angular's template engine — the sandbox escape runs on page load, no click
# needed. Markup payloads are useless here when the server encodes < and >.
ANGULAR_CSTI_PAYLOADS = [
    "{{$on.constructor('alert(1)')()}}",
    "{{constructor.constructor('alert(1)')()}}",
]

# When one of these matched, a generic jQuery selector match on the same code is
# the same flow reported twice with a weaker payload.
_ATTRIBUTE_SINK_IDS = {"jquery_attr", "set_attribute_url", "set_attribute_on", "jQuery.attr", "setAttribute", "jQuery.html"}


@dataclass
class SinkContext:
    """Resolved meaning of a matched sink: what it writes and how it triggers."""
    label: str
    kind: str
    interaction: str          # none | click | event | submit
    attribute: str = ""
    severity: str = "high"
    requires_browser: bool = True


def _is_xhr_eval_flow(sink_entry_id: str, context_window: str) -> bool:
    """
    Return True when an eval/innerHTML sink in *context_window* is fed
    from an XHR/fetch responseText rather than directly from a browser
    source (location.search, location.hash, etc.).

    These flows must be handled by the reflection pipeline
    (candidate-gen + EvalJsonFlowAnalyzer), NOT by static DOM analysis.
    Static analysis cannot determine the server's escaping behaviour; if
    we raise a DOM candidate the iterative validator will find no unencoded
    reflection in the HTML page response and incorrectly mark it inconclusive.
    """
    if sink_entry_id not in ("eval_call", "eval", "inner_html", "innerHTML",
                             "document_write"):
        return False
    # An XHR response feeds this eval — the sink lives server-side.
    return bool(_EVAL_RESPONSE_SINK_RE.search(context_window))


def _extract_xhr_eval_endpoint(context_window: str, page_url: str) -> dict[str, str] | None:
    """
    Extract the API endpoint and source parameter from a confirmed
    XHR→eval() flow, ready for api_eval_endpoints output key.
    """
    endpoint = ""
    m = _XHR_OPEN_PATH_RE.search(context_window)
    if m:
        endpoint = m.group(1)
    else:
        m = _FETCH_PATH_RE.search(context_window)
        if m:
            endpoint = m.group(1)
    if not endpoint:
        return None

    # Source parameter: URLSearchParams.get('name') in the same window
    param = ""
    pm = _PARAM_GET_RE.search(context_window)
    if pm:
        param = pm.group(1)

    return {
        "endpoint":       endpoint,
        "source_param":   param,
        "page_url":       page_url,
        "flow_type":      "xhr_eval",
    }


def _hashchange_context(text: str) -> bool:
    """True when the matched code listens for hashchange (fragment-driven flow)."""
    return bool(re.search(r"on\s*\(\s*['\"]hashchange['\"]", text, re.I))


def payloads_for_kind(kind: str) -> list[str]:
    """
    Payload family for a sink kind.

    Derived by the scenario synthesiser from the sink's delivery class (a URL
    sink gets scheme payloads, a markup sink gets elements, a JS sink gets code)
    instead of a per-kind table; ``_PAYLOADS_BY_KIND`` remains the fallback when
    synthesis produces nothing.
    """
    try:
        from xscan.validation.payload_synthesis import payloads_for_sink_kind
        generated = payloads_for_sink_kind(kind)
    except Exception:
        generated = []
    return generated or list(_PAYLOADS_BY_KIND.get(kind, _DEFAULT_PAYLOADS))


def resolve_sink_context(entry: Any, text: str) -> SinkContext:
    """
    Turn a registry sink + matched text into a concrete sink context.

    ``.attr('href', v)`` and ``setAttribute('href', v)`` write to a *named*
    attribute, so the attribute decides the payload family and the trigger.
    """
    attribute = ""
    if entry.id == "jquery_attr":
        found = _ATTR_NAME_RE.search(text)
        attribute = found.group(1).lower() if found else ""
    elif entry.id in ("set_attribute_url", "set_attribute_on"):
        found = _ATTR_NAME_SET_RE.search(text)
        attribute = found.group(1).lower() if found else ""

    if attribute:
        if attribute in _URL_ATTRIBUTES:
            return SinkContext(
                label=f"{entry.label} [{attribute}]",
                kind="url_attribute",
                interaction="click",
                attribute=attribute,
                severity=entry.severity,
                requires_browser=True,
            )
        if attribute.startswith("on"):
            return SinkContext(
                label=f"{entry.label} [{attribute}]",
                kind="event_handler",
                interaction="event",
                attribute=attribute,
                severity=entry.severity,
                requires_browser=True,
            )
        return SinkContext(
            label=f"{entry.label} [{attribute}]",
            kind="html_attribute",
            interaction="none",
            attribute=attribute,
            severity=entry.severity,
            requires_browser=entry.requires_browser,
        )

    kind = entry.resolved_kind
    interaction = entry.resolved_interaction
    if kind == "selector":
        if _hashchange_context(text):
            # The payload only executes when the fragment CHANGES: navigating to
            # the test URL is the trigger, and print()/alert() must fire there.
            return SinkContext(
                label=f"{entry.label} [hashchange]",
                kind="selector_hashchange",
                interaction="event",
                severity=entry.severity,
                requires_browser=True,
            )
        # jQuery $() only executes injected markup that gets appended; treat as
        # a markup sink unless the page also shows an append/insert call.
        kind = "selector"
    return SinkContext(
        label=entry.label,
        kind=kind,
        interaction=interaction,
        severity=entry.severity,
        requires_browser=entry.requires_browser,
    )


def build_test_url(
    page_url: str,
    source_type: str,
    payload: str,
    param: str = "",
) -> str:
    """
    Build a URL that delivers *payload* to where the page reads it.

    Hash sources take the payload as the fragment. Query sources are written to
    the parameter the page actually reads — URLSearchParams.get() decodes the
    percent-encoding, so encoding the payload keeps it intact.
    """
    base = page_url.rstrip("/")
    if source_type == "hash":
        return base + "#" + payload

    parsed = urlparse(page_url)
    if param:
        query = parse_qs(parsed.query, keep_blank_values=True)
        query[param] = [payload]
        return urlunparse(parsed._replace(query=urlencode(query, doseq=True, safe="")))

    # No known parameter — fall back to a generic one and flag low confidence.
    query = parse_qs(parsed.query, keep_blank_values=True)
    query.setdefault("q", [payload])
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True, safe="")))


@registry.register("dom-xss-detector")
class DomXssDetectorNode(NodeBase, NodeEmitter):
    node_type = "dom-xss-detector"  # type: ignore

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        t0 = self.emit_started(ctx)
        metrics = DOMAnalysisMetrics()

        target_url: str = ctx.get("target_url", "")
        if not target_url:
            self.emit_completed(ctx, metrics={"js_files_analysed": 0, "dom_candidates": 0})
            return {"dom_candidates": [], "dom_candidate_count": 0}

        max_pages = int(ctx.config.get("max_pages", _MAX_PAGES))
        crawled: list[str] = [u for u in (ctx.get("urls") or []) if u]
        # Same page crawled under different spellings = one analysis target.
        merged: list[str] = []
        for raw_page in [target_url] + crawled:
            key = normalise_page_url(raw_page)
            if key and key not in merged:
                merged.append(key)
        pages = merged[:max_pages]
        metrics.pages_crawled = len(pages)

        urls_with_params: list[str] = ctx.get("urls_with_params") or []
        params_by_page = self._params_by_page(urls_with_params)

        js_units = self._collect_js(ctx, pages)
        metrics.js_files_extracted = len(js_units)
        self.emit_progress(
            ctx,
            f"DOM analysis: {len(js_units)} script unit(s) from {len(pages)} page(s)",
        )

        candidates: list[dict[str, Any]] = []
        for page_url, js_url, content in js_units:
            file_metrics = FileAnalysisMetrics(
                file_url=js_url,
                file_type="inline" if "inline:" in js_url else "external",
                file_size_bytes=len(content.encode("utf-8")),
                lines_count=len(content.split("\n")),
                is_vendor_code=_is_vendor_js(js_url, content),
            )
            
            if file_metrics.is_vendor_code:
                # Detect vendor markers
                for pattern, name in [
                    (r"angular\.version", "AngularJS"),
                    (r"window\.jQuery", "jQuery"),
                    (r"React\.version", "React"),
                    (r"__VUE__", "Vue"),
                    (r"ng\$", "Angular"),
                ]:
                    if re.search(pattern, content):
                        file_metrics.vendor_markers.append(name)
                file_metrics.analysis_result = "SKIPPED: vendor code"
                metrics.js_files_vendor_filtered += 1
            else:
                metrics.js_files_analysed += 1
                # Perform analysis and collect metrics
                file_cands = self._analyse_with_metrics(
                    content, js_url, page_url, params_by_page, file_metrics
                )
                candidates.extend(file_cands)
                file_metrics.analysis_result = (
                    f"Generated {len(file_cands)} candidate(s)"
                    if file_cands
                    else "No candidates generated"
                )
            
            metrics.file_metrics.append(file_metrics)
            log_file_analysis(file_metrics)

        metrics.total_lines_analysed = sum(f.lines_count for f in metrics.file_metrics)
        metrics.dom_sources_detected = sum(len(f.sources_found) for f in metrics.file_metrics)
        metrics.dom_sinks_detected = sum(len(f.sinks_found) for f in metrics.file_metrics)

        unique = self._dedupe_candidates(candidates)[:_MAX_CANDIDATES]
        metrics.candidates_generated = len(unique)
        unique.extend(self._detect_csti(ctx, pages, urls_with_params))

        # API endpoints that feed sinks: surfaced for candidate-generator so the
        # reflection probe also covers the endpoint the value actually reaches.
        api_endpoints: list[dict[str, str]] = []
        api_eval_endpoints: list[dict[str, str]] = []
        seen_api: set[str] = set()
        for page_url, js_url, content in js_units:
            if not _XHR_RESPONSE_RE.search(content):
                continue
            # Detect XHR→eval() flows: these must go to candidate-gen / EvalJsonFlowAnalyzer,
            # not to the DOM candidate list (the reflection lives server-side).
            if _EVAL_RESPONSE_SINK_RE.search(content):
                flow = _extract_xhr_eval_endpoint(content, page_url)
                if flow:
                    key = f"{flow['page_url']}:{flow['endpoint']}"
                    if key not in seen_api:
                        seen_api.add(key)
                        api_eval_endpoints.append({**flow, "source_js": js_url})
            for match in _API_ENDPOINT_RE.finditer(content):
                endpoint = match.group(1)
                if endpoint in seen_api:
                    continue
                seen_api.add(endpoint)
                api_endpoints.append({
                    "endpoint": endpoint,
                    "source": js_url,
                })

        # Log overall diagnostics
        log_overall_metrics(metrics)

        ms = (time.monotonic() - t0) * 1000
        self.emit_completed(ctx, metrics={
            "pages_analysed":     len(pages),
            "js_files_analysed":  metrics.js_files_analysed,
            "js_files_vendor_filtered": metrics.js_files_vendor_filtered,
            "dom_candidates":     len(unique),
            "api_endpoints":      len(api_endpoints),
            "api_eval_endpoints": len(api_eval_endpoints),
        }, duration_ms=ms)

        return {
            "dom_candidates":       unique,
            "dom_candidate_count":  len(unique),
            "api_endpoints":        api_endpoints,
            "api_eval_endpoints":   api_eval_endpoints,
            "_diagnostics":         metrics.to_dict(),
        }

    # ------------------------------------------------------------------
    # AngularJS client-side template injection (CSTI)
    # ------------------------------------------------------------------

    def _detect_csti(
        self,
        ctx: ExecutionContext,
        pages: list[str],
        urls_with_params: list[str],
    ) -> list[dict[str, Any]]:
        """
        Detect reflected values that land inside an active AngularJS template.

        When the server reflects a query value into an ng-app page, the value
        is not inert text — Angular evaluates ``{{ ... }}`` client-side, so the
        exploit is a template expression, not markup (which the server often
        HTML-encodes anyway). Requires a live probe: reflection + ng-app in the
        SAME response.
        """
        csti: list[dict[str, Any]] = []
        probe_marker = "xscCSTIprobe" + str(int(time.time()))
        tested: set[str] = set()

        with httpx.Client(follow_redirects=True, timeout=12, verify=False,
                          headers={"User-Agent": _UA}) as client:
            for raw in urls_with_params[:_MAX_CSTI_PROBES]:
                page_key = self._page_key(raw.split("?", 1)[0])
                if page_key in tested:
                    continue
                tested.add(page_key)

                # Inject the probe marker into the first query parameter.
                parsed = urlparse(raw)
                params = {
                    k: v[0] for k, v in
                    parse_qs(parsed.query, keep_blank_values=True).items()
                }
                if not params:
                    continue
                first_param = next(iter(params))
                params[first_param] = probe_marker
                probe_url = urlunparse(
                    parsed._replace(query=urlencode(params, safe=""))
                )

                try:
                    ctx.scope.assert_allowed(probe_url, operation="http_request")
                    resp = client.get(probe_url)
                except Exception:
                    continue
                if resp.status_code != 200:
                    continue
                body = resp.text

                # CSTI requires BOTH: the marker is reflected, and the page
                # carries an active AngularJS application.
                if probe_marker not in body or not _NG_APP_RE.search(body):
                    continue
                csti.append(self._build_csti_candidate(
                    page_url=page_key,
                    param=first_param,
                    body=body,
                    reflected_snippet=self._reflection_window(body, probe_marker),
                ))
        return csti

    @staticmethod
    def _reflection_window(body: str, marker: str) -> str:
        """The server-rendered text around the reflected probe value."""
        idx = body.find(marker)
        if idx < 0:
            return ""
        return body[max(0, idx - 120): idx + len(marker) + 120]

    def _build_csti_candidate(
        self,
        page_url: str,
        param: str,
        body: str,
        reflected_snippet: str = "",
    ) -> dict[str, Any]:
        """Assemble a DOM candidate for the AngularJS expression sink."""
        payloads = payloads_for_kind("csti") or list(ANGULAR_CSTI_PAYLOADS)
        # Constraints from the OBSERVED response: which characters the server
        # already encodes in this exact reflection position (sampled from the
        # probe marker's own rendering), so synthesis never relies on chars
        # the server has proven it alters.
        encoded_chars = self._encoded_in_reflection(reflected_snippet)
        return {
            "type":             "dom-xss",
            "url":              page_url,
            "source":           "URL query parameter",
            "source_type":      "query",
            "sink":             "AngularJS expression evaluation (ng-app template)",
            "sink_kind":        "csti",
            "sink_attribute":   "",
            "interaction":      "none",
            "severity":         "critical",
            "confidence":       "high",
            "file_url":         "inline",
            "line":             0,
            "snippet":          "reflected value lands inside an active ng-app template",
            "context":          "",
            "param":            param,
            "params_tried":     [param],
            "trigger_event":    "",
            "payloads":         payloads,
            "test_urls": [
                build_test_url(page_url, "query", p, param) for p in payloads
            ],
            "best_payload":     payloads[0],
            "best_test_url":    build_test_url(
                page_url, "query", payloads[0], param
            ),
            "requires_browser": True,
            "is_angular":       True,
            "encoding_profile": {
                "raw_chars":     [],
                "encoded_chars": encoded_chars,
                "stripped_chars": [],
                "summary": (
                    "derived from the reflected probe marker in the ng-app template"
                    if encoded_chars else "probe reflected without visible encoding"
                ),
            },
        }

    @staticmethod
    def _encoded_in_reflection(snippet: str) -> list[str]:
        """
        Characters the server demonstrably encodes in this reflection: scan the
        surrounding server-rendered text for HTML entities and record the
        character each entity decodes to.
        """
        if not snippet:
            return []
        import html as _html
        import re as _re
        found: list[str] = []
        for m in _re.finditer(r"&(#x?[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]{1,8});", snippet):
            try:
                ch = _html.unescape(m.group(0))
            except Exception:
                continue
            if ch and len(ch) == 1 and ch not in found and not ch.isalnum():
                found.append(ch)
        return found[:8]

    # ------------------------------------------------------------------
    # JS inventory
    # ------------------------------------------------------------------

    def _collect_js(
        self,
        ctx: ExecutionContext,
        pages: list[str],
    ) -> list[tuple[str, str, str]]:
        """Return (page_url, js_url, content) for every script worth analysing."""
        units: list[tuple[str, str, str]] = []
        seen: set[str] = set()

        # Prefer the js-extract inventory when this workflow produced one.
        for js in (ctx.get("js_files") or []):
            content = js.get("content") or ""
            js_url = str(js.get("url", "inline"))
            page_url = str(js.get("page") or ctx.get("target_url", ""))
            if content and js_url not in seen:
                seen.add(js_url)
                if not _is_vendor_js(js_url, content):
                    units.append((page_url, js_url, content))
        if units:
            return units

        with httpx.Client(follow_redirects=True, timeout=12, verify=False,
                          headers={"User-Agent": _UA}) as client:
            for page_url in pages:
                try:
                    ctx.scope.assert_allowed(page_url, operation="http_request")
                    response = client.get(page_url)
                except Exception:
                    continue
                if response.status_code != 200:
                    continue

                for i, script in enumerate(self._extract_inline_scripts(response.text)):
                    key = f"inline:{page_url}:{i}"
                    if script.strip() and key not in seen:
                        seen.add(key)
                        units.append((page_url, key, script))

                for js_url in self._extract_js_urls(response.text, page_url)[:_MAX_JS_PER_PAGE]:
                    if js_url in seen:
                        continue
                    seen.add(js_url)
                    try:
                        ctx.scope.assert_allowed(js_url, operation="http_request")
                        r = client.get(js_url)
                        if r.status_code == 200:
                            body = r.text[:100_000]
                            # Vendor bundles (AngularJS/jQuery/...) are not the
                            # application's sink code — analysing them yields
                            # untestable candidates against framework internals.
                            if _is_vendor_js(js_url, body):
                                continue
                            units.append((page_url, js_url, body))
                    except Exception:
                        continue
        return units

    # ------------------------------------------------------------------
    # Analysis with Diagnostics
    # ------------------------------------------------------------------

    def _find_sources(self, code_line: str) -> list[Any]:
        """
        Find all matching sources using combined registry system.
        First uses xss_knowledge (optimized), then enhances with registry patterns.
        """
        # Primary sources from xss_knowledge
        sources: list[Any] = [s for s in xss_knowledge.sources if s.matches(code_line)]
        
        # Enhance with additional patterns from registry if needed
        if not sources:
            registry_sources = source_registry.find_matching(code_line)
            # Wrap SourceDefinition objects to add .id attribute for compatibility
            for src_def in registry_sources:
                # Create a wrapper that looks like a SourceEntry
                class SourceEntryWrapper:  # noqa: E701
                    def __init__(self, definition: Any) -> None:
                        self.id = definition.name
                        self.label = definition.name
                        self.pattern = "|".join(definition.patterns) if definition.patterns else ""
                        self.input_type = str(definition.type)
                        self.confidence = "high" if definition.confidence > 0.8 else "medium"
                        self.framework = definition.framework
                        self.notes = definition.description
                        self._original = definition
                    
                    def matches(self, code: str) -> bool:
                        return bool(self._original.matches(code))
                
                sources.append(SourceEntryWrapper(src_def))
        
        return sources

    def _find_sinks(self, code_line: str) -> list[Any]:
        """
        Find all matching sinks using combined registry system.
        First uses xss_knowledge (optimized), then enhances with registry patterns.
        """
        # Primary sinks from xss_knowledge
        sinks: list[Any] = [s for s in xss_knowledge.sinks if s.matches(code_line)]
        
        # Enhance with additional patterns from registry if needed
        if not sinks:
            registry_sinks = sink_registry.find_matching(code_line)
            # Wrap SinkDefinition objects to add .id attribute for compatibility
            for sink_def in registry_sinks:
                # Create a wrapper that looks like a SinkEntry
                class SinkEntryWrapper:  # noqa: E701
                    def __init__(self, definition: Any) -> None:
                        self.id = definition.name
                        self.label = definition.name
                        self.pattern = "|".join(definition.patterns) if definition.patterns else ""
                        self.severity = 'high' if definition.confidence > 0.8 else 'medium'
                        self.category = str(definition.type)
                        self.requires_browser = definition.runtime_detectable  # Use runtime_detectable as proxy
                        self.framework = definition.framework
                        self.notes = definition.description
                        self.kind = ""  # Will be resolved by resolve_sink_context
                        self.interaction = ""  # Will be resolved by resolve_sink_context
                        # For resolve_sink_context fallback
                        self.resolved_kind = 'html_text'
                        self.resolved_interaction = 'none'
                        self._original = definition
                    
                    def matches(self, code: str) -> bool:
                        return bool(self._original.matches(code))
                
                sinks.append(SinkEntryWrapper(sink_def))
        
        return sinks

    # ------------------------------------------------------------------
    # Variable tracking for extended proximity analysis
    # ------------------------------------------------------------------

    def _extract_variable_assignments(self, lines: list[str], start_line: int) -> dict[str, int]:
        """
        Track variable assignments up to start_line.
        Returns dict mapping variable names to their line numbers.
        Useful for connecting sources that are assigned to variables before use.
        """
        vars_by_name: dict[str, int] = {}
        
        # Common source variable names
        source_vars = {
            'tainted', 'input', 'param', 'query', 'search', 'hash', 'url',
            'data', 'value', 'payload', 'result', 'response', 'text'
        }
        
        for i in range(max(0, start_line - 50), min(start_line, len(lines))):
            line = lines[i]
            # Simple pattern: var/let/const name = source
            for source_var in source_vars:
                if source_var in line and '=' in line:
                    # Very basic tracking
                    vars_by_name[source_var] = i
        
        return vars_by_name

    def _find_variable_usage(self, line: str, var_name: str) -> bool:
        """Check if a variable is used in a line."""
        import re
        # Match word boundary to avoid substring matches
        pattern = r'\b' + re.escape(var_name) + r'\b'
        return bool(re.search(pattern, line))

    # ------------------------------------------------------------------
    # Analysis with Extended Window
    # ------------------------------------------------------------------

    def _analyse_with_metrics(
        self,
        content: str,
        js_url: str,
        page_url: str,
        params_by_page: dict[str, list[str]],
        file_metrics: FileAnalysisMetrics,
    ) -> list[dict[str, Any]]:
        """
        Analyse JS content and track detailed metrics about discovery process.
        """
        hashchange = _hashchange_context(content)
        lines = content.splitlines()
        
        # Initialize per-file source/sink analysis
        file_metrics.source_analysis = SourceAnalysisMetrics(
            total_lines_analysed=len(lines)
        )

        if len(lines) <= 5 and len(content) > 10_000:
            candidates = self._analyse_minified_with_metrics(
                content, js_url, page_url, params_by_page, hashchange, file_metrics
            )
        else:
            candidates = self._analyse_multiline_with_metrics(
                lines, js_url, page_url, params_by_page, hashchange, file_metrics
            )

        return candidates

    def _analyse_minified_with_metrics(
        self,
        content: str,
        js_url: str,
        page_url: str,
        params_by_page: dict[str, list[str]],
        hashchange: bool,
        file_metrics: FileAnalysisMetrics,
    ) -> list[dict[str, Any]]:
        """Analyse minified code with metrics tracking."""
        candidates: list[dict[str, Any]] = []
        for sink_entry in self._find_sinks(content):
            for match in sink_entry.regex.finditer(content):
                pos = match.start()
                window = content[max(0, pos - 500): pos + 500]
                file_metrics.sinks_found.append({
                    "type": sink_entry.id,
                    "line": 1,
                    "snippet": window[:100],
                })
                
                if sink_entry.id == "jquery_dollar":
                    if "attr(" in window.replace(" ", ""):
                        continue
                    if _JQUERY_READY_RE.search(content[pos:pos + 40]):
                        continue
                
                if _is_xhr_eval_flow(sink_entry.id, window):
                    file_metrics.source_analysis.record_discard("xhr_eval_flow")
                    continue
                
                for src_entry in self._find_sources(window):
                    file_metrics.sources_found.append({
                        "type": src_entry.id,
                        "line": 1,
                        "snippet": window[:100],
                    })
                    file_metrics.source_analysis.lines_with_both += 1
                    
                    candidate = self._build_candidate(
                        src_label=src_entry.label,
                        source_type=src_entry.input_type,
                        sink_entry=sink_entry,
                        matched_text=window,
                        snippet=content[max(0, pos - 80): pos + 100],
                        context=window,
                        line=1,
                        js_url=js_url,
                        page_url=page_url,
                        params_by_page=params_by_page,
                        confidence="high",
                        hashchange=hashchange,
                    )
                    candidates.append(candidate)
                    break
        return candidates

    def _analyse_multiline_with_metrics(
        self,
        lines: list[str],
        js_url: str,
        page_url: str,
        params_by_page: dict[str, list[str]],
        hashchange: bool,
        file_metrics: FileAnalysisMetrics,
    ) -> list[dict[str, Any]]:
        """Analyse line-by-line code with detailed metrics and extended proximity window."""
        candidates: list[dict[str, Any]] = []
        file_metrics.source_analysis.total_lines_analysed = len(lines)

        for i, line in enumerate(lines):
            stripped = line.strip()
            if len(stripped) < 5:
                continue

            # Check for sink patterns on this line using combined registry
            matched_sinks = self._find_sinks(line)
            if matched_sinks:
                file_metrics.source_analysis.lines_with_sink_patterns += 1
                for sink in matched_sinks:
                    sink_id = sink.id  # Both SinkEntry and SinkDefinition (after patching) have .id
                    file_metrics.source_analysis.sink_patterns_matched[sink_id] = (
                        file_metrics.source_analysis.sink_patterns_matched.get(sink_id, 0) + 1
                    )

            if _JQUERY_READY_RE.search(line):
                matched_sinks = [
                    e for e in matched_sinks 
                    if e.id not in ("jquery_dollar", "jQuery.html")  # Both old and new sink names
                ]
            
            has_attribute_sink = any(
                e.id in _ATTRIBUTE_SINK_IDS for e in matched_sinks
            )
            
            for sink_entry in matched_sinks:
                if has_attribute_sink and sink_entry.id in ("jquery_dollar", "jQuery.html"):
                    continue

                sink_id = sink_entry.id
                file_metrics.sinks_found.append({
                    "type": sink_id,
                    "line": i + 1,
                    "snippet": stripped[:120],
                })

                # ── Extended proximity window ────────────────────────────────
                # Increased from 8 lines to 20 lines to catch more relationships
                # Check context BEFORE sink (previous 20 lines) for sources
                context_before_start = max(0, i - 20)
                context_before = "\n".join(lines[context_before_start:i])
                
                # Full context for XHR detection
                context_full_start = max(0, i - 20)
                context_full = "\n".join(lines[context_full_start: i + 6])

                # XHR→eval() suppression
                if _is_xhr_eval_flow(sink_id, context_full):
                    file_metrics.source_analysis.record_discard("xhr_eval_flow")
                    continue

                # Try to find source on the same line (highest confidence)
                src_entry = next(
                    (s for s in self._find_sources(line)),
                    None,
                )
                confidence = "high"
                
                if src_entry is None:
                    # Try to find source in context before (high-medium confidence)
                    context_sources_before = self._find_sources(context_before)
                    src_entry = next(iter(context_sources_before), None)
                    if src_entry is not None:
                        confidence = "high-medium"
                        file_metrics.source_analysis.record_discard("source_in_extended_before")
                
                if src_entry is None:
                    # Try to find source in full context (medium confidence)
                    context_sources_full = self._find_sources(context_full)
                    src_entry = next(iter(context_sources_full), None)
                    if src_entry is not None:
                        confidence = "medium"
                        file_metrics.source_analysis.record_discard("source_in_extended_full")
                
                if src_entry is None:
                    # No source found in extended window
                    file_metrics.source_analysis.record_discard("no_source_in_extended_window")
                    continue

                # Source found!
                src_id = src_entry.id
                file_metrics.sources_found.append({
                    "type": src_id,
                    "line": i + 1,
                    "snippet": stripped[:120],
                })
                file_metrics.source_analysis.lines_with_source_patterns += 1
                file_metrics.source_analysis.source_patterns_matched[src_id] = (
                    file_metrics.source_analysis.source_patterns_matched.get(src_id, 0) + 1
                )
                file_metrics.source_analysis.lines_with_both += 1

                candidate = self._build_candidate(
                    src_label=src_entry.label,
                    source_type=src_entry.input_type,
                    sink_entry=sink_entry,
                    matched_text=line,
                    snippet=stripped[:200],
                    context=context_full,
                    line=i + 1,
                    js_url=js_url,
                    page_url=page_url,
                    params_by_page=params_by_page,
                    confidence=confidence,
                    hashchange=hashchange,
                )
                candidates.append(candidate)
        return candidates

    # ------------------------------------------------------------------
    # Analysis (legacy, preserved for now)
    # ------------------------------------------------------------------

    def _analyse(
        self,
        content: str,
        js_url: str,
        page_url: str,
        params_by_page: dict[str, list[str]],
    ) -> list[dict[str, Any]]:
        # Whether the page listens for hashchange decides how a fragment flow
        # triggers — this is a property of the page, not of one matched line.
        hashchange = _hashchange_context(content)
        lines = content.splitlines()
        if len(lines) <= 5 and len(content) > 10_000:
            return self._analyse_minified(content, js_url, page_url, params_by_page, hashchange)
        return self._analyse_multiline(lines, js_url, page_url, params_by_page, hashchange)

    def _analyse_minified(
        self,
        content: str,
        js_url: str,
        page_url: str,
        params_by_page: dict[str, list[str]],
        hashchange: bool = False,
    ) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        for sink_entry in self._find_sinks(content):
            for match in sink_entry.regex.finditer(content):
                pos = match.start()
                window = content[max(0, pos - 500): pos + 500]
                if sink_entry.id == "jquery_dollar":
                    if "attr(" in window.replace(" ", ""):
                        continue   # the .attr() sink in this window is the real flow
                    if _JQUERY_READY_RE.search(content[pos:pos + 40]):
                        continue   # DOM-ready wiring, not a sink
                # XHR→eval() suppression: server-side reflection, not DOM sink.
                if _is_xhr_eval_flow(sink_entry.id, window):
                    continue
                for src_entry in self._find_sources(window):
                    candidate = self._build_candidate(
                        src_label=src_entry.label,
                        source_type=src_entry.input_type,
                        sink_entry=sink_entry,
                        matched_text=window,
                        snippet=content[max(0, pos - 80): pos + 100],
                        context=window,
                        line=1,
                        js_url=js_url,
                        page_url=page_url,
                        params_by_page=params_by_page,
                        confidence="high",
                        hashchange=hashchange,
                    )
                    candidates.append(candidate)
                    break
        return candidates

    def _analyse_multiline(
        self,
        lines: list[str],
        js_url: str,
        page_url: str,
        params_by_page: dict[str, list[str]],
        hashchange: bool = False,
    ) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        for i, line in enumerate(lines):
            stripped = line.strip()
            if len(stripped) < 5:
                continue

            matched_sinks = self._find_sinks(line)
            if _JQUERY_READY_RE.search(line):
                # $() used to register a ready callback selects nothing.
                matched_sinks = [
                    e for e in matched_sinks 
                    if e.id != "jquery_dollar"
                ]
            has_attribute_sink = any(
                e.id in _ATTRIBUTE_SINK_IDS for e in matched_sinks
            )
            for sink_entry in matched_sinks:
                if has_attribute_sink and sink_entry.id == "jquery_dollar":
                    continue

                # Extended context window (20 lines before, 5 after)
                context_start = max(0, i - 20)
                context = "\n".join(lines[context_start: i + 6])

                # ── XHR→eval() suppression ────────────────────────────────
                # When eval() is fed from responseText in the same context
                # window the flow goes server-side: the reflection lives in
                # the API response, not in the page's HTML. Static DOM
                # analysis cannot determine the server's escaping behaviour;
                # raise it as an api_eval_endpoint (handled by candidate-gen
                # + EvalJsonFlowAnalyzer) and skip the DOM candidate.
                if _is_xhr_eval_flow(sink_entry.id, context):
                    continue

                src_entry = next(
                    (s for s in self._find_sources(line)),
                    None,
                )
                confidence = "high"
                if src_entry is None:
                    src_sources = self._find_sources(context)
                    src_entry = next(iter(src_sources), None)
                    confidence = "medium"
                if src_entry is None:
                    continue

                candidates.append(self._build_candidate(
                    src_label=src_entry.label,
                    source_type=src_entry.input_type,
                    sink_entry=sink_entry,
                    matched_text=line,
                    snippet=stripped[:200],
                    context=context,
                    line=i + 1,
                    js_url=js_url,
                    page_url=page_url,
                    params_by_page=params_by_page,
                    confidence=confidence,
                    hashchange=hashchange,
                ))
        return candidates

    def _build_candidate(
        self,
        src_label: str,
        source_type: str,
        sink_entry: Any,
        matched_text: str,
        snippet: str,
        context: str,
        line: int,
        js_url: str,
        page_url: str,
        params_by_page: dict[str, list[str]],
        confidence: str,
        hashchange: bool = False,
    ) -> dict[str, Any]:
        sink = resolve_sink_context(sink_entry, matched_text)
        if (
            hashchange
            and source_type == "hash"
            and sink.kind == "selector"
        ):
            # The page listens for hashchange, so this fragment flow only
            # executes when the fragment CHANGES — the confirmer must navigate
            # to the page first and replay the fragment afterwards.
            sink = _dc_replace(
                sink,
                kind="selector_hashchange",
                interaction="event",
                label=f"{sink.label} [hashchange]",
            )
        payloads = payloads_for_kind(sink.kind)

        # Parameter discovery must look at the whole analysis context: the source
        # (which names the parameter) often sits on a different line than the sink.
        params = self._params_for(page_url, js_url, source_type, context, params_by_page)
        if source_type == "hash" or not params:
            params = [""]
            if source_type not in ("hash", "href") and confidence == "high":
                confidence = "low"   # can't name the parameter -> weaker candidate

        test_urls = [build_test_url(page_url, source_type, p, params[0]) for p in payloads]

        return {
            "type":             "dom-xss",
            "url":              page_url,
            "source":           src_label,
            "source_type":      source_type,
            "sink":             sink.label,
            "sink_kind":        sink.kind,
            "sink_attribute":   sink.attribute,
            "interaction":      sink.interaction,
            "severity":         sink.severity,
            "confidence":       confidence,
            "file_url":         js_url,
            "line":             line,
            "snippet":          snippet,
            "context":          context[:500],
            "param":            params[0],
        "params_tried":     params,
        "trigger_event":    "hashchange" if sink.kind == "selector_hashchange" else "",
        "payloads":         payloads,
            "test_urls":        test_urls,
            "best_payload":     payloads[0],
            "best_test_url":    test_urls[0],
            "requires_browser": sink.requires_browser,
            "is_angular":       getattr(sink_entry, "category", "") == "framework_bypass",
        }

    # ------------------------------------------------------------------
    # Parameter binding
    # ------------------------------------------------------------------

    @staticmethod
    def _params_by_page(urls_with_params: list[str]) -> dict[str, list[str]]:
        mapping: dict[str, list[str]] = {}
        for url in urls_with_params:
            parsed = urlparse(url)
            if not parsed.query:
                continue
            key = DomXssDetectorNode._page_key(url)
            names = list(parse_qs(parsed.query, keep_blank_values=True).keys())
            bucket = mapping.setdefault(key, [])
            for name in names:
                if name not in bucket:
                    bucket.append(name)
        return mapping

    @staticmethod
    def _page_key(url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def _params_for(
        self,
        page_url: str,
        js_url: str,
        source_type: str,
        js_text: str,
        params_by_page: dict[str, list[str]],
    ) -> list[str]:
        """
        Parameters the page reads, best source first:

          1. names the JS itself asks for (URLSearchParams.get('returnPath'))
          2. names seen in the crawl's parameterised URLs for this page
        """
        if source_type == "hash":
            return []

        names: list[str] = []
        for match in _PARAM_GET_RE.finditer(js_text):
            if match.group(1) not in names:
                names.append(match.group(1))
        for name in params_by_page.get(self._page_key(page_url), []):
            if name not in names:
                names.append(name)

        # The js_url may be an external file: also check the page's own params.
        if not names:
            for url in (js_url,):
                for name in _PARAM_SPLIT_RE.findall(url):
                    if name not in names:
                        names.append(name)
        return names[:_MAX_PARAMS_PER_CANDIDATE]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _dedupe(items: list[str]) -> list[str]:
        seen: list[str] = []
        for item in items:
            if item and item not in seen:
                seen.append(item)
        return seen

    @staticmethod
    def _dedupe_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: set[tuple[str, str, str, str]] = set()
        unique: list[dict[str, Any]] = []
        for candidate in candidates:
            key = (
                normalise_page_url(candidate["url"]),
                candidate["source"],
                candidate["sink"],
                candidate["param"],
            )
            if key not in seen:
                seen.add(key)
                unique.append(candidate)
        return unique

    @staticmethod
    def _extract_inline_scripts(html: str) -> list[str]:
        return re.findall(r"<script(?:[^>]*)>(.*?)</script>", html, re.DOTALL | re.I)

    @staticmethod
    def _extract_js_urls(html: str, base_url: str) -> list[str]:
        srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
        result = []
        for src in srcs:
            if src.startswith(("http://", "https://")):
                result.append(src)
            else:
                result.append(urljoin(base_url, src))
        return result
