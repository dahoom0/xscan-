"""
HarnessToolRegistry — the set of tools available to the agent.

Rules:
  - Every tool wraps an EXISTING XScan capability.
  - No new unbounded execution paths are introduced.
  - Every tool call passes through ScopeEngine + PolicyEngine before execution.
  - The LLM requests tools by name; the harness validates and dispatches.

Phase 1 tools (HTTP + existing validators):
  http.get              — scoped HTTP GET request
  http.compare          — compare two responses
  js.analyse            — run existing DOM source/sink analysis
  validator.reflect     — test one payload for HTTP reflection (existing HTTPValidator)
  validator.iterative   — run the existing IterativeValidator on a candidate

Phase 3 tools (browser) — not yet available:
  browser.navigate      — placeholder, returns ToolUnavailable
  browser.snapshot      — placeholder
  browser.console       — placeholder
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable

logger = logging.getLogger(__name__)


@dataclass
class HarnessTool:
    name:                 str
    description:          str
    capability:           str              # coarse category: http | js | validator | browser | research
    risk_level:           str = "low"      # low | medium | high
    requires_scope:       bool = True
    requires_policy:      bool = True
    input_schema:         dict[str, Any] = field(default_factory=dict)
    output_schema:        dict[str, Any] = field(default_factory=dict)
    handler:              Callable | None = None
    available:            bool = True      # False = placeholder for future phase


class HarnessToolRegistry:
    """
    Registry of all tools the agent can request.

    Usage::

        reg = HarnessToolRegistry()
        tool = reg.get("http.get")
        result = tool.handler(arguments, scope, policy)
    """

    def __init__(self) -> None:
        self._tools: dict[str, HarnessTool] = {}
        self._register_defaults()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, name: str) -> HarnessTool | None:
        return self._tools.get(name)

    def all_names(self) -> list[str]:
        return sorted(self._tools)

    def available_names(self) -> list[str]:
        return sorted(n for n, t in self._tools.items() if t.available)

    def tool_schema_summary(self) -> str:
        """Compact schema summary for LLM context (keeps token count low)."""
        lines = []
        for name in self.available_names():
            t = self._tools[name]
            lines.append(
                f"{name} ({t.capability}, {t.risk_level} risk): {t.description}"
            )
        return "\n".join(lines)

    def register(self, tool: HarnessTool) -> None:
        self._tools[tool.name] = tool

    # ------------------------------------------------------------------
    # Default tool registration (Phase 1)
    # ------------------------------------------------------------------

    def _register_defaults(self) -> None:
        # ── HTTP tools ───────────────────────────────────────────────
        self.register(HarnessTool(
            name="http.get",
            description="Issue a scoped HTTP GET request. Returns status, headers, body snippet.",
            capability="http",
            risk_level="low",
            input_schema={
                "url":     "str — the full URL to request (must be in scope)",
                "headers": "dict[str, str] — optional custom headers",
                "timeout": "int — request timeout in seconds (default 12)",
            },
            output_schema={
                "status_code": "int",
                "body_snippet": "str — first 500 chars of response body",
                "headers":     "dict[str, str]",
                "elapsed_ms":  "float",
            },
            handler=self._handle_http_get,
        ))

        self.register(HarnessTool(
            name="http.compare",
            description="Compare two HTTP responses and report differences.",
            capability="http",
            risk_level="low",
            input_schema={
                "url_a": "str — first URL",
                "url_b": "str — second URL (must be in scope)",
            },
            output_schema={
                "body_diff_summary": "str",
                "status_differs":    "bool",
                "header_differs":    "bool",
            },
            handler=self._handle_http_compare,
        ))

        # ── JS analysis tools ─────────────────────────────────────────
        self.register(HarnessTool(
            name="js.analyse",
            description=(
                "Run static DOM source/sink/event analysis on the target page. "
                "Returns sources, sinks, events, and taint paths."
            ),
            capability="js",
            risk_level="low",
            input_schema={
                "url": "str — page URL to extract and analyse JS from",
            },
            output_schema={
                "sources": "list[dict] — DOMSourceObservation dicts",
                "sinks":   "list[dict] — DOMSinkObservation dicts",
                "events":  "list[dict] — DOMEventObservation dicts",
                "taint_paths": "list[dict] — TaintPath dicts",
            },
            handler=self._handle_js_analyse,
        ))

        # ── Validator tools ───────────────────────────────────────────
        self.register(HarnessTool(
            name="validator.reflect",
            description=(
                "Test one payload for HTTP reflection in a specific URL parameter. "
                "Returns whether the payload reflected unencoded."
            ),
            capability="validator",
            risk_level="low",
            input_schema={
                "url":       "str",
                "parameter": "str",
                "payload":   "str",
                "method":    "str — GET or POST (default GET)",
            },
            output_schema={
                "reflected":  "bool",
                "encoded":    "bool",
                "stripped":   "bool",
                "snippet":    "str",
                "http_status":"int",
            },
            handler=self._handle_validator_reflect,
        ))

        self.register(HarnessTool(
            name="validator.iterative",
            description=(
                "Run the full iterative validation loop on a candidate. "
                "Uses the existing IterativeValidator with context-aware payloads."
            ),
            capability="validator",
            risk_level="medium",
            input_schema={
                "url":                "str",
                "parameter":          "str",
                "method":             "str",
                "context_analysis":   "dict — ContextObservation dict",
                "encoding_profile":   "dict",
                "execution_semantics":"dict — DOM execution context",
                "technologies":       "list[str]",
            },
            output_schema={
                "status":          "str — IterationStatus",
                "validated":       "bool",
                "best_payload":    "str",
                "best_test_url":   "str",
                "attempt_count":   "int",
                "observations":    "list[dict]",
            },
            handler=self._handle_validator_iterative,
        ))

        # ── Browser tools (Phase 3 — not yet available) ──────────────
        for name, desc in [
            ("browser.navigate", "Navigate to a URL in a browser and capture DOM state"),
            ("browser.snapshot", "Capture a DOM snapshot of the current page"),
            ("browser.console",  "Capture browser console output"),
            ("browser.fragment", "Change the URL fragment and wait for hashchange event"),
        ]:
            self.register(HarnessTool(
                name=name,
                description=desc,
                capability="browser",
                risk_level="medium",
                available=False,   # Phase 10
                handler=self._handle_unavailable,
            ))

        # ── Research tools (allowed domains only) ────────────────────
        self.register(HarnessTool(
            name="research.fetch",
            description=(
                "Fetch a page from an approved research domain "
                "(portswigger.net, owasp.org, etc.). "
                "For technical context only — not target scanning."
            ),
            capability="research",
            risk_level="low",
            input_schema={"url": "str — must be from approved research domain"},
            output_schema={"content": "str — first 2000 chars of content"},
            handler=self._handle_research_fetch,
        ))

    # ------------------------------------------------------------------
    # Handlers — each wraps an EXISTING XScan component
    # ------------------------------------------------------------------

    @staticmethod
    def _handle_http_get(
        arguments: dict[str, Any],
        scope, policy,
    ) -> dict[str, Any]:
        import httpx
        url     = arguments.get("url", "")
        headers = arguments.get("headers", {})
        timeout = int(arguments.get("timeout", 12))

        scope.assert_allowed(url, operation="http_request")
        policy.assert_permitted("http_request", {"node_type": "agent_investigation", "url": url})

        try:
            resp = httpx.get(
                url, headers=headers, follow_redirects=True,
                timeout=timeout, verify=False,
                headers_kwargs={"User-Agent": "Mozilla/5.0 (compatible; XScan/1.0)"},
            )
        except Exception:
            resp = httpx.get(
                url, follow_redirects=True, timeout=timeout, verify=False,
            )

        return {
            "status_code":  resp.status_code,
            "body_snippet": resp.text[:500],
            "headers":      dict(resp.headers),
            "elapsed_ms":   resp.elapsed.total_seconds() * 1000 if hasattr(resp, "elapsed") else 0,
        }

    @staticmethod
    def _handle_http_compare(
        arguments: dict[str, Any],
        scope, policy,
    ) -> dict[str, Any]:
        import httpx
        url_a = arguments.get("url_a", "")
        url_b = arguments.get("url_b", "")

        scope.assert_allowed(url_a, operation="http_request")
        scope.assert_allowed(url_b, operation="http_request")
        policy.assert_permitted("http_request", {"node_type": "agent_investigation"})

        r_a = httpx.get(url_a, follow_redirects=True, timeout=12, verify=False)
        r_b = httpx.get(url_b, follow_redirects=True, timeout=12, verify=False)

        body_a = set(r_a.text.split())
        body_b = set(r_b.text.split())
        added   = body_b - body_a
        removed = body_a - body_b

        return {
            "status_differs":    r_a.status_code != r_b.status_code,
            "status_a":          r_a.status_code,
            "status_b":          r_b.status_code,
            "body_diff_summary": f"+{len(added)} words, -{len(removed)} words",
            "added_words":       list(added)[:20],
            "removed_words":     list(removed)[:20],
        }

    @staticmethod
    def _handle_js_analyse(
        arguments: dict[str, Any],
        scope, policy,
    ) -> dict[str, Any]:
        import httpx, re
        url = arguments.get("url", "")
        scope.assert_allowed(url, operation="http_request")

        from xscan.nodes.dom.sources import detect_sources
        from xscan.nodes.dom.sinks   import detect_sinks
        from xscan.nodes.dom.events  import detect_events
        from xscan.evidence.taint    import TaintGraph

        resp = httpx.get(url, follow_redirects=True, timeout=12, verify=False)
        js_contents: list[tuple[str, str]] = []

        # Inline scripts
        for script in re.findall(r"<script[^>]*>(.*?)</script>", resp.text, re.DOTALL | re.I):
            js_contents.append(("inline", script))

        # External scripts
        for src in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', resp.text, re.I):
            if not src.startswith(("http://", "https://")):
                from urllib.parse import urljoin
                src = urljoin(url, src)
            try:
                scope.assert_allowed(src, operation="http_request")
                r = httpx.get(src, follow_redirects=True, timeout=10, verify=False)
                if r.status_code == 200:
                    js_contents.append((src, r.text[:100_000]))
            except Exception:
                continue

        sources, sinks, events = [], [], []
        for file_url, content in js_contents:
            sources.extend(o.model_dump(mode="json") for o in detect_sources(content, file_url))
            sinks.extend(  o.model_dump(mode="json") for o in detect_sinks(content, file_url))
            events.extend( o.model_dump(mode="json") for o in detect_events(content, file_url))

        # Build taint paths
        from xscan.schemas.xss import DOMSourceObservation, DOMSinkObservation, DOMEventObservation
        tg = TaintGraph(target_url=url)
        tg.build(
            [DOMSourceObservation(**s) for s in sources],
            [DOMSinkObservation(**s)   for s in sinks],
            [DOMEventObservation(**e)  for e in events],
        )

        return {
            "sources":     sources,
            "sinks":       sinks,
            "events":      events,
            "taint_paths": tg.to_dict_list(),
        }

    @staticmethod
    def _handle_validator_reflect(
        arguments: dict[str, Any],
        scope, policy,
    ) -> dict[str, Any]:
        from xscan.validation.http import HTTPValidator
        url       = arguments.get("url", "")
        parameter = arguments.get("parameter", "")
        payload   = arguments.get("payload", "")
        method    = arguments.get("method", "GET")

        validator = HTTPValidator(scope)
        obs = validator.execute(
            url=url, param=parameter, method=method,
            payload=payload, attempt=1,
        )
        return {
            "reflected":   obs.payload_reflected,
            "encoded":     obs.payload_encoded,
            "stripped":    obs.payload_stripped,
            "snippet":     obs.reflection_snippet,
            "http_status": obs.http_status,
            "url_sent":    obs.url_sent,
        }

    @staticmethod
    def _handle_validator_iterative(
        arguments: dict[str, Any],
        scope, policy,
    ) -> dict[str, Any]:
        from xscan.validation.iterative import IterativeValidator
        from xscan.schemas.iteration import IterationBudget

        budget = IterationBudget(
            max_iterations=3,
            max_candidates_per_iteration=4,
            max_total_candidates=12,
            max_runtime_s=60.0,
        )
        validator = IterativeValidator(
            scope=scope, policy=policy, budget=budget,
        )
        state = validator.run(
            url=arguments.get("url", ""),
            parameter=arguments.get("parameter", ""),
            method=arguments.get("method", "GET"),
            context_analysis=arguments.get("context_analysis"),
            encoding_profile=arguments.get("encoding_profile"),
            execution_semantics=arguments.get("execution_semantics"),
            technologies=arguments.get("technologies", []),
        )
        return {
            "status":        state.status,
            "validated":     any(r.reflected and not r.encoded for r in state.previous_results),
            "best_payload":  state.confirmed_payload or next(
                (r.payload for r in state.previous_results if r.reflected and not r.encoded), ""
            ),
            "attempt_count": state.total_candidates,
            "observations":  [r.model_dump(mode="json") for r in state.previous_results],
        }

    @staticmethod
    def _handle_research_fetch(
        arguments: dict[str, Any],
        scope, policy,
    ) -> dict[str, Any]:
        import httpx
        url = arguments.get("url", "")
        policy.assert_permitted("research_fetch", {"url": url, "node_type": "agent_investigation"})
        try:
            resp = httpx.get(url, follow_redirects=True, timeout=15)
            return {"content": resp.text[:2000], "status_code": resp.status_code}
        except Exception as exc:
            return {"content": "", "error": str(exc)[:200]}

    @staticmethod
    def _handle_unavailable(
        arguments: dict[str, Any],
        scope, policy,
    ) -> dict[str, Any]:
        return {"error": "tool_unavailable", "message": "This tool is not available yet (Phase 10)"}


# Module-level singleton
harness_tool_registry = HarnessToolRegistry()
