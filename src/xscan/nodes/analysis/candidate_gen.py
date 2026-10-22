"""
Candidate Generator node
========================
DAG node: reflection-detector + context + encoding in one pass.

For each parameter:
  1. Inject canary → check reflection
  2. If reflected → run ContextAnalyser (deterministic)
  3. Run EncodingAnalyser (deterministic)
  4. Produce a fully-characterised XssCandidate

The LLM never sees raw HTML. It receives a structured ContextAnalysis
and EncodingProfile as evidence.

Inputs:  target_url, urls_with_params, forms
Outputs: xss_candidates (list[dict]), inputs_analyzed (int)

Each candidate dict contains:
  parameter, url, method, context_analysis (dict), encoding_profile (dict),
  canary_evidence (snippet), confidence
"""
from __future__ import annotations

import hashlib
import time
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import httpx

from xscan.core.dag.node_registry import registry
from xscan.nodes.analysis.context import ContextAnalyser
from xscan.nodes.analysis.encoding import EncodingAnalyser
from xscan.nodes.base import ExecutionContext, NodeBase
from xscan.nodes.emitter import NodeEmitter

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"


def _canary(salt: str) -> str:
    return "xscC" + hashlib.md5(f"{salt}{time.time()}".encode()).hexdigest()[:8]


def _same_endpoint(a: str, b: str) -> bool:
    """True when two URLs share scheme+host+path (same endpoint, maybe different query)."""
    try:
        pa, pb = urlparse(a), urlparse(b)
        return (pa.scheme, pa.netloc, pa.path.rstrip("/")) == \
               (pb.scheme, pb.netloc, pb.path.rstrip("/"))
    except Exception:
        return False


@registry.register("candidate-generator")
class CandidateGeneratorNode(NodeBase, NodeEmitter):
    node_type = "candidate-generator"

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        t0 = self.emit_started(ctx)

        urls_with_params: list[str] = ctx.get("urls_with_params", [])
        forms:            list[dict] = ctx.get("forms", [])
        max_candidates:   int = int(ctx.config.get("max_candidates", 50))

        candidates: list[dict] = []
        inputs_analyzed = 0

        context_analyser  = ContextAnalyser()

        with httpx.Client(
            follow_redirects=True, timeout=12,
            verify=False, headers={"User-Agent": _UA},
        ) as client:
            enc_analyser = EncodingAnalyser(client)

            # ── URL parameters ────────────────────────────────────────
            for url in urls_with_params:
                if len(candidates) >= max_candidates:
                    break
                for param in list(parse_qs(urlparse(url).query).keys()):
                    if len(candidates) >= max_candidates:
                        break
                    inputs_analyzed += 1
                    c = self._analyse_param(
                        client, context_analyser, enc_analyser,
                        ctx, url, param, "GET",
                    )
                    if c:
                        candidates.append(c)
                        self.emit_progress(
                            ctx,
                            f"  Candidate: {param} @ {url[:60]}"
                            f"  context={c['context_analysis']['context']}",
                        )

            # ── XHR/fetch API endpoints discovered by dom-xss-detect ─
            # DOM sinks fed by responseText/.json() read the tainted value
            # from an API response — probe those endpoints for reflection or
            # the parameter is reported as unreflected and the planner gets
            # no context evidence.
            # api_eval_endpoints: XHR→eval() flows (newly tracked by dom_xss)
            # api_endpoints:      generic XHR endpoints (tracked previously)
            api_eval_set: set[str] = set()
            for api in (ctx.get("api_eval_endpoints") or [])[:10]:
                if len(candidates) >= max_candidates:
                    break
                endpoint = str(api.get("endpoint", "") or "")
                source_param = str(api.get("source_param", "") or "")
                if not endpoint:
                    continue
                api_url = endpoint
                if not api_url.startswith(("http://", "https://")):
                    target = str(ctx.get("target_url", "") or "")
                    if not target:
                        continue
                    api_url = urljoin(target, api_url)
                # Track for dedup with generic api_endpoints below
                api_eval_set.add(api_url.split("?")[0])
                # Construct a parameterised URL if not already parameterised
                if "?" not in api_url and source_param:
                    api_url = f"{api_url}?{source_param}="
                for param in sorted(parse_qs(urlparse(api_url).query,
                                             keep_blank_values=True).keys()):
                    if len(candidates) >= max_candidates:
                        break
                    inputs_analyzed += 1
                    c = self._analyse_param(
                        client, context_analyser, enc_analyser,
                        ctx, api_url, param, "GET",
                    )
                    if c:
                        # Critical: mark sink_kind=js_execution so the
                        # synthesiser selects js_string_double, not tag_injection.
                        c["is_api_eval_endpoint"] = True
                        c["sink_kind"] = "js_execution"
                        c["sink"] = api.get("flow_type", "eval(responseText)")
                        # Also update the encoding_profile so plan_for_context
                        # and scenario_from_evidence both see the sink.
                        ep = c.get("encoding_profile", {})
                        ep["sink_kind"] = "js_execution"
                        ep["source_type"] = "query"
                        c["encoding_profile"] = ep
                        candidates.append(c)
                        self.emit_progress(
                            ctx,
                            f"  Candidate (api_eval): {param} @ {api_url[:60]}"
                            f"  context={c['context_analysis']['context']}"
                            f"  sink=eval(responseText)",
                        )

            for api in (ctx.get("api_endpoints") or [])[:10]:
                if len(candidates) >= max_candidates:
                    break
                endpoint = str(api.get("endpoint", "") or "")
                if not endpoint or "=" not in endpoint:
                    continue
                api_url = endpoint
                if not api_url.startswith(("http://", "https://")):
                    target = str(ctx.get("target_url", "") or "")
                    if not target:
                        continue
                    api_url = urljoin(target, api_url)
                # Skip if already covered by api_eval_endpoints
                if api_url.split("?")[0] in api_eval_set:
                    continue
                covered = any(
                    _same_endpoint(u, api_url) for u in urls_with_params
                )
                for param in sorted(parse_qs(urlparse(api_url).query,
                                             keep_blank_values=True).keys()):
                    if covered:
                        break
                    if len(candidates) >= max_candidates:
                        break
                    inputs_analyzed += 1
                    c = self._analyse_param(
                        client, context_analyser, enc_analyser,
                        ctx, api_url, param, "GET",
                    )
                    if c:
                        c["is_api_endpoint"] = True
                        candidates.append(c)
                        self.emit_progress(
                            ctx,
                            f"  Candidate (api): {param} @ {api_url[:60]}"
                            f"  context={c['context_analysis']['context']}",
                        )

            # ── Form inputs ───────────────────────────────────────────
            for form in forms:
                if len(candidates) >= max_candidates:
                    break
                action = form["action"]
                _method = form["method"]  # noqa: F841 — used indirectly via _analyse_form_input
                for inp in form.get("inputs", []):
                    if len(candidates) >= max_candidates:
                        break
                    param = inp.get("name", "")
                    if not param:
                        continue
                    inputs_analyzed += 1
                    c = self._analyse_form_input(
                        client, context_analyser, enc_analyser,
                        ctx, form, param,
                    )
                    if c:
                        candidates.append(c)
                        self.emit_progress(
                            ctx,
                            f"  Candidate (form): {param} @ {action[:60]}"
                            f"  context={c['context_analysis']['context']}",
                        )

        ms = (time.monotonic() - t0) * 1000
        self.emit_completed(ctx, metrics={
            "inputs_analyzed": inputs_analyzed,
            "candidates":      len(candidates),
        }, duration_ms=ms)

        return {
            "xss_candidates":  candidates,
            "inputs_analyzed": inputs_analyzed,
            "candidate_count": len(candidates),
        }

    # ------------------------------------------------------------------

    def _analyse_param(
        self, client, ctx_analyser, enc_analyser,
        ctx, url, param, method,
    ) -> dict | None:
        canary = _canary(param)
        probe_url = self._inject_param(url, param, canary)
        try:
            ctx.scope.assert_allowed(probe_url, operation="http_request")
            resp = client.get(probe_url)
        except Exception:
            return None

        # Reject error/redirect responses — they often echo the URL in their
        # body causing false-positive reflection detection
        if resp.status_code >= 400:
            return None

        # Only analyse HTML or JSON responses — skip binary, CSS, etc.
        ct = resp.headers.get("content-type", "").lower()
        if not (ct.startswith("text/html") or ct.startswith("application/json")
                or ct.startswith("text/plain")):
            return None

        analysis = ctx_analyser.analyse(resp.text, canary)
        if not analysis.reflected:
            return None

        # Get all reflections — pick best, but store all for the test planner
        all_analyses = ctx_analyser.analyse_all(resp.text, canary)

        # Run encoding probe
        enc_profile = enc_analyser.probe(url, param, method="GET")

        # For JSON-context reflections: synthesiser needs sink_kind to select
        # js_string_double families instead of the inert tag_injection fallback.
        ctx_name = analysis.context
        inferred_sink_kind = ""
        if ctx_name in ("json_value", "json_string", "json_key") or ctx_name.startswith("script_string") or ctx_name == "script_expression":
            inferred_sink_kind = "js_execution"

        # For JSON/script contexts, can_break_script_string is meaningful
        # even if the raw '"' wasn't seen in the encoding probe yet — the
        # context classifier already found the quote boundary.
        can_break_script = enc_profile.can_break_script_string()
        if ctx_name in ("json_value", "json_string", "json_key"):
            # " must survive for a breakout — check it directly
            can_break_script = '"' not in enc_profile.encoded_chars and \
                               '"' not in enc_profile.stripped_chars

        result: dict = {
            "url":              url,
            "parameter":        param,
            "method":           method,
            "canary_evidence":  analysis.full_snippet[:300],
            "context_analysis": analysis.to_evidence_dict(),
            "all_contexts":     [a.to_evidence_dict() for a in all_analyses],
            "encoding_profile": {
                "raw_chars":     enc_profile.raw_chars,
                "encoded_chars": enc_profile.encoded_chars,
                "stripped_chars":enc_profile.stripped_chars,
                "summary":       enc_profile.summary(),
                "can_break_html_text":      enc_profile.can_break_html_text(),
                "can_break_html_attribute": enc_profile.can_break_html_attribute(),
                "can_break_script_string":  can_break_script,
            },
            "confidence": analysis.confidence,
            "request_url": probe_url,
        }
        if inferred_sink_kind:
            result["sink_kind"] = inferred_sink_kind
            result["encoding_profile"]["sink_kind"] = inferred_sink_kind
        return result

    def _analyse_form_input(
        self, client, ctx_analyser, enc_analyser,
        ctx, form, param,
    ) -> dict | None:
        canary = _canary(param)
        action = form["action"]
        method = form["method"]
        is_api = form.get("is_api", False)
        content_type = form.get("content_type", "")

        # Build the payload for this probe
        data = {
            inp["name"]: canary if inp["name"] == param else (inp.get("value") or "test")
            for inp in form["inputs"]
        }

        try:
            ctx.scope.assert_allowed(action, operation="http_request")

            if method == "POST":
                if content_type == "application/json" or is_api:
                    resp = client.post(
                        action, json=data,
                        headers={"Content-Type": "application/json"},
                    )
                else:
                    resp = client.post(action, data=data)
            else:
                resp = client.get(action, params=data)
        except Exception:
            return None

        # Reject error responses — they echo paths/params, causing false positives
        if resp.status_code >= 400:
            return None

        # Only analyse text responses
        ct = resp.headers.get("content-type", "").lower()
        if not (ct.startswith("text/html") or ct.startswith("application/json")
                or ct.startswith("text/plain")):
            return None

        body = resp.text

        # For API/JSON endpoints: check Content-Type first, then analyse
        resp_is_json = ct.startswith("application/json")

        analysis = ctx_analyser.analyse(body, canary)

        # For API/JSON responses that reflect the input back in JSON,
        # override the context to json_value (ContextAnalyser doesn't know
        # the Content-Type and may misclassify it as html_text)
        if resp_is_json and canary in body:
            from xscan.nodes.analysis.context import ContextAnalysis
            analysis = ContextAnalysis(
                marker=canary,
                reflected=True,
                raw_present=True,
                context="json_value",
                confidence="high",
                full_snippet=body[:300],
            )
        elif not analysis.reflected and is_api and canary in body:
            # Non-JSON API response that still reflects the canary
            from xscan.nodes.analysis.context import ContextAnalysis
            analysis = ContextAnalysis(
                marker=canary,
                reflected=True,
                raw_present=True,
                context="json_value",
                confidence="medium",
                full_snippet=body[:300],
            )

        if not analysis.reflected:
            return None

        enc_profile = enc_analyser.probe(
            action, param, method=method,
            form_data={inp["name"]: inp.get("value", "test") for inp in form["inputs"]},
        )

        result = {
            "url":              action,
            "parameter":        param,
            "method":           method,
            "canary_evidence":  analysis.full_snippet[:300],
            "context_analysis": analysis.to_evidence_dict(),
            "encoding_profile": {
                "raw_chars":     enc_profile.raw_chars,
                "encoded_chars": enc_profile.encoded_chars,
                "stripped_chars":enc_profile.stripped_chars,
                "summary":       enc_profile.summary(),
                "can_break_html_text":      enc_profile.can_break_html_text(),
                "can_break_html_attribute": enc_profile.can_break_html_attribute(),
                "can_break_script_string":  enc_profile.can_break_script_string(),
            },
            "form":       form,
            "confidence": analysis.confidence,
        }
        if is_api:
            result["is_api"] = True
            result["content_type"] = content_type or ("application/json" if method == "POST" else "")
        return result

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return urlunparse(parsed._replace(query=new_query))
