"""
evidence-fusion node — Phase I
================================
Merges outputs from all detection engines into a unified XSSCandidate list.
Deduplicates by (url, parameter, context) or (source, sink) for DOM.

Inputs:
  xss_candidates   — from candidate-generator (reflected)
  dom_candidates   — from dom-xss-detector (simple DOM)
  api_endpoints    — from dom-xss-detector (XHR/fetch endpoints that feed sinks)
  taint_paths      — from taint-graph-builder (deep DOM)
  stored_candidates— from stored-xss-detector
  tool_observations— from tool-xss-scan

Outputs:
  fused_candidates (list[dict])  — deduplicated, typed XSSCandidate dicts
  fused_count      (int)
"""
from __future__ import annotations

import time
from typing import Any

from xscan.core.dag.node_registry import registry
from xscan.nodes.base import NodeBase, ExecutionContext
from xscan.nodes.emitter import NodeEmitter
from xscan.schemas.xss import (
    XSSCandidate, XSSType, ValidationStatus,
    ContextObservation, TaintPath, ToolObservation, ToolStatus,
)


@registry.register("evidence-fusion")
class EvidenceFusionNode(NodeBase, NodeEmitter):
    node_type = "evidence-fusion"

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        t0 = self.emit_started(ctx)

        # Collect from all engines
        # candidate-generator outputs "xss_candidates"
        # reflection-detector (xss-fast) outputs "candidates"
        # Accept both so the key mismatch never silently loses reflections
        reflected_raw: list[dict] = (
            ctx.get("xss_candidates") or
            ctx.get("candidates") or
            []
        )
        dom_simple:    list[dict] = ctx.get("dom_candidates", [])
        api_endpoints: list[dict] = ctx.get("api_endpoints", [])
        taint_raw:     list[dict] = ctx.get("taint_paths", [])
        stored_raw:    list[dict] = ctx.get("stored_candidates", [])
        tool_raw:      list[dict] = ctx.get("tool_observations", [])

        fused: list[XSSCandidate] = []
        seen:  set[str] = set()

        # ── Reflected candidates ──────────────────────────────────────
        for raw in reflected_raw:
            key = f"reflected:{raw.get('url','')}:{raw.get('parameter','')}:{raw.get('context_analysis',{}).get('context','')}"
            if key in seen:
                continue
            seen.add(key)
            c = XSSCandidate.from_dict(raw)
            c.xss_type = XSSType.REFLECTED

            # Propagate endpoint validity from candidate-gen
            c.endpoint_status  = raw.get("endpoint_status", "valid")
            c.rejection_reason = raw.get("rejection_reason", "")

            # json_value context means the input is reflected in a JSON API
            # response. Without browser verification this is not actionable as
            # HTTP-only reflected XSS — mark as low-confidence potential.
            ctx_name = (c.context_analysis.context if c.context_analysis else
                        raw.get("context_analysis", {}).get("context", ""))
            if ctx_name in ("json_value", "json_key", "json_string"):
                c.confidence = "low"
                if not c.rejection_reason:
                    c.rejection_reason = (
                        "JSON API reflection — requires browser/DOM verification "
                        "to determine if the value reaches a dangerous sink"
                    )

            fused.append(c)

        # ── Simple DOM candidates (from dom_xss.py) ───────────────────
        for raw in dom_simple:
            src   = raw.get("source", "")
            sink  = raw.get("sink", "")
            file_ = raw.get("file_url", "")
            param = raw.get("param", "")
            key   = f"dom:{src}:{sink}:{file_}:{param}"
            if key in seen:
                continue
            seen.add(key)

            payloads  = raw.get("payloads", [])
            test_urls = raw.get("test_urls", [])
            c = XSSCandidate(
                xss_type=XSSType.DOM,
                url=raw.get("url") or raw.get("best_test_url", ctx.get("target_url", "")),
                parameter=raw.get("param", ""),
                confidence=raw.get("confidence", "medium"),
                best_payload=payloads[0] if payloads else "",
                best_test_url=test_urls[0] if test_urls else "",
            )
            # Carry the sink context through so the browser confirmer knows what
            # to send and how to trigger it (url_attribute -> click, etc.).
            sink_kind = raw.get("sink_kind", "")
            c.encoding_profile = {
                "xss_type":       "dom",
                "sink":           sink,
                "sink_kind":      sink_kind,
                "sink_attribute": raw.get("sink_attribute", ""),
                "interaction":    raw.get("interaction", "none"),
                "source":         src,
                "source_type":    raw.get("source_type", ""),
                "trigger_event":  raw.get("trigger_event", ""),
                "requires_browser": bool(raw.get("requires_browser", True)),
                # Capability + payload family so the validator tests the payload
                # class the sink needs (javascript: URI for href, markup for
                # innerHTML) instead of falling back to generic markup.
                "sink_capability": _sink_capability(sink_kind),
                "payloads":        [str(p) for p in payloads[:3]],
            }
            c.canary_evidence = raw.get("snippet", "")[:200]
            fused.append(c)

        # ── XHR/fetch API endpoints that feed DOM sinks ───────────────
        # A sink reading responseText/.json() is fed by an API response: the
        # parameter's reflection lives there, not in the HTML page. Emit the
        # parameterised endpoints so candidate-generation can probe them.
        if api_endpoints:
            target_base = str(ctx.get("target_url", "") or "")
            for raw in api_endpoints[:10]:
                endpoint = str(raw.get("endpoint", "") or "")
                if not endpoint or "=" not in endpoint:
                    continue
                api_url = endpoint
                if not api_url.startswith(("http://", "https://")):
                    if not target_base:
                        continue
                    # Relative endpoint — resolve against the target page.
                    try:
                        from urllib.parse import urljoin
                        api_url = urljoin(target_base, api_url)
                    except Exception:
                        continue
                key = f"api-endpoint:{api_url}"
                if key in seen:
                    continue
                seen.add(key)
                params = sorted({p for p in _endpoint_param_names(api_url)})
                c = XSSCandidate(
                    xss_type=XSSType.REFLECTED,
                    url=api_url,
                    parameter=params[0] if params else "",
                    confidence="medium",
                    canary_evidence=(
                        "sink feeds from this endpoint's response "
                        f"({raw.get('source', 'unknown')})"
                    ),
                )
                fused.append(c)

        # ── Taint path candidates (from taint-graph-builder) ──────────
        for raw in taint_raw:
            src_node  = (raw.get("source") or {})
            snk_node  = (raw.get("sink")   or {})
            evt_raw   = raw.get("event")
            src_label = src_node.get("label", "")
            snk_label = snk_node.get("sink_label", snk_node.get("label", ""))
            file_     = src_node.get("file_url", "")
            key       = f"taint:{src_label}:{snk_label}:{file_}"
            if key in seen:
                continue
            seen.add(key)

            pays    = raw.get("payloads", [])
            turls   = raw.get("test_urls", [])
            try:
                tp = TaintPath(**raw)
            except Exception:
                tp = None

            # Unpack event observation so it's directly visible to the validator
            dom_event_obj = None
            if evt_raw:
                try:
                    from xscan.schemas.xss import DOMEventObservation
                    dom_event_obj = DOMEventObservation(**evt_raw)
                except Exception:
                    pass

            # Build execution semantics so the validator knows this is event-driven
            exec_semantics = _build_execution_semantics(
                src_label=src_label,
                snk_label=snk_label,
                event_type=dom_event_obj.event_type if dom_event_obj else "",
                context_snippet=dom_event_obj.context if dom_event_obj else "",
                transformations=_extract_transforms(dom_event_obj),
            )

            c = XSSCandidate(
                xss_type=XSSType.DOM,
                url=turls[0] if turls else ctx.get("target_url", ""),
                confidence=raw.get("confidence", "medium"),
                taint_path=tp,
                dom_event=dom_event_obj,
                best_payload=pays[0] if pays else "",
                best_test_url=turls[0] if turls else "",
            )
            # Store execution semantics in encoding_profile so validator can read it
            exec_semantics["payloads"] = [str(p) for p in pays[:3]]
            c.encoding_profile = exec_semantics
            fused.append(c)

        # ── Stored candidates ─────────────────────────────────────────
        for raw in stored_raw:
            key = f"stored:{raw.get('form_action','')}:{raw.get('parameter','')}:{raw.get('found_at','')}"
            if key in seen:
                continue
            seen.add(key)
            c = XSSCandidate(
                xss_type=XSSType.STORED,
                url=raw.get("found_at", ""),
                parameter=raw.get("parameter", ""),
                method=raw.get("method", "POST") or "POST",
                stored_at=raw.get("form_action", ""),
                found_at=raw.get("found_at", ""),
                canary_evidence=raw.get("snippet", ""),
                confidence="high",
            )
            # Carry the reflection context through so downstream nodes see
            # WHERE the canary landed (e.g. inside <a href="...">).
            ca_dict = dict(raw.get("context_analysis") or {})
            if ca_dict:
                ca_dict.setdefault(
                    "marker", str(raw.get("canary", "") or "stored-canary")[:40]
                )
                # ContextAnalyser evidence keys predate the schema names
                ca_dict["tag_name"]      = str(ca_dict.pop("tag", "") or "")
                ca_dict["attribute_name"] = str(ca_dict.pop("attribute", "") or "")
                ca_dict["full_snippet"]  = str(ca_dict.pop("snippet", "") or "")
                try:
                    c.context_analysis = ContextObservation(**ca_dict)
                except Exception:
                    c.context_analysis = None
            # Carry sink/trigger semantics so the browser confirmer knows how
            # to execute the payload: a javascript: URI stored in an href needs
            # a click, exactly like a DOM url_attribute sink.
            sink_kind = str(raw.get("sink_kind", "") or "")
            if sink_kind:
                c.encoding_profile = {
                    "xss_type":        "stored",
                    "sink_kind":       sink_kind,
                    "sink_capability": ("url_sink" if sink_kind == "url_attribute"
                                        else "html_injection"),
                    "interaction":     "click" if sink_kind == "url_attribute" else "none",
                    "requires_browser": True,
                }
                if sink_kind == "url_attribute":
                    # The reflection context (<a href="...">) makes the exploit
                    # class unambiguous: the stored value executes only as a
                    # scheme, so seed the browser confirmer with it.
                    c.best_payload = "javascript:alert(1)"
                    c.best_test_url = c.found_at or c.url
            fused.append(c)

        # ── Attach tool observations to matching candidates ───────────
        tool_obs_list = [ToolObservation(**t) for t in tool_raw if t]
        for obs in tool_obs_list:
            if not obs.has_candidates:
                continue
            # Find matching candidate by URL
            matched = False
            for c in fused:
                if obs.target_url and obs.target_url in (c.url, c.best_test_url):
                    c.tool_observations.append(obs)
                    matched = True
                    break
            if not matched:
                # Add as standalone candidate with tool evidence
                c = XSSCandidate(
                    xss_type=XSSType.REFLECTED,
                    url=obs.target_url,
                    confidence="medium",
                    best_payload=obs.payloads[0] if obs.payloads else "",
                )
                c.tool_observations = [obs]
                fused.append(c)

        ms = (time.monotonic() - t0) * 1000
        rejected = [c for c in fused if c.endpoint_status == "invalid"]
        actionable = [c for c in fused if c.endpoint_status != "invalid"]
        self.emit_completed(ctx, metrics={
            "reflected":  sum(1 for c in fused if c.xss_type == XSSType.REFLECTED),
            "dom":        sum(1 for c in fused if c.xss_type == XSSType.DOM),
            "stored":     sum(1 for c in fused if c.xss_type == XSSType.STORED),
            "total":      len(fused),
            "rejected":   len(rejected),
        }, duration_ms=ms)

        return {
            "fused_candidates": [c.to_dict() for c in fused],
            "fused_count":      len(fused),
            "rejected_count":   len(rejected),
            "actionable_count": len(actionable),
        }


# ---------------------------------------------------------------------------
# Execution semantics helpers
# ---------------------------------------------------------------------------

def _endpoint_param_names(url: str) -> set[str]:
    """Parameter names present in an API endpoint URL (``?search=`` shape)."""
    from urllib.parse import parse_qs, urlparse
    try:
        return set(parse_qs(urlparse(url).query, keep_blank_values=True).keys())
    except Exception:
        return set()

# dom-xss-detector sink kind -> validator sink capability vocabulary.
_SINK_CAPABILITY: dict[str, str] = {
    "url_attribute":  "url_sink",
    "navigation":     "url_sink",
    "html_text":      "html_injection",
    "html_attribute": "html_injection",
    "event_handler":  "html_injection",
    "selector":       "selector",
    "js_execution":   "js_execution",
    "csti":           "js_execution",
}


def _sink_capability(sink_kind: str) -> str:
    """Map a resolved sink kind onto the validator's capability vocabulary."""
    return _SINK_CAPABILITY.get(sink_kind, "dom_general")


def _build_execution_semantics(
    src_label: str,
    snk_label: str,
    event_type: str,
    context_snippet: str,
    transformations: list[str],
) -> dict:
    """
    Build an execution_semantics dict that the IterativeValidator
    uses to select the correct validation strategy.

    This is the 'missing layer' between taint analysis and validation.
    """
    source_type = "hash" if "hash" in src_label.lower() else (
        "query" if "search" in src_label.lower() or "URLSearch" in src_label else
        "href"  if "href" in src_label.lower() else "unknown"
    )

    # Sink capability determines the required validation strategy
    sink_cap = "selector" if "jQuery" in snk_label and "$" in snk_label else (
        "html_injection" if any(s in snk_label for s in ("innerHTML", "outerHTML", "document.write")) else
        "js_execution"   if any(s in snk_label for s in ("eval", "Function", "setTimeout")) else
        "url_sink"       if any(s in snk_label for s in ("href", "src", "assign", "replace")) else
        "dom_general"
    )

    # Validation mode: event-triggered vs direct navigation
    validation_mode = "event_triggered" if event_type in (
        "hashchange", "popstate", "message", "load", "DOMContentLoaded"
    ) else "direct_navigation"

    return {
        # DOM execution context — not HTTP encoding profile
        "xss_type":            "dom",
        "source_type":         source_type,
        "source_label":        src_label,
        "sink_label":          snk_label,
        "sink_capability":     sink_cap,
        "event_type":          event_type,
        "validation_mode":     validation_mode,
        "transformations":     transformations,
        "context_snippet":     context_snippet[:300],
        # These signal to the heuristic planner to use DOM-aware payloads
        "raw_chars":           [],
        "encoded_chars":       [],
        "can_break_html_text": False,
        "can_break_html_attribute": False,
    }


def _extract_transforms(evt) -> list[str]:
    """Extract transform functions observed in the event callback."""
    if not evt:
        return []
    transforms = []
    ctx = getattr(evt, "context", "") or ""
    source_refs = getattr(evt, "source_refs", []) or []
    for ref in source_refs:
        if "decodeURIComponent" in ref:
            transforms.append("decodeURIComponent")
        if "slice" in ctx:
            transforms.append("slice")
        if "split" in ctx:
            transforms.append("split")
        if "replace" in ctx:
            transforms.append("replace")
    return list(dict.fromkeys(transforms))
