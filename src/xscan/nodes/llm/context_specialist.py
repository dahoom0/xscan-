"""
llm-context-specialist node — Phase J
=======================================
Analyses each fused candidate using the ContextAnalyser specialist.
Output is a structured XSSContextAnalysis — NOT a finding confirmation.

Inputs:  fused_candidates | xss_candidates (list[dict])
Outputs: analysed_candidates (list[dict])
"""
from __future__ import annotations

import time
from typing import Any

from pydantic import BaseModel

from xscan.core.dag.node_registry import registry
from xscan.nodes.base import NodeBase, ExecutionContext
from xscan.nodes.emitter import NodeEmitter
from xscan.schemas.llm import SpecialistInput, SpecialistOutput
from xscan.schemas.xss import XSSCandidate, XSSType


class XSSContextAnalysis(SpecialistOutput):
    """Structured LLM context analysis — NOT a finding confirmation."""
    classification:      str = ""         # e.g. "Reflected XSS in HTML attribute"
    source:              str | None = None
    sink:                str | None = None
    context:             str = ""
    explanation:         str = ""
    supporting_evidence: list[str] = []
    specialist: str = "context-analyst"


class ContextAnalystInput(SpecialistInput):
    candidate_dict: dict[str, Any]


_SYSTEM = """\
You are an XSS context analysis specialist.
Analyse the provided candidate and produce a structured explanation.
You do NOT confirm vulnerabilities — you classify and explain.
Respond ONLY with valid JSON.
"""

_PROMPT = """\
XSS Candidate:

type:            {xss_type}
url:             {url}
parameter:       {parameter}
context:         {context}
tag/attribute:   {tag}/{attribute}
quote_type:      {quote_type}
encoded_chars:   {encoded_chars}
raw_chars:       {raw_chars}
taint_source:    {taint_source}
taint_sink:      {taint_sink}
event:           {event}
canary_evidence: {evidence}

Analyse and respond with JSON:
{{
  "classification": "short type name e.g. 'Reflected XSS in HTML attribute'",
  "confidence": 0.0-1.0,
  "source": "source identifier or null",
  "sink": "sink identifier or null",
  "context": "precise context description",
  "explanation": "why this is suspicious, what the data flow is",
  "supporting_evidence": ["list", "of", "observations"]
}}
"""


@registry.register("llm-context-specialist")
class LLMContextSpecialistNode(NodeBase, NodeEmitter):
    node_type = "llm-context-specialist"

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        t0 = self.emit_started(ctx)

        raw_candidates: list[dict] = (
            ctx.get("fused_candidates") or
            ctx.get("xss_candidates") or
            ctx.get("candidates") or []
        )

        if not raw_candidates or ctx.no_llm:
            if ctx.no_llm:
                self.emit_progress(ctx, "LLM disabled — skipping context analysis")
            ms = (time.monotonic() - t0) * 1000
            self.emit_completed(ctx, metrics={"analysed": 0}, duration_ms=ms)
            return {"analysed_candidates": raw_candidates}

        analysed: list[dict] = []

        for i, raw in enumerate(raw_candidates):
            try:
                c      = XSSCandidate.from_dict(raw)
                ca     = c.context_analysis
                ep     = c.encoding_profile
                tp     = c.taint_path

                prompt = _PROMPT.format(
                    xss_type   = c.xss_type,
                    url        = c.url[:80],
                    parameter  = c.parameter,
                    context    = ca.context if ca else "unknown",
                    tag        = ca.tag_name if ca else "",
                    attribute  = ca.attribute_name if ca else "",
                    quote_type = ca.quote_type if ca else "",
                    encoded_chars = ep.get("encoded_chars", []),
                    raw_chars     = ep.get("raw_chars", []),
                    taint_source  = tp.source_label if tp else "",
                    taint_sink    = tp.sink_label_str if tp else "",
                    event         = tp.event.event_type if tp and tp.event else "",
                    evidence      = c.canary_evidence[:200],
                )

                from xscan.llm.gateway import get_gateway
                from xscan.schemas.llm import LLMRequest
                import json, re

                req  = LLMRequest(
                    model=ctx.config.get("model", ""),
                    system_prompt=_SYSTEM,
                    user_prompt=prompt,
                    specialist="context-analyst",
                    scan_id=ctx.scan_id,
                    node_id=ctx.node_id,
                    timeout=60,
                )
                if not req.model:
                    from xscan.config import get_settings
                    req = req.model_copy(update={"model": get_settings().llm.model})

                resp = get_gateway().complete(req)
                if resp.success:
                    data = {}
                    m    = re.search(r"\{[\s\S]+\}", resp.raw_text)
                    if m:
                        try:
                            data = json.loads(m.group())
                        except Exception:
                            pass
                    raw["llm_context_analysis"] = data
                    raw["llm_classification"]   = data.get("classification", "")
                    raw["llm_explanation"]       = data.get("explanation", "")

            except Exception as exc:
                ctx.logger.warning("Context specialist error on candidate %d: %s", i, exc)
                raw["llm_context_analysis"] = {}

            analysed.append(raw)

        ms = (time.monotonic() - t0) * 1000
        self.emit_completed(ctx, metrics={"analysed": len(analysed)}, duration_ms=ms)
        return {"analysed_candidates": analysed}
