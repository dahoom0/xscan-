"""
Taint Graph — Phase E
=====================
Builds source -> variable -> function -> sink paths from
DOM source/sink/event observations and AST records.

Uses configurable budgets to prevent unbounded analysis:
  max_depth   — max nodes in a single path
  max_paths   — max paths per source
  max_nodes   — total graph node limit

Emits analysis_incomplete when budget is exceeded.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from xscan.schemas.xss import (
    TaintNode, TaintEdge, TaintPath, TaintNodeType,
    DOMSourceObservation, DOMSinkObservation, DOMEventObservation,
    DOMSourceType, DOMSinkCategory,
)

# ── Payload map: (source_type, sink_label) -> payloads ──────────────────────
_PAYLOAD_MAP: dict[tuple[str, str], list[str]] = {
    ("location.hash",  "jQuery $()"): [
        "#<img src=x onerror=alert(1)>",
        "#<svg onload=alert(1)>",
        "#<script>alert(1)</script>",
    ],
    ("location.hash",  "innerHTML"): [
        "#<img src=x onerror=alert(1)>",
        "#<svg onload=alert(1)>",
    ],
    ("location.hash",  "document.write()"): [
        "#<script>alert(1)</script>",
    ],
    ("location.hash",  "eval()"): ["#alert(1)", "#1;alert(1)//"],
    ("location.hash",  "Function()"): ["#alert(1)"],
    ("location.hash",  "element.href"): ["#javascript:alert(1)"],
    ("location.search","innerHTML"): [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    ("location.search","jQuery $()"): [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    ("location.search","eval()"): ["alert(1)", ";alert(1)//"],
    ("location.search","document.write()"): ["<script>alert(1)</script>"],
    ("location.search","element.href"): ["javascript:alert(1)"],
    ("URLSearchParams.get()", "innerHTML"): [
        "<img src=x onerror=alert(1)>",
    ],
    ("URLSearchParams.get()", "jQuery $()"): [
        "<img src=x onerror=alert(1)>",
    ],
}

_DEFAULT_PAYLOADS = [
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
]


def _payloads(source_label: str, sink_label: str) -> list[str]:
    """
    Payloads for a source -> sink path, derived from the sink's semantics.

    The scenario synthesiser picks the delivery class from the sink label (URL
    attribute / JS execution / markup) and composes the payload from it. The
    historical source/sink table stays as a fallback.
    """
    try:
        from xscan.validation.payload_synthesis import Scenario, synthesize

        sink = sink_label.lower()
        src = source_label.lower()
        source_type = "hash" if "hash" in src else "query"
        if any(k in sink for k in ("href", "src", "assign", "url")):
            scenario = Scenario(context="url_param", sink_kind="url_attribute",
                                attribute="href", source_type=source_type)
        elif any(k in sink for k in ("eval", "function(", "settimeout", "setinterval")):
            scenario = Scenario(context="script_expression", sink_kind="js_execution",
                                source_type=source_type)
        elif "jquery" in sink or "$(" in sink:
            scenario = Scenario(context="html_text", sink_kind="selector",
                                source_type=source_type)
        else:
            scenario = Scenario(context="html_text", sink_kind="html_text",
                                source_type=source_type)
        generated = [p.payload for p in synthesize(scenario, max_payloads=3)]
        if generated:
            return generated
    except Exception:
        pass

    for (src, snk), payloads in _PAYLOAD_MAP.items():
        if src.lower() in source_label.lower() and snk.lower() in sink_label.lower():
            return payloads
    return _DEFAULT_PAYLOADS


def _test_url(target_url: str, source_type: str, payload: str) -> str:
    base = target_url.rstrip("/")
    src = source_type.lower()
    if "hash" in src:
        frag = payload if payload.startswith("#") else "#" + payload
        return base + frag
    return base + "?q=" + payload


@dataclass
class TaintGraph:
    """
    In-memory taint graph built from DOM observations.

    Usage::

        tg = TaintGraph(target_url="https://example.com", budget=TaintBudget())
        tg.build(sources, sinks, events, ast_records)
        paths = tg.paths   # list[TaintPath]
    """
    target_url: str
    nodes:  dict[str, TaintNode] = field(default_factory=dict)
    edges:  list[TaintEdge]      = field(default_factory=list)
    paths:  list[TaintPath]      = field(default_factory=list)
    analysis_incomplete: bool    = False

    # Budgets
    max_depth:  int = 8
    max_paths:  int = 20
    max_nodes:  int = 500

    def build(
        self,
        sources: list[DOMSourceObservation],
        sinks:   list[DOMSinkObservation],
        events:  list[DOMEventObservation],
        ast_records: list[dict] | None = None,
    ) -> None:
        """
        Build taint paths from sources + sinks + events.

        Strategy:
          1. For each event observation that has both source_refs and sink_refs
             -> emit a direct source->event->sink path (event-driven)
          2. For source+sink in the same file within close line proximity
             -> emit a proximity path
          3. For source+sink with matching variable names in AST
             -> emit a data-flow path
        """
        if len(self.nodes) >= self.max_nodes:
            self.analysis_incomplete = True
            return

        path_count = 0

        # ── Strategy 1: Event-driven paths (e.g. hashchange + jQuery) ──
        for evt in events:
            if not evt.source_refs or not evt.sink_refs:
                continue
            for src_label in evt.source_refs:
                for snk_label in evt.sink_refs:
                    if path_count >= self.max_paths:
                        self.analysis_incomplete = True
                        return

                    src_node = self._make_source_node(src_label, evt.file_url, evt.line)
                    snk_node = self._make_sink_node(snk_label, evt.file_url, evt.line + 2)
                    evt_node = self._make_event_node(evt)

                    edge1 = TaintEdge(from_id=src_node.id, to_id=evt_node.id,  label="event-source")
                    edge2 = TaintEdge(from_id=evt_node.id, to_id=snk_node.id,  label="event-sink")
                    self.edges.extend([edge1, edge2])

                    pays  = _payloads(src_label, snk_label)
                    turls = [_test_url(self.target_url, src_label, p) for p in pays]

                    self.paths.append(TaintPath(
                        nodes=[src_node, evt_node, snk_node],
                        edges=[edge1, edge2],
                        source=src_node,
                        sink=snk_node,
                        event=evt,
                        depth=3,
                        confidence="high" if "hash" in src_label.lower() else "medium",
                        payloads=pays,
                        test_urls=turls,
                    ))
                    path_count += 1

        # ── Strategy 2: Proximity paths (same file, close lines) ────────
        for src_obs in sources:
            for snk_obs in sinks:
                if path_count >= self.max_paths:
                    self.analysis_incomplete = True
                    return
                if src_obs.file_url != snk_obs.file_url:
                    continue
                if abs(src_obs.line - snk_obs.line) > 15:
                    continue

                # Already covered by event path?
                already = any(
                    p.source and p.source.label == src_obs.label
                    and p.sink and p.sink.sink_label == snk_obs.sink_label
                    for p in self.paths
                )
                if already:
                    continue

                src_node = self._make_source_node(src_obs.label, src_obs.file_url, src_obs.line)
                snk_node = self._make_sink_node(snk_obs.sink_label, snk_obs.file_url, snk_obs.line)
                edge     = TaintEdge(from_id=src_node.id, to_id=snk_node.id, label="proximity")
                self.edges.append(edge)

                pays  = _payloads(src_obs.label, snk_obs.sink_label)
                turls = [_test_url(self.target_url, src_obs.label, p) for p in pays]

                self.paths.append(TaintPath(
                    nodes=[src_node, snk_node],
                    edges=[edge],
                    source=src_node,
                    sink=snk_node,
                    depth=2,
                    confidence="medium",
                    payloads=pays,
                    test_urls=turls,
                ))
                path_count += 1

    def to_dict_list(self) -> list[dict]:
        return [p.model_dump(mode="json") for p in self.paths]

    # ------------------------------------------------------------------

    def _make_source_node(self, label: str, file_url: str, line: int) -> TaintNode:
        key = f"src:{label}:{file_url}:{line}"
        if key not in self.nodes:
            from xscan.schemas.xss import DOMSourceType as DST
            st = DOMSourceType.CUSTOM
            for src_type in DOMSourceType:
                if src_type.value.lower() in label.lower():
                    st = src_type
                    break
            self.nodes[key] = TaintNode(
                node_type=TaintNodeType.SOURCE,
                label=label,
                file_url=file_url,
                line=line,
                source_type=st,
            )
        return self.nodes[key]

    def _make_sink_node(self, label: str, file_url: str, line: int) -> TaintNode:
        key = f"snk:{label}:{file_url}:{line}"
        if key not in self.nodes:
            from xscan.schemas.xss import DOMSinkCategory as DSC
            cat = DOMSinkCategory.DOM
            self.nodes[key] = TaintNode(
                node_type=TaintNodeType.SINK,
                label=label,
                file_url=file_url,
                line=line,
                sink_label=label,
            )
        return self.nodes[key]

    def _make_event_node(self, evt: DOMEventObservation) -> TaintNode:
        key = f"evt:{evt.event_type}:{evt.file_url}:{evt.line}"
        if key not in self.nodes:
            self.nodes[key] = TaintNode(
                node_type=TaintNodeType.FUNCTION,
                label=f"on:{evt.event_type}",
                file_url=evt.file_url,
                line=evt.line,
                snippet=evt.callback_snippet[:100],
            )
        return self.nodes[key]
