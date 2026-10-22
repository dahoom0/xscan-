"""
XSS Domain Schemas — Phase B
=============================
Typed Pydantic models for all XSS analysis components.
All inter-node communication uses these schemas, never raw dicts.

Models defined here:
  XSSCandidate          — normalised candidate from any engine
  DOMSourceObservation  — detected DOM taint source
  DOMSinkObservation    — detected DOM taint sink
  DOMEventObservation   — event-driven DOM flow
  TaintNode             — vertex in the taint graph
  TaintEdge             — directed edge in the taint graph
  TaintPath             — source → sink path through the taint graph
  ContextObservation    — deterministic reflection context analysis result
  ToolObservation       — normalised external tool result
"""
from __future__ import annotations

import uuid
from datetime import datetime, UTC
from enum import StrEnum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class XSSType(StrEnum):
    REFLECTED       = "reflected"
    STORED          = "stored"
    DOM             = "dom"
    REFLECTED_DOM   = "reflected_dom"
    STORED_DOM      = "stored_dom"
    UNKNOWN         = "unknown"


class ValidationStatus(StrEnum):
    UNVALIDATED  = "unvalidated"
    VALIDATED    = "validated"    # unencoded reflection confirmed via HTTP
    CONFIRMED    = "confirmed"    # browser evidence proves execution
    REJECTED     = "rejected"
    INCONCLUSIVE = "inconclusive"


class DOMSourceType(StrEnum):
    LOCATION_SEARCH     = "location.search"
    LOCATION_HASH       = "location.hash"
    LOCATION_HREF       = "location.href"
    DOCUMENT_URL        = "document.URL"
    DOCUMENT_REFERRER   = "document.referrer"
    WINDOW_NAME         = "window.name"
    URL_SEARCH_PARAMS   = "URLSearchParams.get()"
    DECODE_URI          = "decodeURIComponent()"
    POST_MESSAGE        = "postMessage"
    COOKIE              = "document.cookie"
    LOCAL_STORAGE       = "localStorage"
    SESSION_STORAGE     = "sessionStorage"
    CUSTOM              = "custom"


class DOMSinkCategory(StrEnum):
    HTML        = "html"
    DOM         = "dom"
    ATTRIBUTE   = "attribute"
    URL         = "url"
    JAVASCRIPT  = "javascript"
    SELECTOR    = "selector"
    FRAMEWORK   = "framework"


class TaintNodeType(StrEnum):
    SOURCE      = "source"
    VARIABLE    = "variable"
    FUNCTION    = "function"
    ARGUMENT    = "argument"
    RETURN      = "return"
    PROPERTY    = "property"
    SINK        = "sink"
    TRANSFORM   = "transform"


class ToolStatus(StrEnum):
    CONFIRMED_CANDIDATE = "confirmed_candidate"
    CANDIDATE           = "candidate"
    NO_CANDIDATES       = "no_candidates"
    NO_PARAMETERS       = "no_parameters"
    CONNECTION_FAILED   = "connection_failed"
    EXECUTION_FAILED    = "execution_failed"
    TIMEOUT             = "timeout"
    UNSUPPORTED         = "unsupported"


# ---------------------------------------------------------------------------
# ContextObservation — replaces the dataclass in nodes/analysis/context.py
# ---------------------------------------------------------------------------

class ContextObservation(BaseModel):
    """
    Deterministic reflection context analysis.
    Produced by ContextAnalyser, consumed by LLM specialists and XssValidator.
    """
    marker:          str
    reflected:       bool = False
    raw_present:     bool = False

    # Injection context
    context: str = "unknown"
    # Possible: html_text, html_attribute, html_attribute_unquoted,
    #           html_comment, html_url_attribute, html_event_handler,
    #           javascript_string, javascript_string_double,
    #           javascript_string_single, javascript_string_template,
    #           javascript_expression, javascript_template_literal,
    #           css, url, json, svg, dom, jquery, framework_template, unknown

    # HTML element / attribute context
    tag_name:       str = ""
    attribute_name: str = ""
    quote_type:     str = ""    # double | single | unquoted | none

    # JavaScript context
    script_quote:   str = ""    # double | single | template | none

    # Encoding / transformation
    encoded_chars:  list[str] = Field(default_factory=list)
    breakout_chars: list[str] = Field(default_factory=list)

    # Evidence snippets
    before:       str = ""
    after:        str = ""
    full_snippet: str = ""

    # Confidence
    confidence: str = "high"   # high | medium | low

    # All reflection positions (for multi-context targets)
    all_contexts: list[dict[str, Any]] = Field(default_factory=list)

    def to_evidence_dict(self) -> dict[str, Any]:
        return self.model_dump(exclude={"all_contexts"})


# ---------------------------------------------------------------------------
# DOMSourceObservation
# ---------------------------------------------------------------------------

class DOMSourceObservation(BaseModel):
    """A detected DOM taint source with its AST location."""
    id: str = Field(default_factory=lambda: "SRC-" + uuid.uuid4().hex[:8])
    source_type: DOMSourceType = DOMSourceType.CUSTOM
    label:       str = ""       # e.g. "location.hash.slice(1)"
    file_url:    str = ""       # JS file URL or "inline"
    line:        int = 0
    column:      int = 0
    ast_node_type: str = ""
    snippet:     str = ""
    # The variable/property the source value is assigned to
    assigned_to: str = ""
    confidence:  str = "medium"


# ---------------------------------------------------------------------------
# DOMSinkObservation
# ---------------------------------------------------------------------------

class DOMSinkObservation(BaseModel):
    """A detected DOM taint sink with its AST location."""
    id: str = Field(default_factory=lambda: "SNK-" + uuid.uuid4().hex[:8])
    sink_label:    str = ""     # e.g. "jQuery $()"
    sink_category: DOMSinkCategory = DOMSinkCategory.DOM
    severity:      str = "high" # critical | high | medium | low
    file_url:      str = ""
    line:          int = 0
    column:        int = 0
    ast_node_type: str = ""
    snippet:       str = ""
    confidence:    str = "medium"


# ---------------------------------------------------------------------------
# DOMEventObservation
# ---------------------------------------------------------------------------

class DOMEventObservation(BaseModel):
    """
    An event-driven DOM execution path.
    Critical for hashchange / popstate / message patterns.
    """
    id: str = Field(default_factory=lambda: "EVT-" + uuid.uuid4().hex[:8])
    event_type:    str = ""     # hashchange | popstate | message | load | etc.
    file_url:      str = ""
    line:          int = 0
    column:        int = 0
    callback_snippet: str = ""
    # Source references found within the callback
    source_refs:   list[str] = Field(default_factory=list)
    # Sink references found within the callback
    sink_refs:     list[str] = Field(default_factory=list)
    # Full context window around the event listener
    context:       str = ""


# ---------------------------------------------------------------------------
# TaintNode / TaintEdge / TaintPath
# ---------------------------------------------------------------------------

class TaintNode(BaseModel):
    """A vertex in the taint graph."""
    id:          str = Field(default_factory=lambda: "TN-" + uuid.uuid4().hex[:8])
    node_type:   TaintNodeType = TaintNodeType.VARIABLE
    label:       str = ""       # variable name, function name, etc.
    file_url:    str = ""
    line:        int = 0
    column:      int = 0
    snippet:     str = ""
    # For source nodes
    source_type: Optional[DOMSourceType] = None
    # For sink nodes
    sink_label:  str = ""
    sink_category: Optional[DOMSinkCategory] = None
    severity:    str = ""


class TaintEdge(BaseModel):
    """A directed edge in the taint graph."""
    id:       str = Field(default_factory=lambda: "TE-" + uuid.uuid4().hex[:8])
    from_id:  str
    to_id:    str
    label:    str = ""          # "assignment" | "argument" | "return" | "property"
    file_url: str = ""
    line:     int = 0


class TaintPath(BaseModel):
    """
    A complete source → sink path through the taint graph.
    This is the primary evidence for DOM XSS.
    """
    id: str = Field(default_factory=lambda: "TP-" + uuid.uuid4().hex[:8])
    nodes:      list[TaintNode] = Field(default_factory=list)
    edges:      list[TaintEdge] = Field(default_factory=list)
    source:     Optional[TaintNode] = None
    sink:       Optional[TaintNode] = None
    event:      Optional[DOMEventObservation] = None
    depth:      int = 0
    confidence: str = "medium"
    # Payloads appropriate for this source→sink combination
    payloads:   list[str] = Field(default_factory=list)
    test_urls:  list[str] = Field(default_factory=list)

    @property
    def source_label(self) -> str:
        return self.source.label if self.source else "unknown"

    @property
    def sink_label_str(self) -> str:
        return self.sink.sink_label if self.sink else "unknown"


# ---------------------------------------------------------------------------
# XSSCandidate — the normalised candidate model
# ---------------------------------------------------------------------------

class XSSCandidate(BaseModel):
    """
    Normalised XSS candidate produced by any detection engine.
    All inter-node communication uses this model, never raw dicts.
    """
    id: str = Field(default_factory=lambda: "CAND-" + uuid.uuid4().hex[:8])

    # Classification
    xss_type:   XSSType = XSSType.UNKNOWN
    confidence: str = "medium"      # high | medium | low

    # Location
    url:        str = ""
    parameter:  str = ""
    method:     str = "GET"

    # Context (from ContextObservation)
    context_analysis: Optional[ContextObservation] = None
    encoding_profile: dict[str, Any] = Field(default_factory=dict)

    # DOM-specific
    taint_path:       Optional[TaintPath] = None
    dom_source:       Optional[DOMSourceObservation] = None
    dom_sink:         Optional[DOMSinkObservation] = None
    dom_event:        Optional[DOMEventObservation] = None

    # Stored-specific
    stored_at:        str = ""      # form action where canary was submitted
    found_at:         str = ""      # page where canary was later found

    # Evidence
    canary_evidence:  str = ""
    all_contexts:     list[dict[str, Any]] = Field(default_factory=list)

    # Tool observations
    tool_observations: list["ToolObservation"] = Field(default_factory=list)

    # Validation
    validation_status: ValidationStatus = ValidationStatus.UNVALIDATED
    observations:      list[dict[str, Any]] = Field(default_factory=list)
    test_plan:         dict[str, Any] = Field(default_factory=dict)
    best_payload:      str = ""
    best_test_url:     str = ""
    replan_count:      int = 0

    # Endpoint validity (set by candidate-gen or evidence-fusion)
    # Values: "valid" | "invalid" | "unknown"
    endpoint_status:   str = "unknown"
    # Human-readable reason when endpoint_status == "invalid"
    rejection_reason:  str = ""

    # Legacy dict support (for backward compat during migration)
    _raw: dict[str, Any] = {}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "XSSCandidate":
        """
        Create an XSSCandidate from a legacy raw dict.
        Used during migration period while old nodes still output dicts.
        """
        ca_dict = d.get("context_analysis", {})
        ca: Optional["ContextObservation"] = None
        if ca_dict:
            # Ensure the required `marker` field exists — older / SPA paths
            # produce context_analysis dicts without it.
            if "marker" not in ca_dict:
                # Synthesise a marker from the canary evidence or leave as empty
                canary = d.get("canary_evidence", d.get("request_url", ""))
                ca_dict = {**ca_dict, "marker": canary[:40] or "unknown"}
            try:
                ca = ContextObservation(**ca_dict)
            except Exception:
                ca = None

        c = cls(
            xss_type=(XSSType(d.get("xss_type"))
                      if d.get("xss_type") in XSSType.__members__ or d.get("xss_type") in XSSType._value2member_map_
                      else XSSType.REFLECTED),
            url=d.get("url", ""),
            parameter=d.get("parameter", ""),
            method=d.get("method", "GET"),
            context_analysis=ca,
            encoding_profile=d.get("encoding_profile", {}),
            canary_evidence=d.get("canary_evidence", ""),
            all_contexts=d.get("all_contexts", []),
        )
        c._raw = d
        return c

    def to_dict(self) -> dict[str, Any]:
        """Serialise to dict for DAG state threading."""
        d = self.model_dump(mode="json", exclude={"_raw"})
        # Flatten context_analysis back to dict for backward compat
        if self.context_analysis:
            d["context_analysis"] = self.context_analysis.to_evidence_dict()
        return d


# ---------------------------------------------------------------------------
# ToolObservation
# ---------------------------------------------------------------------------

class ToolObservation(BaseModel):
    """
    Normalised result from an external XSS tool (XSStrike, dalfox, etc.).

    CRITICAL SEMANTICS:
      NO_PARAMETERS   ≠ safe
      NO_CANDIDATES   ≠ safe
      EXECUTION_FAILED ≠ safe
    These states mean the tool could not assess — not that there is no vulnerability.
    """
    id: str = Field(default_factory=lambda: "TOBS-" + uuid.uuid4().hex[:8])
    tool:       str = ""
    version:    str = ""
    target_url: str = ""
    endpoint:   str = ""
    parameter:  str = ""
    status:     ToolStatus = ToolStatus.NO_CANDIDATES
    observation: str = ""       # human-readable summary
    payloads:   list[str] = Field(default_factory=list)
    raw_output: str = ""        # first 500 chars of raw tool output
    evidence_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def has_candidates(self) -> bool:
        return self.status in (ToolStatus.CANDIDATE, ToolStatus.CONFIRMED_CANDIDATE)

    @property
    def is_failure(self) -> bool:
        return self.status in (
            ToolStatus.CONNECTION_FAILED,
            ToolStatus.EXECUTION_FAILED,
            ToolStatus.TIMEOUT,
        )

    @property
    def is_definitive(self) -> bool:
        """True = tool ran and produced a meaningful result (not failure/unsupported)."""
        return not self.is_failure and self.status != ToolStatus.UNSUPPORTED
