"""
Vulnerability Model Schemas
===========================
Structured representation of WHY an input is dangerous — built from the
evidence the scanner actually observed (reflection context, encoding profile,
sink semantics, taint path) and never invented for presentation.

Models:
  FlowStep            — one hop in the reconstructed data flow
  FlowEdge            — labelled edge between two FlowSteps (new)
  TransformRecord     — one transformation applied along the path (new)
  ExecutionContext    — rich context at the sink (new)
  AttackConstraints   — what an exploit for THIS path may depend on
  PayloadConstructionPlan — the plan before payload string generation (new)
  VulnerabilityModel  — full source / flow / sink / context / constraints
  CandidateProvenance — how a concrete payload was derived (for findings)

The payload synthesiser consumes AttackConstraints rather than a
vulnerability-type label, so the concrete payload is an OUTPUT of the
observed data flow rather than a dictionary lookup.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# FlowStep — one hop in the data flow
# ---------------------------------------------------------------------------

class FlowStep(BaseModel):
    """One hop in the reconstructed source -> transformation -> sink path."""
    kind: str                  # source | transformation | sink
    label: str                 # e.g. "URLSearchParams.get('q')"
    detail: str = ""           # e.g. "reads parameter 'q' from the query string"
    evidence: str = ""         # where the fact was observed (file, snippet, node)
    location: str = ""         # file:line or JS URL for DOM steps (new)

    def render(self, indent: str = "    ") -> str:
        line = f"{indent}{self.label}"
        if self.detail:
            line += f"  ({self.detail})"
        if self.location:
            line += f"  [{self.location}]"
        return line


# ---------------------------------------------------------------------------
# FlowEdge — labelled edge between two FlowSteps (new)
# ---------------------------------------------------------------------------

class FlowEdge(BaseModel):
    """
    A directed edge between two FlowStep indices.

    Describes how one step feeds the next: e.g. 'assignment', 'argument',
    'string concatenation', 'JSON.stringify', 'HTTP response body'.
    """
    from_index: int            # index into VulnerabilityModel.flow
    to_index: int
    label: str = ""            # assignment | argument | concat | response_body | etc.
    evidence: str = ""


# ---------------------------------------------------------------------------
# TransformRecord — one transformation applied along the path (new)
# ---------------------------------------------------------------------------

class TransformRecord(BaseModel):
    """
    One transformation applied to attacker-controlled data between source
    and sink.  Ordered; first element is closest to the source.

    Examples: decodeURIComponent, JSON.parse, slice, replace, toString,
              URL-decode, HTML-decode, base64-decode, trim, toLowerCase.
    """
    name: str                  # function/method name
    detail: str = ""           # e.g. "slice(1) removes the leading '#'"
    lossless: bool = True      # False when the transform can drop characters
    evidence: str = ""         # JS snippet or HTTP request/response excerpt


# ---------------------------------------------------------------------------
# SinkContext — rich context at the sink (new)
# ---------------------------------------------------------------------------

class SinkContext(BaseModel):
    """
    The exact syntactic/execution context where attacker-controlled data
    arrives at the dangerous sink.  Drives which payload families are viable.

    context_type mirrors the ExecutionContext enum names used by the
    synthesiser: JAVASCRIPT_STRING_DOUBLE, HTML_ATTRIBUTE, JSON_STRING, etc.
    """
    context_type: str = "UNKNOWN"      # one of the ExecutionContext enum values
    surrounding_syntax: str = ""       # literal text immediately around the reflection
    enclosing_construct: str = ""      # full enclosing structure (JSON object, JS string…)
    trailing_construct: str = ""       # text after the value that must be re-balanced
    delimiter: str = ""                # active delimiter: " ' ` none
    delimiter_state: str = ""          # open | closed | unquoted
    parser: str = ""                   # html | javascript | json | css | url | template
    nesting_depth: int = 0             # how deeply nested in enclosing constructs
    requires_closure: bool = False     # True when the enclosing construct must be closed
    requires_rebalance: bool = False   # True when trailing syntax must be neutralised


# ---------------------------------------------------------------------------
# AttackConstraints — the exploit contract for this exact path
# ---------------------------------------------------------------------------

class AttackConstraints(BaseModel):
    """
    What an exploit for this path is allowed to depend on, derived from the
    observed scenario. The synthesiser reasons over these instead of a
    ``vulnerability_type`` label.
    """
    source: str = ""
    source_parameter: str = ""
    sink: str = ""                      # human label
    sink_kind: str = ""                 # url_attribute | html_text | html_attribute | csti | js_execution | json_eval | …
    attribute: str = ""
    execution_context: str = ""         # url_valued_attribute | markup | js_string | template | json_eval | …
    quote_type: str = ""                # double | single | unquoted | backtick | ""
    raw_chars: list[str] = Field(default_factory=list)
    encoded_chars: list[str] = Field(default_factory=list)
    stripped_chars: list[str] = Field(default_factory=list)
    transformed_chars: list[str] = Field(default_factory=list)  # chars changed but not removed
    # Text before/after: the synthesiser closes these constructs first.
    # Increased from 24 chars to 120 so JSON object prefixes are captured.
    enclosing_construct: str = ""
    trailing_construct: str = ""
    scheme_filter: bool = False
    javascript_execution_required: bool = True
    quote_breakout_required: bool = False
    object_closure_required: bool = False   # True when JSON object {} must be closed too
    technologies: list[str] = Field(default_factory=list)
    # Inferred delivery method from source type
    delivery: str = ""                  # query | form | fragment | post | api | cookie
    trigger: str = ""                   # load | click | event | navigate | none

    @property
    def filtered(self) -> bool:
        """True when the server was observed encoding or stripping characters."""
        return bool(self.encoded_chars or self.stripped_chars)

    @property
    def angular(self) -> bool:
        return "angular" in " ".join(self.technologies).lower() or self.sink_kind == "csti"

    def infer_json_eval_closure(self, full_before: str, full_after: str) -> None:
        """
        When the reflection context is inside a JSON object literal that is
        later eval()'d, the payload must close both the string value AND the
        object before injecting code.  Detect this from the full surrounding
        text (not the truncated 24-char window) and set flags accordingly.
        """
        import re
        # Does the before-text look like it's inside a JSON object?
        if re.search(r'[{,]\s*"[\w\-]+"\s*:\s*"?$', full_before):
            self.object_closure_required = bool(re.search(r"\}", full_after))
            self.quote_breakout_required = True
            if not self.quote_type:
                self.quote_type = "double"
            if not self.execution_context:
                self.execution_context = "json_eval"

    def summary(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


# ---------------------------------------------------------------------------
# PayloadConstructionPlan — bridge between model and payload string (new)
# ---------------------------------------------------------------------------

class ConstructionStep(BaseModel):
    """One step in the syntactic transition from source to execution."""
    description: str           # human-readable explanation
    required_chars: list[str] = Field(default_factory=list)
    produces: str = ""         # what this step outputs


class PayloadConstructionPlan(BaseModel):
    """
    The plan that payload synthesis must execute.

    This is the artefact that explains WHY a particular payload works:
    it enumerates the syntactic transitions required to move from the
    current parser state (inside a JSON string / HTML attribute / etc.)
    to a controlled-execution state.

    The synthesiser constructs this plan from AttackConstraints + SinkContext
    before generating any payload string.  The plan is stored with the
    candidate so the report can explain the reasoning.
    """
    candidate_id: str = ""
    starting_context: str = ""      # e.g. "JSON string value inside eval()"
    target_state: str = ""          # e.g. "JavaScript expression in eval() scope"
    required_transition: str = ""   # e.g. "close \" + close } + inject call + comment"
    steps: list[ConstructionStep] = Field(default_factory=list)
    # Constraints used when building this plan
    quote_char: str = ""
    object_close: bool = False
    requires_comment_tail: bool = False
    # Encoding assumptions (derived from encoding profile)
    assumed_raw_chars: list[str] = Field(default_factory=list)
    assumed_encoded_chars: list[str] = Field(default_factory=list)
    # Delivery + trigger
    delivery: str = ""              # how the payload reaches the sink
    trigger: str = ""               # what causes execution
    expected_observation: str = ""  # what deterministic evidence confirms success
    # Generated from this plan
    generated_payloads: list[str] = Field(default_factory=list)
    # Provenance
    generation_mode: str = ""       # deterministic | lm_assisted | fallback


# ---------------------------------------------------------------------------
# VulnerabilityModel — full source / flow / sink / context
# ---------------------------------------------------------------------------

class VulnerabilityModel(BaseModel):
    """
    Why the input is dangerous. Every property is filled from observed
    evidence; ``explain()`` renders the finding's WHY report.
    """
    # Identity (new)
    candidate_id: str = ""
    target_url: str = ""
    endpoint: str = ""

    # Source
    source: str = ""
    source_parameter: str = ""

    # Flow
    flow: list[FlowStep] = Field(default_factory=list)
    flow_edges: list[FlowEdge] = Field(default_factory=list)         # new
    transformations: list[TransformRecord] = Field(default_factory=list)  # new

    # Sink
    sink: str = ""
    sink_argument: str = ""
    sink_context: str = ""

    # Context (enriched)
    execution_context: str = ""
    sink_context_detail: SinkContext = Field(default_factory=SinkContext)  # new

    # Encoding
    encoding_notes: list[str] = Field(default_factory=list)
    sanitization_notes: list[str] = Field(default_factory=list)

    # Attacker control
    attacker_control: str = ""          # confirmed | suspected | unverified

    # Constraints
    constraints: AttackConstraints = Field(default_factory=AttackConstraints)

    # Synthesis plan (new — populated when a plan is generated)
    construction_plan: PayloadConstructionPlan | None = None

    # Validation history refs (new)
    attempt_ids: list[str] = Field(default_factory=list)
    confirmation_evidence_ids: list[str] = Field(default_factory=list)

    def explain(self) -> list[str]:
        """The WHY lines for a finding — every claim traces to evidence."""
        lines: list[str] = []

        # Identity
        if self.candidate_id:
            lines.append(f"Candidate: {self.candidate_id}")
        if self.target_url:
            lines.append(f"Target: {self.target_url}")
        if self.endpoint:
            lines.append(f"Endpoint: {self.endpoint}")

        # Source
        if self.source:
            src = f"Source: {self.source}"
            if self.source_parameter:
                src += f"[{self.source_parameter}]"
            lines.append(src)

        # Data flow
        if self.flow:
            lines.append("Data flow:")
            for i, step in enumerate(self.flow):
                prefix = "    -> " if i else "    "
                lines.append(step.render(prefix))
                # Show edges from this step
                for edge in self.flow_edges:
                    if edge.from_index == i and edge.label:
                        lines.append(f"       via: {edge.label}")

        # Transformations
        if self.transformations:
            lines.append("Transformations:")
            for t in self.transformations:
                note = f"    {t.name}"
                if t.detail:
                    note += f": {t.detail}"
                if not t.lossless:
                    note += "  (may drop characters)"
                lines.append(note)

        # Sink
        if self.sink:
            sink_line = f"Sink: {self.sink}"
            if self.sink_argument:
                sink_line += f" [{self.sink_argument}]"
            lines.append(sink_line)
        if self.sink_context:
            lines.append(f"Sink context: {self.sink_context}")
        if self.execution_context:
            lines.append(f"Execution context: {self.execution_context}")

        # SinkContext detail
        sc = self.sink_context_detail
        if sc.context_type and sc.context_type != "UNKNOWN":
            lines.append(f"Context type: {sc.context_type}")
        if sc.surrounding_syntax:
            lines.append(f"Surrounding syntax: {sc.surrounding_syntax!r}")
        if sc.enclosing_construct:
            lines.append(f"Enclosing construct: {sc.enclosing_construct!r}")
        if sc.trailing_construct:
            lines.append(f"Trailing construct: {sc.trailing_construct!r}")
        if sc.delimiter:
            lines.append(f"Active delimiter: {sc.delimiter!r}")
        if sc.parser:
            lines.append(f"Parser: {sc.parser}")

        # Encoding
        for note in self.encoding_notes:
            lines.append(f"Encoding: {note}")
        for note in self.sanitization_notes:
            lines.append(f"Sanitization: {note}")

        # Constraints
        c = self.constraints
        if c.raw_chars:
            lines.append(f"Characters that survive reflection: {' '.join(sorted(c.raw_chars))}")
        if c.filtered:
            blocked = " ".join(dict.fromkeys(c.encoded_chars + c.stripped_chars))
            lines.append(f"Constraint: avoid characters the server alters: {blocked}")
        if c.scheme_filter:
            lines.append("Constraint: javascript: scheme was normalized — scheme-based execution unavailable")
        if c.quote_breakout_required:
            lines.append(
                f"Constraint: breakout requires terminating the "
                f"{c.quote_type or 'enclosing'!r} quote"
            )
        if c.object_closure_required:
            lines.append("Constraint: enclosing JSON object must be closed before executing")
        if c.enclosing_construct:
            lines.append(
                f"Construct: reflection inside {c.enclosing_construct[-60:]!r}"
                + (f" ... {c.trailing_construct[:60]!r}" if c.trailing_construct else "")
            )
        if c.delivery:
            lines.append(f"Delivery: {c.delivery}")
        if c.trigger:
            lines.append(f"Trigger: {c.trigger}")

        # Construction plan summary
        if self.construction_plan:
            plan = self.construction_plan
            if plan.required_transition:
                lines.append(f"Syntactic transition: {plan.required_transition}")
            if plan.expected_observation:
                lines.append(f"Expected observation: {plan.expected_observation}")

        # Attacker control
        if self.attacker_control:
            lines.append(f"Attacker control: {self.attacker_control}")

        return lines


# ---------------------------------------------------------------------------
# CandidateProvenance — how a concrete payload was derived
# ---------------------------------------------------------------------------

class CandidateProvenance(BaseModel):
    """
    Derivation record carried on a payload candidate dict.
    Answers "why this candidate" for the final report.
    """
    candidate_id: str = ""
    strategy: str = ""                  # synthesis family, e.g. attribute_breakout
    trigger: str = ""                   # none | load | click | event
    generation_reason: str = ""         # hypothesis / rationale
    parent_candidate: str = ""          # candidate_id this one was refined from
    constraints_digest: str = ""        # fingerprint of the constraints used
    generation_mode: str = ""           # scenario_synthesis | refinement | fallback
    construction_plan_id: str = ""      # new: links to PayloadConstructionPlan

    def attach(self, candidate: dict[str, Any]) -> dict[str, Any]:
        """Merge the provenance fields into a candidate dict (mutating copy)."""
        updated = dict(candidate)
        updated.update({
            "candidate_id":        self.candidate_id,
            "strategy":            self.strategy,
            "required_trigger":    self.trigger,
            "generation_reason":   self.generation_reason,
            "parent_candidate":    self.parent_candidate,
            "constraints_digest":  self.constraints_digest,
            "generation_mode":     self.generation_mode,
        })
        return updated


# ---------------------------------------------------------------------------
# Model construction from existing pipeline evidence
# ---------------------------------------------------------------------------

def _flow_for(
    source: str,
    parameter: str,
    sink: str,
    attribute: str,
    transformations: list[TransformRecord] | None = None,
) -> tuple[list[FlowStep], list[FlowEdge]]:
    """Reconstruct the observed flow and edges from pipeline facts."""
    flow: list[FlowStep] = []
    edges: list[FlowEdge] = []

    if source:
        flow.append(FlowStep(
            kind="source",
            label=source,
            detail=(f"parameter {parameter!r}" if parameter else "attacker-controlled input"),
            evidence="source registry / crawl",
        ))

    if parameter:
        flow.append(FlowStep(
            kind="transformation",
            label=f"parameter extraction ({parameter})",
            detail="value read from the request",
            evidence="parameter binding",
        ))
        if len(flow) >= 2:
            edges.append(FlowEdge(
                from_index=len(flow) - 2,
                to_index=len(flow) - 1,
                label="parameter read",
            ))

    # Transformations from static analysis
    for t in (transformations or []):
        flow.append(FlowStep(
            kind="transformation",
            label=t.name,
            detail=t.detail,
            evidence=t.evidence,
        ))
        if len(flow) >= 2:
            edges.append(FlowEdge(
                from_index=len(flow) - 2,
                to_index=len(flow) - 1,
                label=t.name,
            ))

    if sink:
        flow.append(FlowStep(
            kind="sink",
            label=sink + (f" [{attribute}]" if attribute else ""),
            detail="tainted value written to the sink",
            evidence="sink registry match",
        ))
        if len(flow) >= 2:
            edges.append(FlowEdge(
                from_index=len(flow) - 2,
                to_index=len(flow) - 1,
                label="tainted assignment",
            ))

    return flow, edges


def _execution_context_for(sink_kind: str, attribute: str, context: str) -> str:
    """Classify the execution environment the payload must survive."""
    if sink_kind == "csti":
        return "template"
    if sink_kind in ("json_eval", "eval"):
        return "json_eval"
    if sink_kind == "url_attribute" or attribute in (
        "href", "src", "action", "formaction", "xlink:href", "data",
    ):
        return "url_valued_attribute"
    if sink_kind == "event_handler":
        return "event_handler"
    if sink_kind == "js_execution":
        if context in ("json_string", "json_value", "json_key"):
            return "json_eval"
        if context == "script_string_double":
            return "js_string_double"
        if context == "script_string_single":
            return "js_string_single"
        return "js_expression"
    if context.startswith("script_string"):
        return "js_string" if "string" in context else "js_expression"
    if context in ("json_string", "json_value", "json_key"):
        return "json_eval"
    if sink_kind in ("html_text", "selector", "selector_hashchange"):
        return "markup"
    if sink_kind == "html_attribute" or context.startswith("html_attribute"):
        return "attribute"
    return context or "unknown"


def _sink_context_for(
    context: str,
    sink_kind: str,
    before: str,
    after: str,
    quote_type: str,
) -> SinkContext:
    """Build a rich SinkContext from the pipeline evidence."""
    ctx_type = "UNKNOWN"
    parser = "html"
    delimiter = ""
    delimiter_state = "unquoted"
    requires_closure = False
    requires_rebalance = False

    # Map canonical context names to ExecutionContext enum-style names
    ctx_map = {
        "html_text":                "HTML_TEXT",
        "html_attribute":           "HTML_ATTRIBUTE",
        "html_attribute_unquoted":  "HTML_ATTRIBUTE_UNQUOTED",
        "html_comment":             "HTML_COMMENT",
        "script_string_double":     "JAVASCRIPT_STRING_DOUBLE",
        "script_string_single":     "JAVASCRIPT_STRING_SINGLE",
        "script_string_template":   "JAVASCRIPT_TEMPLATE",
        "script_expression":        "JAVASCRIPT_EXPRESSION",
        "json_value":               "JSON_STRING",
        "json_string":              "JSON_STRING",
        "json_key":                 "JSON_STRING",
        "url_param":                "URL_CONTEXT",
        "css_value":                "CSS_CONTEXT",
        "unknown":                  "UNKNOWN",
    }
    ctx_type = ctx_map.get(context, "UNKNOWN")

    # Parser from context (context takes priority over sink_kind)
    if context.startswith("json_") or sink_kind in ("json_eval",):
        parser = "json"
    elif context.startswith("script_") or sink_kind in ("js_execution", "eval"):
        parser = "javascript"
    elif context == "url_param":
        parser = "url"
    elif context == "css_value":
        parser = "css"
    else:
        parser = "html"

    # Delimiter from quote type
    qt_map = {"double": '"', "single": "'", "backtick": "`", "template": "`"}
    delimiter = qt_map.get(quote_type, "")
    if delimiter:
        delimiter_state = "open"
        requires_closure = True
        requires_rebalance = bool(after and not after.strip().startswith(("//", "/*")))

    # JSON object closure?
    nesting_depth = 0
    if context in ("json_value", "json_string", "json_key"):
        opens = before.count("{") + before.count("[")
        closes = before.count("}") + before.count("]")
        nesting_depth = max(0, opens - closes)

    return SinkContext(
        context_type=ctx_type,
        surrounding_syntax=(before[-40:] + "●" + after[:40]) if (before or after) else "",
        enclosing_construct=before[-80:],
        trailing_construct=after[:80],
        delimiter=delimiter,
        delimiter_state=delimiter_state,
        parser=parser,
        nesting_depth=nesting_depth,
        requires_closure=requires_closure,
        requires_rebalance=requires_rebalance,
    )


def build_model_from_candidate(
    candidate: dict[str, Any],
    candidate_id: str = "",
) -> VulnerabilityModel:
    """
    Build a VulnerabilityModel from the dicts the pipeline already produces.
    Only observed facts are recorded.
    """
    ca = dict(candidate.get("context_analysis") or {})
    ep = dict(candidate.get("encoding_profile") or {})

    sink_kind = str(
        candidate.get("sink_kind") or ep.get("sink_kind") or ""
    )
    attribute = str(
        candidate.get("sink_attribute") or ep.get("sink_attribute")
        or ca.get("attribute") or ca.get("attribute_name") or ""
    )
    context = str(ca.get("context") or ca.get("reflection_context") or "")
    sink_label = str(candidate.get("sink") or ep.get("sink") or sink_kind or "unknown sink")
    source_label = str(
        candidate.get("source") or ep.get("source") or ca.get("source") or ""
    )
    parameter = str(candidate.get("parameter") or candidate.get("param") or "")
    source_type = str(candidate.get("source_type") or ep.get("source_type") or "")
    if not source_label:
        source_label = {
            "hash": "location.hash",
            "query": "location.search",
            "href": "location.href",
            "form": "form input",
            "api": "request body",
        }.get(source_type, "request input")

    raw_chars = [str(c) for c in (ep.get("raw_chars") or [])]
    encoded = [str(c) for c in (ep.get("encoded_chars") or [])]
    stripped = [str(c) for c in (ep.get("stripped_chars") or [])]

    encoding_notes: list[str] = []
    if encoded:
        encoding_notes.append(f"server HTML-encodes: {' '.join(encoded)}")
    if stripped:
        encoding_notes.append(f"server strips: {' '.join(stripped)}")
    if raw_chars:
        encoding_notes.append(f"reflects raw: {' '.join(raw_chars)}")
    if not ep:
        encoding_notes.append(
            "no live encoding profile — synthesiser stays permissive, browser decides"
        )

    sanitization_notes: list[str] = []
    if ep.get("summary"):
        sanitization_notes.append(str(ep["summary"]))

    # Use full before/after snippets (not truncated to 24 chars)
    before = str(ca.get("before") or "")
    after = str(ca.get("after") or "")
    quote_type = str(ca.get("quote_type") or "")
    if not quote_type and context == "json_value":
        quote_type = "double"  # JSON string values are always double-quoted

    control = "confirmed" if raw_chars else (
        "suspected" if (encoded or stripped) else "unverified"
    )

    exec_ctx = _execution_context_for(sink_kind, attribute.lower(), context)

    constraints = AttackConstraints(
        source=source_label,
        source_parameter=parameter,
        sink=sink_label,
        sink_kind=sink_kind,
        attribute=attribute.lower(),
        execution_context=exec_ctx,
        quote_type=quote_type,
        raw_chars=raw_chars,
        encoded_chars=encoded,
        stripped_chars=stripped,
        # Use up to 120 chars so JSON object prefixes are captured
        enclosing_construct=before[-120:],
        trailing_construct=after[:120],
        javascript_execution_required=True,
        quote_breakout_required=(
            context.startswith("html_attribute")
            or context.startswith("script_string")
            or context in ("json_value", "json_string", "json_key")
        ),
        technologies=[str(t) for t in (ep.get("technologies") or [])],
        delivery=_delivery_for(source_type, candidate.get("method", "")),
        trigger=_trigger_for(sink_kind),
    )
    # Detect JSON object closure requirement from full context
    constraints.infer_json_eval_closure(before, after)

    # Build sink context detail
    sink_ctx_detail = _sink_context_for(context, sink_kind, before, after, quote_type)

    # Build flow with edges
    flow, edges = _flow_for(source_label, parameter, sink_label, attribute)

    return VulnerabilityModel(
        candidate_id=candidate_id or str(candidate.get("id") or ""),
        target_url=str(candidate.get("url") or ""),
        endpoint=str(candidate.get("url") or ""),
        source=source_label,
        source_parameter=parameter,
        flow=flow,
        flow_edges=edges,
        sink=sink_label,
        sink_argument=attribute,
        sink_context=context or sink_kind or "unknown",
        execution_context=exec_ctx,
        sink_context_detail=sink_ctx_detail,
        encoding_notes=encoding_notes,
        sanitization_notes=sanitization_notes,
        attacker_control=control,
        constraints=constraints,
    )


def model_from_execution_semantics(
    execution_semantics: dict[str, Any],
    parameter: str = "",
    url: str = "",
) -> VulnerabilityModel:
    """
    Build a model for a DOM candidate that carries no server-side reflection
    context (static source->sink analysis).
    """
    esem = dict(execution_semantics or {})
    sink_kind = str(esem.get("sink_kind") or "")
    capability = str(esem.get("sink_capability") or "")
    source_type = str(esem.get("source_type") or "")
    attribute = str(esem.get("sink_attribute") or "")

    source_label = {
        "hash": "location.hash",
        "query": "location.search",
        "href": "location.href",
    }.get(source_type, source_type or "browser input")

    sink_label = sink_kind or capability or "dom sink"
    exec_ctx = _execution_context_for(sink_kind, attribute, "")

    flow, edges = _flow_for(source_label, parameter, sink_label, attribute)

    return VulnerabilityModel(
        target_url=url,
        endpoint=url,
        source=source_label,
        source_parameter=parameter,
        flow=flow,
        flow_edges=edges,
        sink=sink_label,
        sink_argument=attribute,
        sink_context=sink_kind or capability or "dom",
        execution_context=exec_ctx,
        encoding_notes=[
            "client-side flow: the value never reaches the server, "
            "constraints come from static analysis and the browser decides"
        ],
        attacker_control="suspected",
        constraints=AttackConstraints(
            source=source_label,
            source_parameter=parameter,
            sink=sink_label,
            sink_kind=sink_kind,
            attribute=attribute.lower(),
            execution_context=exec_ctx,
            delivery=_delivery_for(source_type, ""),
            trigger=_trigger_for(sink_kind),
        ),
    )


def _delivery_for(source_type: str, method: str) -> str:
    """Infer delivery method from source type and HTTP method."""
    m = (method or "GET").upper()
    if source_type == "hash":
        return "fragment"
    if source_type == "query":
        return "query"
    if m == "POST":
        return "form_post"
    if source_type in ("api", "json"):
        return "api"
    return "query"


def _trigger_for(sink_kind: str) -> str:
    """Infer execution trigger from sink kind."""
    triggers = {
        "url_attribute":        "click",
        "navigation":           "navigate",
        "event_handler":        "event",
        "selector_hashchange":  "event",
        "csti":                 "load",
        "html_text":            "load",
        "js_execution":         "load",
        "json_eval":            "load",
    }
    return triggers.get(sink_kind, "load")
