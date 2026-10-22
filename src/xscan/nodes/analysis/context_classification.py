"""
Structured Context Classification
==================================
Enhanced classification of execution contexts with typed enums and confidence scores.

Replaces unstructured string classifications with structured types that drive
payload synthesis and test strategy selection.
"""
from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class ExecutionContextType(str, Enum):
    """
    Execution context: how the browser interprets the reflected output.
    
    Each type has specific breakout requirements, dangerous operations,
    and recommended test strategies.
    """
    HTML_TEXT = "HTML_TEXT"
    HTML_ATTRIBUTE = "HTML_ATTRIBUTE"
    HTML_ATTRIBUTE_UNQUOTED = "HTML_ATTRIBUTE_UNQUOTED"
    HTML_COMMENT = "HTML_COMMENT"
    JAVASCRIPT_STRING_DOUBLE = "JAVASCRIPT_STRING_DOUBLE"
    JAVASCRIPT_STRING_SINGLE = "JAVASCRIPT_STRING_SINGLE"
    JAVASCRIPT_TEMPLATE = "JAVASCRIPT_TEMPLATE"
    JAVASCRIPT_EXPRESSION = "JAVASCRIPT_EXPRESSION"
    JSON_STRING = "JSON_STRING"
    URL_VALUED_ATTRIBUTE = "URL_VALUED_ATTRIBUTE"
    CSS_CONTEXT = "CSS_CONTEXT"
    UNKNOWN = "UNKNOWN"


class ParserType(str, Enum):
    """Parser that will process the output."""
    HTML = "html"
    JAVASCRIPT = "javascript"
    JSON = "json"
    URL = "url"
    CSS = "css"
    UNKNOWN = "unknown"


class DelimiterState(str, Enum):
    """State of the active string delimiter."""
    OPEN = "open"
    CLOSED = "closed"
    UNQUOTED = "unquoted"


class ContextClassification(BaseModel):
    """
    Structured classification of how reflection reaches a sink.
    
    This replaces free-form reasoning with typed, machine-readable context
    that drives payload synthesis and validation strategy selection.
    """
    
    # Core classification
    context_type: ExecutionContextType = ExecutionContextType.UNKNOWN
    confidence: float = 0.0  # 0.0-1.0 confidence in this classification
    
    # Parser and syntax details
    parser: ParserType = ParserType.HTML
    delimiter: str = ""  # " ' ` or "" (empty string for unquoted)
    delimiter_state: DelimiterState = DelimiterState.UNQUOTED
    
    # Surrounding context (for understanding the breakout)
    surrounding_syntax: str = ""  # Before + marker + after (e.g., 'value="●"')
    enclosing_construct: str = ""  # Full construct around the marker (last 80 chars before)
    trailing_construct: str = ""   # What comes after the marker (first 80 chars after)
    
    # Nesting information
    nesting_depth: int = 0  # How deeply nested in braces/brackets (for JSON)
    
    # Breakout requirements
    requires_breakout: bool = False  # True if we need to escape something
    breakout_chars: list[str] = Field(default_factory=list)  # Chars needed to escape
    escape_sequences: list[str] = Field(default_factory=list)  # Alternative escapes
    
    # Closure requirements
    requires_quote_closure: bool = False
    requires_brace_closure: bool = False
    requires_comment_tail: bool = False  # Whether // or /* needed to neutralize tail
    
    # Evidence and reasoning
    evidence: str = ""  # Why this classification was chosen
    alternative_contexts: list[ExecutionContextType] = Field(default_factory=list)  # Other possibilities
    
    # HTML-specific
    tag_name: str = ""
    attribute_name: str = ""
    
    # Transformation hints
    observed_transformations: list[str] = Field(default_factory=list)
    observed_filtering: list[str] = Field(default_factory=list)
    
    def summary(self) -> str:
        """Human-readable summary of the classification."""
        lines = [
            f"Context: {self.context_type.value} (confidence: {self.confidence:.0%})",
            f"Parser: {self.parser.value}",
        ]
        
        if self.delimiter:
            lines.append(f"Delimiter: {self.delimiter!r} ({self.delimiter_state.value})")
        
        if self.tag_name:
            lines.append(f"Tag: <{self.tag_name}>")
        if self.attribute_name:
            lines.append(f"Attribute: {self.attribute_name}")
        
        if self.requires_breakout:
            chars = ", ".join(self.breakout_chars[:5])
            lines.append(f"Breakout needed: {chars}")
        
        if self.evidence:
            lines.append(f"Evidence: {self.evidence[:100]}")
        
        return "\n".join(lines)
    
    def is_confident(self, threshold: float = 0.7) -> bool:
        """Whether confidence meets threshold."""
        return self.confidence >= threshold
    
    def is_viable_for_xss(self) -> bool:
        """Whether this context could potentially lead to XSS."""
        # Contexts that can definitely reach execution
        executable = {
            ExecutionContextType.HTML_TEXT,
            ExecutionContextType.HTML_ATTRIBUTE,
            ExecutionContextType.JAVASCRIPT_STRING_DOUBLE,
            ExecutionContextType.JAVASCRIPT_STRING_SINGLE,
            ExecutionContextType.JAVASCRIPT_TEMPLATE,
            ExecutionContextType.JAVASCRIPT_EXPRESSION,
            ExecutionContextType.JSON_STRING,
            ExecutionContextType.URL_VALUED_ATTRIBUTE,
        }
        return self.context_type in executable
    
    def strategy_recommendation(self) -> str:
        """Suggest a validation strategy for this context."""
        strategies = {
            ExecutionContextType.HTML_TEXT: "tag_injection",
            ExecutionContextType.HTML_ATTRIBUTE: "attribute_breakout",
            ExecutionContextType.HTML_ATTRIBUTE_UNQUOTED: "attribute_unquoted",
            ExecutionContextType.JAVASCRIPT_STRING_DOUBLE: "js_string_breakout",
            ExecutionContextType.JAVASCRIPT_STRING_SINGLE: "js_string_breakout",
            ExecutionContextType.JAVASCRIPT_TEMPLATE: "js_template",
            ExecutionContextType.JAVASCRIPT_EXPRESSION: "js_expression",
            ExecutionContextType.JSON_STRING: "json_eval",
            ExecutionContextType.URL_VALUED_ATTRIBUTE: "javascript_uri",
            ExecutionContextType.CSS_CONTEXT: "css_breakout",
            ExecutionContextType.UNKNOWN: "fallback_multi_strategy",
        }
        return strategies.get(self.context_type, "unknown")


class ClassificationResult(BaseModel):
    """
    Result of context classification: primary + alternatives.
    """
    primary: ContextClassification
    alternatives: list[ContextClassification] = Field(default_factory=list)
    position_in_response: int = 0  # Char offset where marker was found
    marker_length: int = 0
    
    def best_viable_for_xss(self) -> ContextClassification | None:
        """Pick the best context that could lead to XSS."""
        candidates = [c for c in [self.primary] + self.alternatives if c.is_viable_for_xss()]
        if not candidates:
            return None
        # Sort by confidence, pick highest
        return max(candidates, key=lambda c: c.confidence)
