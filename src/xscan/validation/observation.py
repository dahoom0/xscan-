"""
Observation
===========
Structured result from executing one test case.
This is what the LLM re-planner receives — never just "payload failed".
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Observation:
    """
    What actually happened when a test case was executed.
    Feeds back into the LLM test planner on re-plan cycles.
    """
    attempt:          int
    payload:          str
    url_sent:         str
    http_status:      int   = 0

    # Reflection analysis of the response
    payload_reflected:  bool  = False   # raw payload appears in response
    payload_encoded:    bool  = False   # encoded version appears
    payload_stripped:   bool  = False   # neither appears
    response_changed:   bool  = False   # response differs from baseline

    # Context of reflection in this response
    reflection_context: str   = ""      # html_text / html_attribute / script_string / etc.
    reflection_snippet: str   = ""      # the surrounding text

    # Execution evidence (browser, future)
    dom_changed:        bool  = False
    browser_event:      Optional[str] = None   # "alert_fired" | "error" | None
    console_output:     str   = ""

    # Meta
    error:              str   = ""
    duration_ms:        float = 0.0

    def to_dict(self) -> dict:
        return {
            "attempt":            self.attempt,
            "payload":            self.payload,
            "http_status":        self.http_status,
            "payload_reflected":  self.payload_reflected,
            "payload_encoded":    self.payload_encoded,
            "payload_stripped":   self.payload_stripped,
            "response_changed":   self.response_changed,
            "reflection_context": self.reflection_context,
            "reflection_snippet": self.reflection_snippet[:120],
            "dom_changed":        self.dom_changed,
            "browser_event":      self.browser_event,
            "error":              self.error,
        }

    @property
    def confirmed(self) -> bool:
        """True only if deterministic browser evidence proves execution."""
        return self.browser_event == "alert_fired" or self.dom_changed

    @property
    def promising(self) -> bool:
        """True if the payload reflected unencoded — worth re-planning."""
        return self.payload_reflected and not self.payload_encoded
