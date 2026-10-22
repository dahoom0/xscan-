"""
Iterative XSS Test Planner Specialist — spec §13
=================================================
Generates the NEXT batch of candidates given:
  - target context
  - encoding/filter profile
  - available skills
  - previous test results (what worked/failed and why)
  - remaining budget

Rules:
  - Returns at most max_candidates_per_iteration candidates
  - Must not repeat fingerprinted candidates
  - Must not claim confirmation — that is the validator's job
  - Must not request more tests than the budget allows
  - All output is Pydantic-validated before entering the DAG
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from xscan.llm.specialists.base import SpecialistBase
from xscan.schemas.llm import SpecialistInput, SpecialistOutput
from xscan.schemas.iteration import PreviousTestResult

_SYSTEM = """\
You are an XSS test-planning specialist.

Your job is to generate the NEXT set of XSS test candidates based on:
1. What the previous test attempts observed
2. What hypotheses have been eliminated
3. What context constraints apply
4. What skills are available

You do NOT confirm findings. You generate candidates for the validator to test.
Respond ONLY with valid JSON.
Do not repeat candidates that have already been tested.
Do not generate more candidates than requested.

{ctf_hint}
"""

_PROMPT = """\
=== TARGET CONTEXT ===
URL: {url}
Parameter: {parameter}
Injection context: {context}
Tag/attribute: {tag} / {attribute}
Quote type: {quote_type}

=== SINK / FLOW EVIDENCE ===
Source: {source_label}
Sink: {sink_label}
Sink capability: {sink_capability}
Trigger: {trigger_event}
Enclosing construct around the reflection: {enclosing_construct}
Text after the reflection: {trailing_construct}
Observed reflection snippet: {reflection_snippet}

=== FILTER / ENCODING CONSTRAINTS ===
Raw (NOT encoded): {raw_chars}
Encoded by server: {encoded_chars}
Stripped by server: {stripped_chars}
Can break html_attribute: {can_break_attribute}
Can break script string:  {can_break_script}

=== HOW TO BUILD A PAYLOAD FOR THIS SINK ===
Derive each payload from the evidence above, never from a generic list:
- js_execution/eval sinks: the reflected value is spliced into JavaScript.
  If the value lands inside a JS string literal, close the quote first
  (e.g. ";alert(1)//). If it lands inside a JSON object literal that is later
  eval'd, close the string, keep the object parseable (arithmetic like
  -alert(1)), close the brace, then comment out the tail ("-alert(1)}};//).
  Bare markup (<script>, <img>) is INERT at an eval sink — never send it.
- selector/innerHTML sinks: value is parsed as HTML — use markup payloads.
- url sinks (href/src): only scheme payloads (javascript:alert(1)) execute.
- When the server encodes or strips a character, never use it again.

=== AVAILABLE SKILLS ===
{skills_summary}

=== PREVIOUS TEST RESULTS ({prev_count} attempts) ===
{previous_results_text}

=== FAILED HYPOTHESES ===
{failed_hypotheses}

=== REMAINING BUDGET ===
Max candidates this iteration: {max_candidates}
Total tested so far: {total_tested}
Max total allowed: {max_total}

=== INSTRUCTIONS ===
1. What did the previous tests establish?
2. What hypotheses remain viable?
3. Select the most appropriate skill for the remaining hypotheses.
4. Generate up to {max_candidates} new candidates, ranked by likelihood of success.
5. Each candidate must test a DIFFERENT hypothesis from already-tested ones.
6. Do not generate candidates requiring characters that are stripped or encoded.

Respond with JSON only:
{{
  "analysis": "what previous results established and what hypotheses remain",
  "eliminated_hypotheses": ["list of hypotheses ruled out by previous results"],
  "remaining_hypotheses": ["list of hypotheses still worth testing"],
  "selected_skill": "skill name used",
  "candidates": [
    {{
      "priority": 1,
      "payload": "exact payload string",
      "hypothesis": "what this tests",
      "expected_observation": "what should happen if this succeeds",
      "rationale": "why this given the constraints and previous results",
      "generation_mode": "skill_candidate | skill_template | llm_derived"
    }}
  ],
  "confidence": "high | medium | low",
  "stop_recommendation": false
}}
"""


class IterativePlanInput(SpecialistInput):
    url:          str
    parameter:    str
    context_analysis:  dict = Field(default_factory=dict)
    encoding_profile:  dict = Field(default_factory=dict)
    previous_results:  list[PreviousTestResult] = Field(default_factory=list)
    skills_text:       str  = ""
    max_candidates:    int  = 5
    total_tested:      int  = 0
    max_total:         int  = 20
    failed_hypotheses: list[str] = Field(default_factory=list)
    ctf_hint:          str  = ""  # CTF context hint (e.g., "This is a DVWA instance")


class IterativeCandidate(BaseModel):
    priority:             int
    payload:              str
    hypothesis:           str = ""
    expected_observation: str = ""
    rationale:            str = ""
    generation_mode:      str = "llm_derived"


class IterativePlanOutput(SpecialistOutput):
    analysis:              str = ""
    eliminated_hypotheses: list[str] = Field(default_factory=list)
    remaining_hypotheses:  list[str] = Field(default_factory=list)
    selected_skill:        str = ""
    candidates:            list[IterativeCandidate] = Field(default_factory=list)
    stop_recommendation:   bool = False

    specialist: str = "iterative-planner"


class IterativePlannerSpecialist(SpecialistBase[IterativePlanInput, IterativePlanOutput]):
    specialist_name = "iterative-planner"
    system_prompt   = _SYSTEM
    default_timeout = 90
    # Generous token budget — the response JSON contains analysis + candidates
    # and must not be truncated mid-object (truncation causes JSON parse failure)
    default_max_tokens = 2048

    def run(self, input_data: IterativePlanInput) -> IterativePlanOutput:
        """Override run() to inject CTF hint into system prompt before sending to LLM."""
        # Format system prompt with CTF hint (if any)
        ctf_hint = input_data.ctf_hint or ""
        formatted_system = self.system_prompt.format(ctf_hint=ctf_hint)
        
        # Temporarily replace system_prompt with formatted version
        original_system = self.system_prompt
        self.system_prompt = formatted_system
        
        # If CTF context detected, increase timeout and reduce token budget
        # to make LLM respond faster with aggressive strategy
        original_timeout = self.default_timeout
        original_max_tokens = self.default_max_tokens
        if ctf_hint:
            # CTF targets get more time but smaller token budget (forces concise response)
            self.default_timeout = 150  # increased from 90s
            self.default_max_tokens = 1500  # reduced from 2048 (still enough for JSON)
        
        try:
            return super().run(input_data)
        finally:
            # Restore originals for next calls
            self.system_prompt = original_system
            self.default_timeout = original_timeout
            self.default_max_tokens = original_max_tokens

    def build_prompt(self, data: IterativePlanInput) -> str:
        ca = data.context_analysis
        ep = data.encoding_profile

        # Format previous results
        prev_text = ""
        if data.previous_results:
            prev_text = "\n".join(r.to_planner_summary() for r in data.previous_results)
        else:
            prev_text = "No previous tests yet. This is the first iteration."

        # Skills summary (first 600 chars to keep prompt bounded)
        # If CTF context detected, trim to 300 chars to reduce LLM latency
        skills_limit = 300 if data.ctf_hint else 600
        skills_sum = data.skills_text[:skills_limit] if data.skills_text else "No skills loaded."

        # Enclosing/trailing constructs: the exact text around the reflection
        # is what a breakout has to close — give the model the real thing.
        def _snippet(obj: dict, key: str, limit: int = 120) -> str:
            val = str(obj.get(key, "") or "")
            return val[-limit:] if val else "(not observed)"

        ca_construct = _snippet(ca, "full_snippet")
        if ca_construct == "(not observed)":
            ca_construct = _snippet(ca, "before")
        
        # For CTF contexts, trim snippet size to reduce token overhead
        snippet_limit = 80 if data.ctf_hint else 120
        ca_construct = _snippet(ca, "full_snippet", limit=snippet_limit)
        if ca_construct == "(not observed)":
            ca_construct = _snippet(ca, "before", limit=snippet_limit)
        
        return _PROMPT.format(
            url=data.url,
            parameter=data.parameter,
            context=ca.get("context", "unknown"),
            tag=ca.get("tag", ""),
            attribute=ca.get("attribute", ""),
            quote_type=ca.get("quote_type", ""),
            source_label=ep.get("source_label", "") or "(unknown)",
            sink_label=ep.get("sink_label", "") or ep.get("sink", "") or "(unknown)",
            sink_capability=ep.get("sink_capability", "") or "(unknown)",
            trigger_event=ep.get("trigger_event", "") or "page load / navigation",
            enclosing_construct=ca_construct,
            trailing_construct=_snippet(ca, "after", limit=snippet_limit),
            reflection_snippet=_snippet(ep, "context_snippet", limit=snippet_limit) if ep.get("context_snippet") else ca_construct,
            raw_chars=ep.get("raw_chars", []),
            encoded_chars=ep.get("encoded_chars", []),
            stripped_chars=ep.get("stripped_chars", []),
            can_break_attribute=ep.get("can_break_html_attribute", False),
            can_break_script=ep.get("can_break_script_string", False),
            skills_summary=skills_sum,
            prev_count=len(data.previous_results),
            previous_results_text=prev_text,
            failed_hypotheses="\n".join(data.failed_hypotheses) or "None yet.",
            max_candidates=data.max_candidates,
            total_tested=data.total_tested,
            max_total=data.max_total,
        )

    def parse_output(self, raw_text: str) -> IterativePlanOutput:
        data = self._extract_json(raw_text)
        candidates = []
        for i, c in enumerate(data.get("candidates", [])[:10], 1):   # hard cap 10
            candidates.append(IterativeCandidate(
                priority=int(c.get("priority", i)),
                payload=c.get("payload", ""),
                hypothesis=c.get("hypothesis", ""),
                expected_observation=c.get("expected_observation", ""),
                rationale=c.get("rationale", ""),
                generation_mode=c.get("generation_mode", "llm_derived"),
            ))
        return IterativePlanOutput(
            scan_id="-",
            analysis=data.get("analysis", ""),
            eliminated_hypotheses=data.get("eliminated_hypotheses", []),
            remaining_hypotheses=data.get("remaining_hypotheses", []),
            selected_skill=data.get("selected_skill", ""),
            candidates=sorted(candidates, key=lambda x: x.priority),
            stop_recommendation=bool(data.get("stop_recommendation", False)),
            reasoning=data.get("analysis", ""),
            confidence=float({
                "high": 0.9, "medium": 0.6, "low": 0.3
            }.get(str(data.get("confidence", "medium")), 0.6)),
        )
