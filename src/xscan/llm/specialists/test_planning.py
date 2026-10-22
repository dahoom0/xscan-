"""
XSS Test Planning Specialist
=============================
The LLM receives structured evidence (context + encoding) and returns
a structured test plan — NOT a finding declaration.

The LLM's job:
  - Reason about what the context means
  - Determine what breakout strategy is viable given the encoding
  - Produce 1–5 bounded test cases in priority order
  - Explain what observation would confirm exploitability

The validator executes the test cases and returns observations.
The LLM never confirms a finding — evidence does.
"""
from __future__ import annotations

from pydantic import BaseModel, Field
from typing import Literal

from xscan.llm.specialists.base import SpecialistBase
from xscan.schemas.llm import SpecialistInput, SpecialistOutput

_SYSTEM = """\
You are an XSS test-planning specialist. Your role is to analyse injection evidence
and produce a structured test plan. You do NOT declare vulnerabilities.
You produce test cases. The validator determines whether they succeed.
Respond ONLY with valid JSON.
"""

_PROMPT = """\
Injection Evidence:

URL: {url}
Parameter: {parameter}
Method: {method}

Reflection Context Analysis:
  context:        {context}
  reflected:      {reflected}
  raw_present:    {raw_present}
  tag:            {tag}
  attribute:      {attribute}
  quote_type:     {quote_type}
  script_quote:   {script_quote}
  breakout_chars: {breakout_chars}
  before:         {before}
  after:          {after}

Encoding Profile:
  raw (not encoded):  {raw_chars}
  encoded:            {encoded_chars}
  stripped:           {stripped_chars}
  can_break_html_text:      {can_break_html_text}
  can_break_html_attribute: {can_break_html_attribute}
  can_break_script_string:  {can_break_script_string}

{skill_context}

Based on this evidence, create a structured test plan:

{{
  "viable": true | false,
  "reasoning": "explain the context and why it is or isn't viable",
  "context_interpretation": "what does the reflection context mean for exploitation?",
  "encoding_interpretation": "what does the encoding profile allow or prevent?",
  "breakout_strategy": "describe the breakout approach",
  "test_cases": [
    {{
      "priority": 1,
      "payload": "exact payload string",
      "expected_observation": "what should appear in the response or DOM if successful",
      "rationale": "why this payload for this context"
    }}
  ],
  "max_attempts": 3,
  "estimated_confidence": "high | medium | low"
}}

Rules:
- test_cases must be ordered by likelihood of success
- payloads must be specific to the context (not generic lists)
- If context is html_attribute with quote_type double, payloads must break out of "..."
- If < and > are encoded, do not suggest payloads that require them in the outer context
- Maximum 5 test cases
- Do not declare a finding — return only the test plan
"""


class TestCase(BaseModel):
    priority:             int
    payload:              str
    expected_observation: str
    rationale:            str


class TestPlanInput(SpecialistInput):
    url:              str
    parameter:        str
    method:           str = "GET"
    context_analysis: dict = Field(default_factory=dict)
    encoding_profile: dict = Field(default_factory=dict)
    skill_context:    str  = ""


class TestPlanOutput(SpecialistOutput):
    viable:                   bool          = False
    context_interpretation:   str           = ""
    encoding_interpretation:  str           = ""
    breakout_strategy:        str           = ""
    test_cases:               list[TestCase] = Field(default_factory=list)
    max_attempts:             int           = 3
    estimated_confidence:     str           = "low"

    specialist: str = "test-planning"


class TestPlanningSpecialist(SpecialistBase[TestPlanInput, TestPlanOutput]):
    specialist_name = "test-planning"
    system_prompt   = _SYSTEM
    default_timeout = 120

    def build_prompt(self, input_data: TestPlanInput) -> str:
        ca = input_data.context_analysis
        ep = input_data.encoding_profile
        skill_section = input_data.skill_context or ""

        return _PROMPT.format(
            url=input_data.url,
            parameter=input_data.parameter,
            method=input_data.method,
            context=ca.get("context", "unknown"),
            reflected=ca.get("reflected", False),
            raw_present=ca.get("raw_present", False),
            tag=ca.get("tag", ""),
            attribute=ca.get("attribute", ""),
            quote_type=ca.get("quote_type", ""),
            script_quote=ca.get("script_quote", ""),
            breakout_chars=ca.get("breakout_chars", []),
            before=ca.get("before", "")[-80:],
            after=ca.get("after", "")[:80],
            raw_chars=ep.get("raw_chars", []),
            encoded_chars=ep.get("encoded_chars", []),
            stripped_chars=ep.get("stripped_chars", []),
            can_break_html_text=ep.get("can_break_html_text", False),
            can_break_html_attribute=ep.get("can_break_html_attribute", False),
            can_break_script_string=ep.get("can_break_script_string", False),
            skill_context=skill_section,
        )

    def parse_output(self, raw_text: str) -> TestPlanOutput:
        data = self._extract_json(raw_text)
        test_cases = []
        for tc in data.get("test_cases", []):
            test_cases.append(TestCase(
                priority=int(tc.get("priority", 1)),
                payload=tc.get("payload", ""),
                expected_observation=tc.get("expected_observation", ""),
                rationale=tc.get("rationale", ""),
            ))
        return TestPlanOutput(
            scan_id="-",
            viable=bool(data.get("viable", False)),
            reasoning=data.get("reasoning", ""),
            context_interpretation=data.get("context_interpretation", ""),
            encoding_interpretation=data.get("encoding_interpretation", ""),
            breakout_strategy=data.get("breakout_strategy", ""),
            test_cases=sorted(test_cases, key=lambda x: x.priority),
            max_attempts=int(data.get("max_attempts", 3)),
            estimated_confidence=data.get("estimated_confidence", "low"),
        )
