"""
IntentSpecialist — parses natural-language scan intent for `xscan smart`.

Output is a structured plan — NOT a list of shell commands.
The plan is then validated against available workflows before execution.
"""
from __future__ import annotations
from pydantic import Field
from xscan.llm.specialists.base import SpecialistBase
from xscan.schemas.llm import SpecialistInput, SpecialistOutput

_SYSTEM = """\
You are an XScan intent parser. Convert the user's security testing intent
into a structured execution plan. Respond ONLY with valid JSON.
Never include shell commands in your output.
"""

_PROMPT = """\
User intent: {intent}

Available workflows: {workflows}

Parse the intent and respond with JSON only:
{{
  "objective": "brief description of what the user wants",
  "target": "extracted target URL or domain if mentioned",
  "recommended_workflow": "most appropriate workflow name from the list",
  "profile": "fast" | "balanced" | "deep",
  "capabilities_needed": ["list", "of", "needed", "capabilities"],
  "constraints": ["any", "explicit", "constraints", "mentioned"],
  "confidence": "high" | "medium" | "low",
  "reasoning": "why you chose this workflow"
}}
"""


class IntentInput(SpecialistInput):
    intent: str
    available_workflows: list[str] = Field(default_factory=list)


class IntentOutput(SpecialistOutput):
    objective: str = ""
    target: str = ""
    recommended_workflow: str = ""
    profile: str = "balanced"
    capabilities_needed: list[str] = Field(default_factory=list)
    constraints: list[str] = Field(default_factory=list)
    specialist: str = "intent"


class IntentSpecialist(SpecialistBase[IntentInput, IntentOutput]):
    specialist_name = "intent"
    system_prompt = _SYSTEM
    default_timeout = 60

    def build_prompt(self, input_data: IntentInput) -> str:
        return _PROMPT.format(
            intent=input_data.intent,
            workflows=", ".join(input_data.available_workflows) or "xss-balanced",
        )

    def parse_output(self, raw_text: str) -> IntentOutput:
        data = self._extract_json(raw_text)
        return IntentOutput(
            scan_id="-",
            objective=data.get("objective", ""),
            target=data.get("target", ""),
            recommended_workflow=data.get("recommended_workflow", "xss-balanced"),
            profile=data.get("profile", "balanced"),
            capabilities_needed=data.get("capabilities_needed", []),
            constraints=data.get("constraints", []),
            reasoning=data.get("reasoning", ""),
            confidence=float({"high": 0.9, "medium": 0.6, "low": 0.3}.get(
                data.get("confidence", "medium"), 0.6
            )),
        )
