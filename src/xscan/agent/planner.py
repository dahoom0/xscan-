"""
AgentPlannerSpecialist — LLM specialist for agent decisions.
Subclasses SpecialistBase to reuse LLMGateway + output validation.

The LLM receives:
  - current investigation state (condensed)
  - active hypothesis
  - available tools + schemas
  - recent experiment results
  - remaining budget
  - skills

The LLM returns a structured AgentDecision (Pydantic-validated).
Invalid output raises AgentDecisionError — it does NOT execute.
"""
from __future__ import annotations

from typing import Any

from pydantic import Field

from xscan.llm.specialists.base import SpecialistBase
from xscan.schemas.llm import SpecialistInput, SpecialistOutput
from xscan.agent.decisions import AgentDecision, AgentDecisionError, DecisionType

_SYSTEM = """\
You are an XSS investigation specialist agent.

Your job is to investigate a specific XSS candidate by selecting and executing
tools, forming hypotheses, and updating your reasoning based on observations.

You do NOT confirm vulnerabilities — the validator does that.
You do NOT execute commands — the harness does that.
You propose structured actions that the harness will validate and execute.

Respond ONLY with valid JSON matching the AgentDecision schema.
"""

_PROMPT = """\
=== INVESTIGATION STATE ===
{investigation_summary}

=== ACTIVE HYPOTHESIS ===
{hypothesis_summary}

=== AVAILABLE TOOLS ===
{tools_summary}

=== RECENT EXPERIMENTS ===
{recent_experiments}

=== SKILLS (relevant knowledge) ===
{skills_text}

=== BUDGET REMAINING ===
{budget_info}

=== TASK ===
Based on the current state and hypothesis, decide the next action.

Ask yourself:
1. What information is still missing?
2. What experiment would best distinguish between competing explanations?
3. Which tool provides that information while staying in scope?
4. What observation would confirm or reject the hypothesis?

Respond with JSON only:
{{
  "decision_type": "tool_call" | "continue_reasoning" | "final" | "ask_approval" | "abandon",
  "reasoning": "your reasoning about the current state and next step",
  "tool_call": {{
    "tool": "tool name from the available tools list",
    "arguments": {{}},
    "reason": "why this tool",
    "expected_observation": "what should happen",
    "hypothesis_id": "{hypothesis_id}"
  }},
  "final": {{
    "status": "confirmed" | "rejected" | "inconclusive",
    "confidence": 0.0,
    "reason": "explanation",
    "evidence_ids": [],
    "summary": "what was found"
  }},
  "approval_reason": "",
  "abandon_reason": ""
}}

Only populate the sub-object matching your decision_type.
Do not claim confirmation — only the validator can confirm.
Do not request tools not in the available tools list.
"""


class AgentPlannerInput(SpecialistInput):
    investigation_summary: str = ""
    hypothesis_summary:    str = ""
    tools_summary:         str = ""
    recent_experiments:    str = ""
    skills_text:           str = ""
    budget_info:           str = ""
    hypothesis_id:         str = ""


class AgentPlannerOutput(SpecialistOutput):
    """Raw output — parsed into AgentDecision by parse_output."""
    decision: dict[str, Any] = Field(default_factory=dict)
    specialist: str = "agent-planner"


class AgentPlannerSpecialist(SpecialistBase[AgentPlannerInput, AgentPlannerOutput]):
    specialist_name = "agent-planner"
    system_prompt   = _SYSTEM
    default_timeout = 90

    def build_prompt(self, data: AgentPlannerInput) -> str:
        return _PROMPT.format(
            investigation_summary=data.investigation_summary[:800],
            hypothesis_summary=data.hypothesis_summary[:400],
            tools_summary=data.tools_summary[:600],
            recent_experiments=data.recent_experiments[:500],
            skills_text=data.skills_text[:400],
            budget_info=data.budget_info[:200],
            hypothesis_id=data.hypothesis_id,
        )

    def parse_output(self, raw_text: str) -> AgentPlannerOutput:
        data = self._extract_json(raw_text)
        return AgentPlannerOutput(
            scan_id="-",
            decision=data,
            reasoning=data.get("reasoning", ""),
        )

    def decide(self, state_data: AgentPlannerInput) -> AgentDecision:
        """
        Run the specialist and return a validated AgentDecision.
        Raises AgentDecisionError if the LLM output is invalid.
        """
        output = self.run(state_data)
        return AgentDecision.from_llm_dict(output.decision)
