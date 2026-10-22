"""
Agent Decisions — Strict Pydantic schemas for LLM output.

Rules:
  - Every LLM output is validated against these schemas before execution.
  - Invalid output raises AgentDecisionError — it does NOT execute.
  - The LLM cannot request operations outside the defined DecisionType set.
  - ToolCall.arguments is a dict — never a raw shell command string.
"""
from __future__ import annotations

import uuid
from enum import StrEnum
from typing import Any, Optional

from pydantic import BaseModel, Field, model_validator


class DecisionType(StrEnum):
    TOOL_CALL         = "tool_call"         # request to execute a tool
    CONTINUE_REASONING= "continue_reasoning"# need more information before acting
    FINAL             = "final"             # investigation complete
    ASK_APPROVAL      = "ask_approval"      # requires human approval
    ABANDON           = "abandon"           # candidate not exploitable


class AgentDecisionError(ValueError):
    """Raised when the LLM produces output that fails schema validation."""


# ---------------------------------------------------------------------------
# Tool call
# ---------------------------------------------------------------------------

class ToolCall(BaseModel):
    """
    A request to execute one tool.
    Arguments are a typed dict — never a shell command string.
    """
    tool:                 str
    arguments:            dict[str, Any] = Field(default_factory=dict)
    reason:               str = ""   # why this tool was chosen
    expected_observation: str = ""   # what should happen if successful
    hypothesis_id:        str = ""   # which hypothesis this tests


# ---------------------------------------------------------------------------
# Final decision
# ---------------------------------------------------------------------------

class FinalDecision(BaseModel):
    status:       str                  # confirmed | rejected | inconclusive
    confidence:   float = 0.0         # 0.0 – 1.0
    reason:       str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    summary:      str = ""


# ---------------------------------------------------------------------------
# Root decision model
# ---------------------------------------------------------------------------

class AgentDecision(BaseModel):
    """
    Structured decision produced by the LLM each iteration.

    All fields beyond `decision_type` are optional — only the relevant
    sub-model for the decision type needs to be populated.

    Validated before any execution occurs.
    """
    decision_type:   DecisionType
    reasoning:       str = ""           # LLM's reasoning — logged, not executed
    tool_call:       Optional[ToolCall] = None
    final:           Optional[FinalDecision] = None
    approval_reason: str = ""           # for ASK_APPROVAL
    abandon_reason:  str = ""           # for ABANDON

    @model_validator(mode="after")
    def _check_consistency(self) -> "AgentDecision":
        if self.decision_type == DecisionType.TOOL_CALL and not self.tool_call:
            raise AgentDecisionError(
                "decision_type=tool_call requires tool_call to be populated"
            )
        if self.decision_type == DecisionType.FINAL and not self.final:
            raise AgentDecisionError(
                "decision_type=final requires final to be populated"
            )
        if self.decision_type == DecisionType.ASK_APPROVAL and not self.approval_reason:
            raise AgentDecisionError(
                "decision_type=ask_approval requires approval_reason"
            )
        return self

    @classmethod
    def from_llm_dict(cls, data: dict[str, Any]) -> "AgentDecision":
        """
        Parse and validate an LLM response dict.
        Raises AgentDecisionError on any validation failure.
        """
        try:
            return cls(**data)
        except Exception as exc:
            raise AgentDecisionError(
                f"LLM decision failed validation: {exc}  raw={data}"
            ) from exc
