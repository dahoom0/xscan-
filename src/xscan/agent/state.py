"""
AgentState — complete persistent state of an investigation.

The agent loop reads from and writes to this state each iteration.
The LLM never modifies state directly — it proposes decisions,
the loop validates them and updates state.

Reuses IterationBudget from schemas.iteration for budget tracking.
"""
from __future__ import annotations

import uuid
from datetime import datetime, UTC
from enum import StrEnum
from typing import Any, Optional

from pydantic import BaseModel, Field

from xscan.schemas.iteration import IterationBudget, IterationStatus
from xscan.agent.hypothesis import Hypothesis
from xscan.agent.experiment import Experiment


class AgentStatus(StrEnum):
    """Maps to IterationStatus but adds agent-specific states."""
    RUNNING               = "running"
    CONFIRMED             = "confirmed"
    REJECTED              = "rejected"
    INCONCLUSIVE          = "inconclusive"
    BUDGET_EXHAUSTED      = "budget_exhausted"
    ERROR                 = "error"
    APPROVAL_REQUIRED     = "approval_required"

    @property
    def is_terminal(self) -> bool:
        return self in (
            AgentStatus.CONFIRMED, AgentStatus.REJECTED,
            AgentStatus.INCONCLUSIVE, AgentStatus.BUDGET_EXHAUSTED,
            AgentStatus.ERROR,
        )

    @property
    def implies_safe(self) -> bool:
        return False   # no terminal state means 'safe'


class AgentBudget(BaseModel):
    """
    Agent-level budget — extends IterationBudget with agent-specific limits.
    All values are enforced by the harness, not the LLM.
    """
    max_iterations:       int   = 10
    max_experiments:      int   = 20
    max_requests:         int   = 50
    max_browser_actions:  int   = 0   # 0 = browser not available yet (Phase 10)
    max_runtime_s:        float = 300.0
    max_tool_failures:    int   = 5
    stop_on_confirmation: bool  = True

    def can_continue(
        self,
        iteration: int,
        experiments_run: int,
        requests_made: int,
        tool_failures: int,
        elapsed_s: float,
    ) -> tuple[bool, str]:
        if iteration >= self.max_iterations:
            return False, f"max_iterations={self.max_iterations}"
        if experiments_run >= self.max_experiments:
            return False, f"max_experiments={self.max_experiments}"
        if requests_made >= self.max_requests:
            return False, f"max_requests={self.max_requests}"
        if tool_failures >= self.max_tool_failures:
            return False, f"max_tool_failures={self.max_tool_failures}"
        if elapsed_s >= self.max_runtime_s:
            return False, f"max_runtime_s={self.max_runtime_s}"
        return True, ""


class AgentState(BaseModel):
    """
    Complete state of one agent investigation run.

    Threaded through the agent loop. Never modified by the LLM directly.
    """
    investigation_id: str = Field(default_factory=lambda: "INV-" + uuid.uuid4().hex[:8])
    scan_id:          str = ""
    candidate_id:     str = ""

    # Target information
    target_url:  str = ""
    parameter:   str = ""

    # Status
    status:   AgentStatus = AgentStatus.RUNNING
    iteration: int = 0

    # Hypothesis tracking
    hypotheses:         list[Hypothesis] = Field(default_factory=list)
    active_hypothesis:  Optional[str] = None   # ID of current hypothesis

    # Experiment tracking
    experiments:         list[Experiment] = Field(default_factory=list)
    experiment_fingerprints: set[str]     = Field(default_factory=set)

    # Counters (enforced by harness)
    requests_made:   int   = 0
    tool_failures:   int   = 0
    elapsed_s:       float = 0.0

    # Evidence collected
    evidence_ids:    list[str] = Field(default_factory=list)

    # Terminal result
    confirmed_payload: Optional[str] = None
    final_evidence:    list[str]     = Field(default_factory=list)

    # Application model (what we've learned about the target)
    application_model: dict[str, Any] = Field(default_factory=dict)

    # Budget
    budget: AgentBudget = Field(default_factory=AgentBudget)

    # Observability log — every decision + result, for user inspection
    decision_log: list[dict[str, Any]] = Field(default_factory=list)

    model_config = {"arbitrary_types_allowed": True}

    # ------------------------------------------------------------------
    # Hypothesis management
    # ------------------------------------------------------------------

    def add_hypothesis(self, h: Hypothesis) -> None:
        self.hypotheses.append(h)
        if not self.active_hypothesis:
            self.active_hypothesis = h.id

    def get_active_hypothesis(self) -> Optional[Hypothesis]:
        if not self.active_hypothesis:
            return None
        return next((h for h in self.hypotheses if h.id == self.active_hypothesis), None)

    def get_hypothesis(self, hyp_id: str) -> Optional[Hypothesis]:
        return next((h for h in self.hypotheses if h.id == hyp_id), None)

    # ------------------------------------------------------------------
    # Experiment management
    # ------------------------------------------------------------------

    def is_duplicate_experiment(self, fingerprint: str) -> bool:
        return fingerprint in self.experiment_fingerprints

    def record_experiment(self, exp: Experiment) -> None:
        self.experiments.append(exp)
        if exp.fingerprint:
            self.experiment_fingerprints.add(exp.fingerprint)
        if exp.result and exp.result.status.value == "failed":
            self.tool_failures += 1
        self.requests_made += 1

    # ------------------------------------------------------------------
    # Budget
    # ------------------------------------------------------------------

    def can_continue(self) -> tuple[bool, str]:
        return self.budget.can_continue(
            iteration=self.iteration,
            experiments_run=len(self.experiments),
            requests_made=self.requests_made,
            tool_failures=self.tool_failures,
            elapsed_s=self.elapsed_s,
        )

    # ------------------------------------------------------------------
    # Terminal transitions
    # ------------------------------------------------------------------

    def confirm(self, payload: str, evidence_ids: list[str]) -> None:
        self.status            = AgentStatus.CONFIRMED
        self.confirmed_payload = payload
        self.final_evidence    = evidence_ids

    def reject(self, reason: str = "") -> None:
        self.status = AgentStatus.REJECTED
        self._log_decision("reject", {"reason": reason})

    def exhaust(self, reason: str = "") -> None:
        self.status = AgentStatus.BUDGET_EXHAUSTED
        self._log_decision("budget_exhausted", {"reason": reason})

    def mark_inconclusive(self) -> None:
        self.status = AgentStatus.INCONCLUSIVE

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------

    def log_decision(
        self,
        iteration: int,
        decision_type: str,
        tool: str,
        tool_args: dict,
        policy_allowed: bool,
        observation_summary: str,
        hypothesis_update: str,
    ) -> None:
        self.decision_log.append({
            "iteration":          iteration,
            "decision_type":      decision_type,
            "tool":               tool,
            "tool_args_summary":  {k: str(v)[:50] for k, v in tool_args.items()},
            "policy_allowed":     policy_allowed,
            "observation":        observation_summary[:200],
            "hypothesis_update":  hypothesis_update[:200],
        })

    def _log_decision(self, kind: str, data: dict) -> None:
        self.decision_log.append({"kind": kind, **data})

    # ------------------------------------------------------------------
    # Summary for context building
    # ------------------------------------------------------------------

    def investigation_summary(self) -> str:
        hyp = self.get_active_hypothesis()
        lines = [
            f"Investigation: {self.investigation_id}",
            f"  Status:      {self.status}",
            f"  Iteration:   {self.iteration}",
            f"  Experiments: {len(self.experiments)}",
            f"  Requests:    {self.requests_made}",
        ]
        if hyp:
            lines.append(f"\nActive hypothesis:\n{hyp.summary()}")
        recent = self.experiments[-3:]
        if recent:
            lines.append("\nRecent experiments:")
            for e in recent:
                lines.append(f"  {e.summary()}")
        return "\n".join(lines)
