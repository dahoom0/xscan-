"""
Experiment — a deliberate investigation step.

A payload is a parameter of an experiment, not the center of the architecture.

The agent asks:
  "What am I trying to prove?"
  "What experiment can distinguish between competing explanations?"
  "What observation should I expect?"

Experiments are stored in AgentState and never repeated (fingerprint dedup).
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, UTC
from enum import StrEnum
from typing import Any, Optional

from pydantic import BaseModel, Field


class ExperimentStatus(StrEnum):
    PENDING       = "pending"
    RUNNING       = "running"
    COMPLETED     = "completed"
    FAILED        = "failed"        # tool/network error
    SKIPPED       = "skipped"       # duplicate or budget exhausted
    POLICY_BLOCKED= "policy_blocked"


class ExperimentResult(BaseModel):
    """What actually happened when an experiment ran."""
    status:              ExperimentStatus = ExperimentStatus.PENDING
    actual_observation:  str = ""
    interpretation:      str = ""   # agent's interpretation of the result
    hypothesis_update:   str = ""   # how this changes the hypothesis
    evidence_ids:        list[str] = Field(default_factory=list)
    raw_output:          str = ""   # capped at 500 chars
    duration_ms:         float = 0.0
    error:               str = ""


class Experiment(BaseModel):
    """
    One deliberate investigation step: a tool call with a clear objective.

    An experiment is NOT just "try this payload" — it is a hypothesis-driven
    investigation step with a stated objective and expected observation.
    """
    id:             str = Field(default_factory=lambda: "EXP-" + uuid.uuid4().hex[:8])
    hypothesis_id:  str = ""
    iteration:      int = 0
    objective:      str = ""        # "Does location.hash flow into jQuery $()?
    tool:           str = ""        # tool name from HarnessToolRegistry
    arguments:      dict[str, Any] = Field(default_factory=dict)
    expected_observation: str = ""  # "onerror fires when hash contains <img>"

    result:         Optional[ExperimentResult] = None
    fingerprint:    str = ""        # dedup key
    created_at:     datetime = Field(default_factory=lambda: datetime.now(UTC))
    started_at:     Optional[datetime] = None
    finished_at:    Optional[datetime] = None

    # ------------------------------------------------------------------

    @classmethod
    def compute_fingerprint(
        cls,
        tool: str,
        arguments: dict[str, Any],
        hypothesis_id: str,
    ) -> str:
        """SHA-256 fingerprint for deduplication."""
        import json
        norm = f"{tool}|{json.dumps(arguments, sort_keys=True)}|{hypothesis_id}"
        return hashlib.sha256(norm.encode()).hexdigest()[:16]

    def start(self) -> None:
        self.started_at = datetime.now(UTC)
        if self.result:
            self.result.status = ExperimentStatus.RUNNING

    def complete(
        self,
        actual_observation: str,
        interpretation: str,
        evidence_ids: list[str],
        raw_output: str = "",
    ) -> None:
        self.finished_at = datetime.now(UTC)
        elapsed = (
            (self.finished_at - self.started_at).total_seconds() * 1000
            if self.started_at else 0.0
        )
        self.result = ExperimentResult(
            status=ExperimentStatus.COMPLETED,
            actual_observation=actual_observation[:300],
            interpretation=interpretation[:300],
            evidence_ids=evidence_ids,
            raw_output=raw_output[:500],
            duration_ms=elapsed,
        )

    def fail(self, error: str) -> None:
        self.finished_at = datetime.now(UTC)
        self.result = ExperimentResult(
            status=ExperimentStatus.FAILED,
            error=error[:200],
        )

    def block(self, reason: str) -> None:
        self.result = ExperimentResult(
            status=ExperimentStatus.POLICY_BLOCKED,
            error=reason[:200],
        )

    @property
    def is_complete(self) -> bool:
        return (
            self.result is not None
            and self.result.status != ExperimentStatus.RUNNING
            and self.result.status != ExperimentStatus.PENDING
        )

    def summary(self) -> str:
        lines = [f"Experiment {self.id}: [{self.tool}] {self.objective[:80]}"]
        if self.result:
            lines.append(f"  Status: {self.result.status}")
            if self.result.actual_observation:
                lines.append(f"  Observed: {self.result.actual_observation[:100]}")
            if self.result.interpretation:
                lines.append(f"  Interpretation: {self.result.interpretation[:100]}")
        return "\n".join(lines)
