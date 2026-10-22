"""
Hypothesis — the agent reasons in terms of hypotheses, not payloads.

A hypothesis represents a testable claim about the target:
  "The location.hash value flows unencoded into jQuery $() via the hashchange handler."

The agent's job is to:
  1. Form a hypothesis from the initial candidate
  2. Design experiments that can confirm or reject it
  3. Update confidence based on observations
  4. Split into sub-hypotheses when evidence is ambiguous
  5. Abandon when contradicted by deterministic evidence

Hypotheses live inside AgentState — the LLM cannot modify them directly.
"""
from __future__ import annotations

import uuid
from datetime import datetime, UTC
from enum import StrEnum
from typing import Optional

from pydantic import BaseModel, Field


class HypothesisStatus(StrEnum):
    ACTIVE        = "active"
    SUPPORTED     = "supported"     # evidence increases confidence
    CONTRADICTED  = "contradicted"  # evidence reduces confidence
    CONFIRMED     = "confirmed"     # deterministic evidence proves it
    REJECTED      = "rejected"      # deterministic evidence disproves it
    ABANDONED     = "abandoned"     # budget exhausted / not worth pursuing


class Hypothesis(BaseModel):
    """
    One testable claim about a candidate vulnerability.

    The agent forms these from XSSCandidate data. They are updated
    based on experiment observations, not LLM opinion.
    """
    id: str = Field(default_factory=lambda: "HYP-" + uuid.uuid4().hex[:8])
    vulnerability_type: str = ""    # "reflected_xss" | "dom_xss" | "stored_xss"
    source:             str = ""    # "location.hash" | "search param 'q'" | etc.
    sink:               str = ""    # "jQuery $()" | "innerHTML" | etc.
    context:            str = ""    # injection context
    event:              str = ""    # "hashchange" | "" (no event dependency)
    transformations:    list[str] = Field(default_factory=list)  # ["decodeURIComponent", "slice(1)"]
    required_conditions:list[str] = Field(default_factory=list)
    constraints:        list[str] = Field(default_factory=list)  # encoding constraints

    # Evidence tracking
    supporting_evidence_ids:    list[str] = Field(default_factory=list)
    contradicting_evidence_ids: list[str] = Field(default_factory=list)

    # Confidence: 0.0–1.0, updated by experiments
    confidence:   float = 0.5
    status:       HypothesisStatus = HypothesisStatus.ACTIVE

    # Guidance for next experiment
    next_experiment_hint: str = ""

    created_at:   datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at:   datetime = Field(default_factory=lambda: datetime.now(UTC))

    # ------------------------------------------------------------------
    # State transitions — called by AgentLoop, not LLM
    # ------------------------------------------------------------------

    def support(self, evidence_id: str, confidence_delta: float = 0.1) -> None:
        """An experiment produced supporting evidence."""
        if evidence_id not in self.supporting_evidence_ids:
            self.supporting_evidence_ids.append(evidence_id)
        self.confidence = min(1.0, self.confidence + confidence_delta)
        if self.confidence >= 0.9:
            self.status = HypothesisStatus.SUPPORTED
        self.updated_at = datetime.now(UTC)

    def contradict(self, evidence_id: str, confidence_delta: float = 0.2) -> None:
        """An experiment produced contradicting evidence."""
        if evidence_id not in self.contradicting_evidence_ids:
            self.contradicting_evidence_ids.append(evidence_id)
        self.confidence = max(0.0, self.confidence - confidence_delta)
        if self.confidence <= 0.1:
            self.status = HypothesisStatus.CONTRADICTED
        self.updated_at = datetime.now(UTC)

    def confirm(self, evidence_ids: list[str]) -> None:
        """Deterministic evidence proves this hypothesis."""
        self.supporting_evidence_ids.extend(
            eid for eid in evidence_ids
            if eid not in self.supporting_evidence_ids
        )
        self.confidence = 1.0
        self.status = HypothesisStatus.CONFIRMED
        self.updated_at = datetime.now(UTC)

    def reject(self, evidence_ids: list[str]) -> None:
        """Deterministic evidence disproves this hypothesis."""
        self.contradicting_evidence_ids.extend(
            eid for eid in evidence_ids
            if eid not in self.contradicting_evidence_ids
        )
        self.confidence = 0.0
        self.status = HypothesisStatus.REJECTED
        self.updated_at = datetime.now(UTC)

    def abandon(self, reason: str = "") -> None:
        self.status = HypothesisStatus.ABANDONED
        if reason:
            self.next_experiment_hint = f"Abandoned: {reason}"
        self.updated_at = datetime.now(UTC)

    @property
    def is_terminal(self) -> bool:
        return self.status in (
            HypothesisStatus.CONFIRMED,
            HypothesisStatus.REJECTED,
            HypothesisStatus.ABANDONED,
        )

    def summary(self) -> str:
        """Human-readable summary for LLM context."""
        lines = [
            f"Hypothesis {self.id}: {self.vulnerability_type}",
            f"  Source: {self.source}",
            f"  Sink:   {self.sink}",
        ]
        if self.event:
            lines.append(f"  Event:  {self.event}")
        if self.transformations:
            lines.append(f"  Transforms: {', '.join(self.transformations)}")
        if self.constraints:
            lines.append(f"  Constraints: {', '.join(self.constraints)}")
        lines.append(f"  Confidence: {self.confidence:.2f}  Status: {self.status}")
        if self.next_experiment_hint:
            lines.append(f"  Next: {self.next_experiment_hint}")
        return "\n".join(lines)


def hypothesis_from_candidate(candidate_dict: dict) -> Hypothesis:
    """
    Bootstrap a Hypothesis from a fused XSSCandidate dict.
    Called by AgentController at investigation start.
    """
    esem     = candidate_dict.get("encoding_profile", {})  # exec semantics stored here
    ca       = candidate_dict.get("context_analysis") or {}
    xss_type = candidate_dict.get("xss_type", "unknown")

    source = esem.get("source_label", "") or ca.get("source", "") or "unknown"
    sink   = esem.get("sink_label", "")   or ca.get("sink", "")   or "unknown"
    event  = esem.get("event_type", "")

    # Derive transformations from execution semantics
    transforms = esem.get("transformations", [])

    # Derive constraints from encoding profile
    encoded  = esem.get("encoded_chars", [])
    stripped = esem.get("stripped_chars", [])
    constraints = []
    if "<" in encoded or ">" in encoded:
        constraints.append("angle brackets HTML-encoded")
    if stripped:
        constraints.append(f"stripped chars: {stripped}")

    return Hypothesis(
        vulnerability_type=xss_type,
        source=source,
        sink=sink,
        context=ca.get("context", "") if isinstance(ca, dict) else "",
        event=event,
        transformations=transforms,
        constraints=constraints,
        required_conditions=[f"event={event}"] if event else [],
        next_experiment_hint=(
            f"Verify {source} flows to {sink}"
            + (f" via {event} event" if event else "")
        ),
    )
