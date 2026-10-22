"""
Iterative Candidate Generation Schemas
=======================================
Models for the generate → test → learn → replan loop.

PreviousTestResult  — what one test attempt observed
TestAttempt         — evidence record for one execution
CandidateFingerprint— deduplication key
IterationBudget     — enforced limits (LLM cannot override)
IterationState      — full state passed between iterations
IterationStatus     — terminal states
FailureClass        — structured failure taxonomy (new)
ConstraintDelta     — learned constraint update from a failure (new)
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Terminal states — spec §11
# CRITICAL: BUDGET_EXHAUSTED != SAFE
# ---------------------------------------------------------------------------

class IterationStatus(StrEnum):
    RUNNING          = "running"
    CONFIRMED        = "confirmed"       # deterministic evidence proves execution
    REJECTED         = "rejected"        # deterministic evidence disproves
    INCONCLUSIVE     = "inconclusive"    # budget exhausted without confirmation
    BUDGET_EXHAUSTED = "budget_exhausted"# hard limit hit — NOT the same as safe

    @property
    def is_terminal(self) -> bool:
        return self in (
            IterationStatus.CONFIRMED,
            IterationStatus.REJECTED,
            IterationStatus.INCONCLUSIVE,
            IterationStatus.BUDGET_EXHAUSTED,
        )

    @property
    def implies_safe(self) -> bool:
        """NEVER True — no terminal state means 'safe'."""
        return False


# ---------------------------------------------------------------------------
# FailureClass — structured failure taxonomy (new)
# ---------------------------------------------------------------------------

class FailureClass(StrEnum):
    """
    Classifies why a test attempt did not confirm the vulnerability.

    Every class implies a different constraint update:
      ENCODED          → add breakout chars to encoded_chars
      FILTERED/STRIPPED→ add breakout chars to stripped_chars
      PARTIAL          → some chars survived, some didn't — need diff
      WRONG_CONTEXT    → re-classify context, try different family
      WRONG_DELIVERY   → payload reached the wrong endpoint/parameter
      SYNTAX_INVALID   → payload was reflected but caused a JS error
      SINK_NOT_REACHED → payload reflected in HTML but didn't reach sink
      SCHEME_BLOCKED   → javascript: scheme was normalised away
      NOT_REFLECTED    → canary did not appear in response at all
      TRUNCATED        → payload was cut off after N chars
      UNKNOWN          → cannot determine from available evidence
    """
    ENCODED          = "encoded"
    FILTERED         = "filtered"
    STRIPPED         = "stripped"
    PARTIAL          = "partial"
    WRONG_CONTEXT    = "wrong_context"
    WRONG_DELIVERY   = "wrong_delivery"
    SYNTAX_INVALID   = "syntax_invalid"
    SINK_NOT_REACHED = "sink_not_reached"
    SINK_REACHED_NO_EXECUTION = "sink_reached_no_execution"
    EVENT_NOT_TRIGGERED = "event_not_triggered"
    SCHEME_BLOCKED   = "scheme_blocked"
    NOT_REFLECTED    = "not_reflected"
    TRUNCATED        = "truncated"
    BUDGET_HIT       = "budget_hit"
    UNKNOWN          = "unknown"


# ---------------------------------------------------------------------------
# ConstraintDelta — what a failure teaches us (new)
# ---------------------------------------------------------------------------

class ConstraintDelta(BaseModel):
    """
    Learned constraint update derived from a structured failure observation.

    Applied by the iterative loop to narrow the AttackConstraints before
    generating the next candidate generation.  Never produced by the LLM.
    """
    failure_class: FailureClass = FailureClass.UNKNOWN
    # Characters to add to each constraint set
    add_encoded_chars: list[str] = Field(default_factory=list)
    add_stripped_chars: list[str] = Field(default_factory=list)
    add_transformed_chars: list[str] = Field(default_factory=list)
    # Characters to remove from raw_chars (no longer usable)
    remove_raw_chars: list[str] = Field(default_factory=list)
    scheme_blocked: bool = False
    truncation_limit: int = 0       # 0 = no truncation observed
    context_reclassified: str = ""  # new context if WRONG_CONTEXT
    rationale: str = ""             # human explanation of the constraint update

    @classmethod
    def from_observation(
        cls,
        payload: str,
        status: str,
        reflection_snippet: str = "",
        http_status: int = 0,
    ) -> ConstraintDelta:
        """
        Derive a ConstraintDelta deterministically from a test observation.
        No LLM involved.
        """
        import html as _html

        status = (status or "").lower()

        if status == "confirmed":
            return cls(failure_class=FailureClass.UNKNOWN, rationale="confirmed")

        # WAF/firewall block — check http_status early
        if http_status in (403, 406, 429):
            return cls(failure_class=FailureClass.FILTERED, rationale=f"HTTP {http_status} — WAF/filter blocked request")

        # Detect scheme blocking
        if payload.lower().startswith("javascript:") and (
            status == "stripped"
            or ("javascript" not in (reflection_snippet or "").lower())
        ):
            return cls(
                failure_class=FailureClass.SCHEME_BLOCKED,
                scheme_blocked=True,
                add_stripped_chars=[":"],
                remove_raw_chars=[":"],
                rationale="javascript: scheme was normalised or stripped",
            )

        if status == "encoded" or (
            reflection_snippet and _html.escape(payload[:20]) in reflection_snippet
        ):
            # Find which chars were encoded
            encoded_chars: list[str] = []
            for c in set(payload):
                if c.isalnum():
                    continue
                esc = _html.escape(c)
                if esc != c and reflection_snippet and esc in reflection_snippet:
                    encoded_chars.append(c)
            if not encoded_chars:
                # Can't diff precisely — mark whole payload's special chars
                encoded_chars = [c for c in set(payload) if not c.isalnum() and c not in " _"]
            return cls(
                failure_class=FailureClass.ENCODED,
                add_encoded_chars=encoded_chars,
                remove_raw_chars=encoded_chars,
                rationale=f"characters HTML-encoded: {encoded_chars}",
            )

        if status == "stripped":
            stripped_chars = [c for c in set(payload) if not c.isalnum() and c not in " _"]
            return cls(
                failure_class=FailureClass.STRIPPED,
                add_stripped_chars=stripped_chars,
                remove_raw_chars=stripped_chars,
                rationale=f"characters stripped: {stripped_chars}",
            )

        # No snippet and not a definitive encoded/stripped/confirmed status
        if not reflection_snippet and status not in ("encoded", "stripped", "reflected", "validated"):
            return cls(failure_class=FailureClass.NOT_REFLECTED, rationale="canary absent from response")

        # Reflected but didn't execute — possibly wrong context
        if status in ("reflected", "validated", "tested") and reflection_snippet:
            return cls(
                failure_class=FailureClass.SINK_NOT_REACHED,
                rationale="payload reflected but no execution observed — context may be wrong",
            )

        return cls(failure_class=FailureClass.UNKNOWN, rationale=f"status={status!r}")


# ---------------------------------------------------------------------------
# IterationBudget — enforced by XScan, not the LLM
# ---------------------------------------------------------------------------

class IterationBudget(BaseModel):
    """
    Hard limits for the iterative candidate loop.
    These values are read from config; the LLM cannot modify them.
    """
    max_iterations:               int   = 5
    max_candidates_per_iteration: int   = 5
    max_total_candidates:         int   = 20
    max_requests:                 int   = 40
    max_runtime_s:                float = 120.0
    stop_on_confirmation:         bool  = True

    def remaining_candidates(self, used: int) -> int:
        return max(0, self.max_total_candidates - used)

    def can_continue(
        self,
        iteration: int,
        total_candidates_tested: int,
        elapsed_s: float,
    ) -> tuple[bool, str]:
        """Return (can_continue, reason_if_not)."""
        if iteration >= self.max_iterations:
            return False, f"max_iterations={self.max_iterations} reached"
        if total_candidates_tested >= self.max_total_candidates:
            return False, f"max_total_candidates={self.max_total_candidates} reached"
        if elapsed_s >= self.max_runtime_s:
            return False, f"max_runtime_s={self.max_runtime_s} reached"
        return True, ""


# ---------------------------------------------------------------------------
# CandidateFingerprint — deduplication
# ---------------------------------------------------------------------------

class CandidateFingerprint(BaseModel):
    """Uniquely identifies a tested candidate to prevent repetition."""
    fingerprint: str
    payload:     str
    url:         str
    parameter:   str
    context:     str

    @classmethod
    def compute(
        cls,
        payload: str,
        url: str,
        parameter: str,
        context: str,
    ) -> CandidateFingerprint:
        # Normalise before hashing
        norm = (
            payload.strip().lower()
            + "|" + url.rstrip("/").lower()
            + "|" + parameter.lower()
            + "|" + context.lower()
        )
        fp = hashlib.sha256(norm.encode()).hexdigest()[:16]
        return cls(
            fingerprint=fp,
            payload=payload,
            url=url,
            parameter=parameter,
            context=context,
        )


# ---------------------------------------------------------------------------
# PreviousTestResult — what one attempt observed
# ---------------------------------------------------------------------------

class PreviousTestResult(BaseModel):
    """
    Structured observation from a single test attempt.
    This is the evidence passed to the LLM for replanning.
    LLM reasoning alone cannot confirm a finding — evidence does.
    """
    candidate_id:      str
    attempt_id:        str
    iteration:         int
    payload:           str
    fingerprint:       str = ""

    # Deterministic observations
    reflected:         bool  = False   # payload appeared unencoded in response
    encoded:           bool  = False   # payload appeared but was HTML-encoded
    stripped:          bool  = False   # payload was removed
    transformed:       bool  = False   # payload was modified (not stripped, not encoded)
    http_status:       int   = 0
    response_changed:  bool  = False

    # Context of reflection
    reflection_context: str  = ""
    reflection_snippet: str  = ""

    # Browser evidence (Phase 10)
    browser_effect:    bool  = False
    console_output:    str   = ""
    dom_changed:       bool  = False

    # Outcome
    status:            str   = "tested"   # tested | rejected | validated | confirmed
    rejection_reason:  str | None = None
    evidence_refs:     list[str] = Field(default_factory=list)

    # Structured failure analysis (new)
    failure_class:     str   = ""         # FailureClass value
    constraint_delta:  ConstraintDelta | None = None

    @property
    def was_useful(self) -> bool:
        """True if this result provides new information for replanning."""
        return self.reflected or self.encoded or self.transformed

    def to_planner_summary(self) -> str:
        """Human-readable summary for the LLM replanning prompt."""
        parts = [f"Candidate {self.candidate_id}: payload={self.payload[:60]!r}"]
        if self.reflected and not self.encoded:
            parts.append("  reflected UNENCODED")
        elif self.encoded:
            parts.append("  reflected but HTML-encoded")
        elif self.stripped:
            parts.append("  stripped/removed by application")
        elif self.transformed:
            parts.append("  transformed (modified before reflection)")
        else:
            parts.append("  not reflected")
        if self.browser_effect:
            parts.append("  BROWSER EVENT OBSERVED")
        if self.failure_class:
            parts.append(f"  failure class: {self.failure_class}")
        if self.rejection_reason:
            parts.append(f"  rejection: {self.rejection_reason}")
        return "\n".join(parts)


# ---------------------------------------------------------------------------
# TestAttempt — evidence record per execution
# ---------------------------------------------------------------------------

class TestAttempt(BaseModel):
    """
    One test attempt record — stored in the evidence graph.
    Every attempt is preserved regardless of outcome.
    """
    attempt_id:        str = Field(default_factory=lambda: "ATT-" + uuid.uuid4().hex[:8])
    candidate_id:      str = ""
    iteration:         int = 0
    payload:           str = ""
    url:               str = ""
    parameter:         str = ""
    input_fingerprint: str = ""
    validator_result:  str = "pending"   # pending | reflected | encoded | stripped | confirmed | rejected
    evidence_refs:     list[str] = Field(default_factory=list)
    started_at:        datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at:       datetime | None = None
    duration_ms:       float = 0.0


# ---------------------------------------------------------------------------
# IterationState — full state threaded between iterations
# ---------------------------------------------------------------------------

class IterationState(BaseModel):
    """
    Complete state of the iterative loop.
    Passed between iterations; never modified by the LLM directly.
    """
    scan_id:    str
    url:        str
    parameter:  str

    # Iteration tracking
    iteration:          int = 0
    total_candidates:   int = 0
    total_requests:     int = 0
    elapsed_s:          float = 0.0
    status:             IterationStatus = IterationStatus.RUNNING

    # History (what has been tested)
    tested_fingerprints: set[str]             = Field(default_factory=set)
    previous_results:    list[PreviousTestResult] = Field(default_factory=list)
    all_attempts:        list[TestAttempt]    = Field(default_factory=list)

    # Terminal result
    confirmed_payload:  str | None = None
    confirmed_at:       datetime | None = None

    # Budget (enforced externally)
    budget: IterationBudget = Field(default_factory=IterationBudget)

    model_config = {"arbitrary_types_allowed": True}

    def is_duplicate(self, fingerprint: str) -> bool:
        return fingerprint in self.tested_fingerprints

    def record_attempt(self, result: PreviousTestResult, attempt: TestAttempt) -> None:
        self.tested_fingerprints.add(result.fingerprint)
        self.previous_results.append(result)
        self.all_attempts.append(attempt)
        self.total_candidates += 1
        self.total_requests   += 1

    def can_continue(self) -> tuple[bool, str]:
        return self.budget.can_continue(
            self.iteration, self.total_candidates, self.elapsed_s
        )

    def confirm(self, payload: str, evidence_refs: list[str]) -> None:
        self.status            = IterationStatus.CONFIRMED
        self.confirmed_payload = payload
        self.confirmed_at      = datetime.now(UTC)

    def exhaust(self, reason: str = "") -> None:
        self.status = IterationStatus.BUDGET_EXHAUSTED

    def summary(self) -> dict:
        return {
            "status":            self.status,
            "iterations":        self.iteration,
            "total_candidates":  self.total_candidates,
            "total_requests":    self.total_requests,
            "confirmed_payload": self.confirmed_payload,
            "attempts": [
                {
                    "attempt_id":  a.attempt_id,
                    "payload":     a.payload,
                    "result":      a.validator_result,
                    "iteration":   a.iteration,
                }
                for a in self.all_attempts
            ],
        }
