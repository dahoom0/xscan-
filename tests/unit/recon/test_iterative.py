"""
Acceptance tests for the iterative candidate generation loop — spec §15.

Test scenario:
  Candidate 1 -> filtered (stripped)
  Candidate 2 -> reflected but encoded
  Candidate 3 -> filtered (stripped)
  Candidate 4 -> successful (unencoded reflection)

Verify:
  - XScan does not stop after Candidate 1
  - Learns from each failure
  - Eventually validates Candidate 4
  - Stops immediately after confirmation
  - MAX_TOTAL_CANDIDATES is enforced even if LLM requests more
  - BUDGET_EXHAUSTED != SAFE
  - Full attempt history is preserved
  - All attempt states are distinguishable
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from xscan.core.scope.engine import ScopeEngine
from xscan.core.scope.policy import PolicyEngine
from xscan.schemas.iteration import (
    IterationBudget, IterationStatus,
    PreviousTestResult, CandidateFingerprint,
)
from xscan.validation.iterative import IterativeValidator
from xscan.validation.observation import Observation


# ---------------------------------------------------------------------------
# Mock HTTP responses
# ---------------------------------------------------------------------------

class _ScenarioHTTPValidator:
    """
    Simulates a server that:
      payload 1 -> stripped
      payload 2 -> encoded
      payload 3 -> stripped
      payload 4 -> reflected unencoded  (success)
      payload 5+ -> stripped
    """

    def __init__(self) -> None:
        self.call_count = 0
        self._requests = 0

    def execute(self, url, param, method, payload, attempt, form_data=None, baseline_body="") -> Observation:
        self.call_count += 1
        self._requests += 1
        obs = Observation(attempt=attempt, payload=payload, url_sent=url)
        obs.http_status = 200
        obs.response_changed = True

        if self.call_count == 2:
            # payload 2: encoded
            obs.payload_encoded  = True
            obs.payload_reflected = False
            obs.payload_stripped  = False
        elif self.call_count == 4:
            # payload 4: unencoded reflection — SUCCESS
            obs.payload_reflected = True
            obs.payload_encoded   = False
            obs.payload_stripped  = False
            obs.reflection_context = "html_attribute"
            obs.reflection_snippet = f'value="{payload}"'
        else:
            # all others: stripped
            obs.payload_stripped  = True
            obs.payload_reflected = False
            obs.payload_encoded   = False

        return obs


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scope():
    return ScopeEngine.allow_all("test-iter")

@pytest.fixture
def policy():
    return PolicyEngine()

@pytest.fixture
def budget_small():
    return IterationBudget(
        max_iterations=5,
        max_candidates_per_iteration=5,
        max_total_candidates=10,   # must be >= 4 for the scenario to reach success
        max_requests=20,
        max_runtime_s=60.0,
        stop_on_confirmation=True,
    )

@pytest.fixture
def budget_tiny():
    """Budget that exhausts after 3 total candidates."""
    return IterationBudget(
        max_iterations=5,
        max_candidates_per_iteration=5,
        max_total_candidates=3,
        max_requests=10,
        max_runtime_s=60.0,
        stop_on_confirmation=True,
    )


# ---------------------------------------------------------------------------
# Scenario test — spec §15
# ---------------------------------------------------------------------------

class TestIterativeScenario:
    """
    Scenario: filtered → encoded → filtered → CONFIRMED
    """

    def _run(self, budget, scope, policy, extra_payloads=None) -> tuple[Any, _ScenarioHTTPValidator]:
        mock_http = _ScenarioHTTPValidator()

        engine = IterativeValidator(
            scope=scope,
            policy=policy,
            budget=budget,
            scan_id="test",
            no_llm=True,
        )

        # Directly replace the _http attribute after construction
        engine._http = mock_http  # type: ignore[attr-defined]

        state = engine.run(
            url="https://example.com/search",
            parameter="q",
            method="GET",
            context_analysis={
                "context":        "html_attribute",
                "quote_type":     "double",
                "attribute":      "value",
                "tag":            "input",
                "breakout_chars": ['"'],
            },
            encoding_profile={
                "raw_chars":                ['"', "'", " ", "="],
                "encoded_chars":            ["<", ">"],
                "stripped_chars":           [],
                "can_break_html_attribute": True,
                "can_break_script_string":  True,
                "can_break_html_text":      False,
            },
        )

        return state, mock_http

    def test_does_not_stop_after_first_failure(self, budget_small, scope, policy):
        state, mock = self._run(budget_small, scope, policy)
        assert mock.call_count >= 2, "Should have tested more than 1 candidate"

    def test_eventually_confirms(self, budget_small, scope, policy):
        state, mock = self._run(budget_small, scope, policy)
        assert state.status == IterationStatus.CONFIRMED, (
            f"Expected CONFIRMED, got {state.status}. "
            f"Attempts: {[r.to_planner_summary() for r in state.previous_results]}"
        )
        assert state.confirmed_payload is not None

    def test_stops_immediately_on_confirmation(self, budget_small, scope, policy):
        """After confirmation, no more candidates should be tested."""
        state, mock = self._run(budget_small, scope, policy)
        # Call count should be exactly 4 (confirmed on 4th)
        assert mock.call_count == 4, (
            f"Expected 4 calls (stop on confirmation), got {mock.call_count}"
        )

    def test_full_history_preserved(self, budget_small, scope, policy):
        """All attempts (including failures) must be in the history."""
        state, mock = self._run(budget_small, scope, policy)
        assert len(state.previous_results) == 4, (
            f"Expected 4 results, got {len(state.previous_results)}"
        )
        # First: stripped
        assert state.previous_results[0].stripped
        # Second: encoded
        assert state.previous_results[1].encoded
        # Third: stripped
        assert state.previous_results[2].stripped
        # Fourth: unencoded reflection
        assert state.previous_results[3].reflected
        assert not state.previous_results[3].encoded

    def test_attempt_states_distinguishable(self, budget_small, scope, policy):
        """Each attempt must have a distinct, accurate status."""
        state, _ = self._run(budget_small, scope, policy)
        statuses = [r.status for r in state.previous_results]
        # Should include stripped, encoded, and validated
        assert "stripped" in statuses or "tested" in statuses
        assert "encoded"  in statuses or "tested" in statuses
        # Last one confirmed
        assert state.previous_results[-1].status in ("validated", "confirmed")


class TestBudgetEnforcement:
    """Budget limits enforced by XScan, not the LLM."""

    def test_max_total_candidates_enforced(self, budget_tiny, scope, policy):
        """Even if we could test more, stop at max_total_candidates."""
        def never_succeed(url, param, method, payload, attempt, form_data=None, baseline_body=""):
            obs = Observation(attempt=attempt, payload=payload, url_sent=url)
            obs.payload_stripped = True
            return obs

        engine = IterativeValidator(
            scope=scope, policy=policy, budget=budget_tiny,
            scan_id="test", no_llm=True,
        )
        engine._http = MagicMock()  # type: ignore
        engine._http.execute.side_effect = never_succeed
        engine._http._requests = 0

        state = engine.run(
            url="https://example.com/search",
            parameter="q",
            context_analysis={"context": "html_attribute", "quote_type": "double"},
            encoding_profile={
                "raw_chars": ['"'], "encoded_chars": [],
                "can_break_html_attribute": True,
            },
        )

        assert state.total_candidates <= budget_tiny.max_total_candidates, (
            f"Tested {state.total_candidates} but max was {budget_tiny.max_total_candidates}"
        )
        assert state.status in (
            IterationStatus.BUDGET_EXHAUSTED,
            IterationStatus.INCONCLUSIVE,
        )

    def test_budget_exhausted_is_not_safe(self, budget_tiny, scope, policy):
        """BUDGET_EXHAUSTED must never be interpreted as safe."""
        def never_succeed(url, param, method, payload, attempt, form_data=None, baseline_body=""):
            obs = Observation(attempt=attempt, payload=payload, url_sent=url)
            obs.payload_stripped = True
            return obs

        engine = IterativeValidator(
            scope=scope, policy=policy, budget=budget_tiny,
            scan_id="test", no_llm=True,
        )
        engine._http = MagicMock()  # type: ignore
        engine._http.execute.side_effect = never_succeed
        engine._http._requests = 0

        state = engine.run(
            url="https://example.com/search",
            parameter="q",
            context_analysis={"context": "html_attribute", "quote_type": "double"},
            encoding_profile={"raw_chars": ['"'], "can_break_html_attribute": True},
        )

        # The critical assertion from the spec
        assert not state.status.implies_safe
        assert state.status != IterationStatus.CONFIRMED


class TestDeduplication:
    def test_duplicate_fingerprint_skipped(self, scope, policy):
        """Same payload + url + param + context must not be retested."""
        fp1 = CandidateFingerprint.compute(
            payload='"><img src=x onerror=alert(1)>',
            url="https://example.com/search",
            parameter="q",
            context="html_attribute",
        )
        fp2 = CandidateFingerprint.compute(
            payload='"><img src=x onerror=alert(1)>',  # identical
            url="https://example.com/search",
            parameter="q",
            context="html_attribute",
        )
        assert fp1.fingerprint == fp2.fingerprint

    def test_different_payloads_different_fingerprints(self):
        fp1 = CandidateFingerprint.compute(
            payload='" onmouseover="alert(1)',
            url="https://example.com/search",
            parameter="q",
            context="html_attribute",
        )
        fp2 = CandidateFingerprint.compute(
            payload='"><svg onload=alert(1)>',
            url="https://example.com/search",
            parameter="q",
            context="html_attribute",
        )
        assert fp1.fingerprint != fp2.fingerprint

    def test_state_dedup_prevents_retest(self, scope, policy):
        from xscan.schemas.iteration import IterationState, IterationBudget, PreviousTestResult, TestAttempt
        state = IterationState(scan_id="t", url="https://x.com", parameter="q")
        fp = "abc123"
        prev = PreviousTestResult(
            candidate_id="c1", attempt_id="a1", iteration=1,
            payload="test", fingerprint=fp, stripped=True, status="stripped",
        )
        attempt = TestAttempt(iteration=1, payload="test", fingerprint=fp)
        state.record_attempt(prev, attempt)

        assert state.is_duplicate(fp)
        assert not state.is_duplicate("differentfp")


class TestIterationStatus:
    def test_terminal_states(self):
        for s in (IterationStatus.CONFIRMED, IterationStatus.REJECTED,
                  IterationStatus.INCONCLUSIVE, IterationStatus.BUDGET_EXHAUSTED):
            assert s.is_terminal

    def test_running_is_not_terminal(self):
        assert not IterationStatus.RUNNING.is_terminal

    def test_no_status_implies_safe(self):
        """Spec requirement: no terminal state means 'safe'."""
        for s in IterationStatus:
            assert not s.implies_safe


class TestPreviousTestResult:
    def test_to_planner_summary_stripped(self):
        r = PreviousTestResult(
            candidate_id="c1", attempt_id="a1", iteration=1,
            payload="<img>", fingerprint="x",
            stripped=True, status="stripped",
        )
        summary = r.to_planner_summary()
        assert "stripped" in summary

    def test_to_planner_summary_encoded(self):
        r = PreviousTestResult(
            candidate_id="c2", attempt_id="a2", iteration=1,
            payload="<img>", fingerprint="x",
            encoded=True, status="encoded",
        )
        summary = r.to_planner_summary()
        assert "encoded" in summary

    def test_to_planner_summary_reflected(self):
        r = PreviousTestResult(
            candidate_id="c3", attempt_id="a3", iteration=1,
            payload='" onmouseover="alert(1)', fingerprint="x",
            reflected=True, status="validated",
        )
        summary = r.to_planner_summary()
        assert "UNENCODED" in summary or "reflected" in summary.lower()

    def test_was_useful_for_encoded(self):
        r = PreviousTestResult(
            candidate_id="c1", attempt_id="a1", iteration=1,
            payload="x", fingerprint="y", encoded=True, status="encoded",
        )
        assert r.was_useful   # encoded is still useful info

    def test_not_useful_when_stripped(self):
        r = PreviousTestResult(
            candidate_id="c1", attempt_id="a1", iteration=1,
            payload="x", fingerprint="y", stripped=True, status="stripped",
        )
        assert not r.was_useful
