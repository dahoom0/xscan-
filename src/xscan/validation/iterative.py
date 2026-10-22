"""
Iterative XSS Validation Engine — spec §2-§12
==============================================
Implements the bounded generate → test → learn → replan loop.

Flow:
  IterationState
       ↓
  [while budget allows]
       ↓
    Plan (LLM or heuristic)
       ↓
    Filter duplicates
       ↓
    Policy gate
       ↓
    Test each candidate (HTTPValidator)
       ↓
    Capture PreviousTestResult
       ↓
    Update IterationState
       ↓
    If confirmed → stop
       ↓
    Replan with results
       ↓
  [end loop]
       ↓
  IterationState (terminal)

Budget limits are enforced here, not by the LLM.
The LLM cannot claim success — only the validator can confirm.
"""
from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from xscan.core.scope.engine import ScopeEngine
from xscan.core.scope.policy import PolicyEngine
from xscan.errors import PolicyViolation
from xscan.schemas.iteration import (
    CandidateFingerprint,
    IterationBudget,
    IterationState,
    IterationStatus,
    PreviousTestResult,
    TestAttempt,
)
from xscan.validation.http import HTTPValidator
from xscan.validation.observation import Observation

logger = logging.getLogger(__name__)

ProgressCb = Callable[[str], None]


class IterativeValidator:
    """
    Bounded iterative XSS validation engine.

    Usage::

        engine = IterativeValidator(scope, policy, budget)
        state  = engine.run(
            url="https://example.com/search",
            parameter="q",
            method="GET",
            context_analysis={...},
            encoding_profile={...},
            no_llm=False,
        )
        # state.status ∈ CONFIRMED | REJECTED | INCONCLUSIVE | BUDGET_EXHAUSTED
    """

    def __init__(
        self,
        scope:        ScopeEngine,
        policy:       PolicyEngine,
        budget:       IterationBudget | None = None,
        scan_id:      str = "",
        no_llm:       bool = False,
        progress_cb:  ProgressCb | None = None,
    ) -> None:
        self._scope     = scope
        self._policy    = policy
        self._budget    = budget or IterationBudget()
        self._scan_id   = scan_id
        self._no_llm    = no_llm
        self._progress  = progress_cb or (lambda msg: None)
        self._http      = HTTPValidator(scope)

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run(
        self,
        url:                str,
        parameter:          str,
        method:             str = "GET",
        context_analysis:   dict[str, Any] | None = None,
        encoding_profile:   dict[str, Any] | None = None,
        form_data:          dict[str, Any] | None = None,
        technologies:       list[str] | None = None,
        all_contexts:       list[dict[str, Any]] | None = None,
        execution_semantics:dict[str, Any] | None = None,
    ) -> IterationState:
        """
        Execute the full iterative loop for one candidate (url + parameter).
        Returns the terminal IterationState.

        all_contexts: every reflection context found (e.g. [html_text, html_attribute]).
                      The engine tries the most exploitable context first.
        """
        state = IterationState(
            scan_id=self._scan_id,
            url=url,
            parameter=parameter,
            budget=self._budget,
        )
        ca    = context_analysis or {}
        ep    = encoding_profile or {}
        esem  = execution_semantics or {}
        t0    = time.monotonic()

        # A hash-fragment source never reaches the server: the payload lives in
        # the fragment, which the browser strips from every request. The HTTP
        # loop can only waste its budget asking the server for an unchanged
        # page — the browser confirmer owns this candidate.
        if esem.get("xss_type") == "dom" and esem.get("source_type") == "hash":
            self._progress(
                "  Fragment source — nothing reaches the server; "
                "delegating to browser confirmation"
            )
            state.status = IterationStatus.INCONCLUSIVE
            state.elapsed_s = time.monotonic() - t0
            return state

        # A stored payload that landed inside a URL attribute (href/src) is
        # inert until a victim activates the element — no HTTP response can
        # ever show execution, and replaying the POST adds nothing the detector
        # has not already proven. The browser confirmer owns this class: it
        # delivers the payload and clicks the poisoned link.
        if esem.get("xss_type") == "stored" and esem.get("sink_kind") == "url_attribute":
            self._progress(
                "  Stored payload sits in a URL attribute (href/src) — "
                "execution needs a click; delegating to browser confirmation"
            )
            state.status = IterationStatus.INCONCLUSIVE
            state.elapsed_s = time.monotonic() - t0
            return state

        # AngularJS template injection: the payload is a {{ ... }} expression
        # evaluated by Angular on page load — no reflection breakout exists and
        # no HTTP response can show execution. The browser confirmer loads the
        # test URL and reads the dialog off the hooked window.
        if esem.get("sink_capability") == "js_execution" and esem.get("sink_kind") == "csti":
            self._progress(
                "  AngularJS template expression — evaluated client-side on "
                "load; delegating to browser confirmation"
            )
            state.status = IterationStatus.INCONCLUSIVE
            state.elapsed_s = time.monotonic() - t0
            return state
        techs = technologies or []

        # Detect DOM execution context from execution_semantics
        is_dom      = esem.get("xss_type") == "dom" or (not parameter and not ca)
        source_type = esem.get("source_type", "")
        sink_cap    = esem.get("sink_capability", "")

        # For DOM candidates with no explicit parameter, derive from source type
        effective_param = parameter
        if is_dom and not effective_param:
            effective_param = "#fragment" if source_type == "hash" else "q"
        state = state.model_copy(update={"parameter": effective_param})

        # Rank all reflection contexts by exploitability
        ranked_contexts = _rank_contexts(all_contexts or ([ca] if ca else [{}]))

        # Load skills — for DOM, also load jQuery/DOM-specific skills
        dom_techs = list(techs)
        if is_dom:
            dom_techs.extend(["jQuery"] if "jQuery" in sink_cap else ["DOM"])
        skills_text = self._load_skills(ca, dom_techs)

        failed_hypotheses: list[str] = []

        while True:
            state.elapsed_s = time.monotonic() - t0

            # Budget gate
            can_go, reason = state.can_continue()
            if not can_go:
                self._progress(f"  Budget exhausted: {reason}")
                state.exhaust(reason)
                break

            state.iteration += 1
            self._progress(
                f"  Iteration {state.iteration}  "
                f"({state.total_candidates}/{self._budget.max_total_candidates} tested)"
            )

            # Generate candidates for this iteration
            # On iteration 1: use skill-aware heuristic covering ALL ranked contexts
            # On iteration 2+: use LLM replanner with observation history
            candidates = self._plan_iteration(
                state, ranked_contexts[0] if ranked_contexts else {}, ep, skills_text,
                failed_hypotheses,
                all_contexts=ranked_contexts,
                execution_semantics=esem,
                technologies=techs,
            )

            if not candidates:
                self._progress("  No viable candidates generated — stopping")
                state.status = IterationStatus.INCONCLUSIVE
                break

            # Test candidates one by one
            confirmed_this_iteration = False
            for cand in candidates:
                payload    = cand.get("payload", "")
                hypothesis = cand.get("hypothesis", "")
                if not payload:
                    continue

                # Deduplication
                fp = CandidateFingerprint.compute(
                    payload=payload,
                    url=url,
                    parameter=parameter,
                    context=ca.get("context", ""),
                )
                if state.is_duplicate(fp.fingerprint):
                    self._progress(f"    Skip duplicate: {payload[:50]!r}")
                    continue

                # Remaining budget check
                if state.total_candidates >= self._budget.max_total_candidates:
                    state.exhaust("max_total_candidates")
                    break

                # Check for interrupt between candidates (Ctrl+C)
                from xscan.validation.http import is_stop_requested
                if is_stop_requested():
                    self._progress("  Scan interrupted by user")
                    state.status = IterationStatus.INCONCLUSIVE
                    return state

                # Policy gate
                try:
                    self._policy.assert_permitted(
                        "http_request",
                        {"node_type": "xss_validator", "url": url},
                    )
                except PolicyViolation as exc:
                    self._progress(f"    Policy blocked: {exc}")
                    continue

                # Execute test
                attempt = TestAttempt(
                    iteration=state.iteration,
                    payload=payload,
                    url=url,
                    parameter=parameter,
                    input_fingerprint=fp.fingerprint,
                )
                state.elapsed_s = time.monotonic() - t0

                obs = self._http.execute(
                    url=url, param=parameter, method=method,
                    payload=payload, attempt=state.total_candidates + 1,
                    form_data=form_data,
                )

                # Build PreviousTestResult from observation
                prev = self._obs_to_result(
                    obs=obs,
                    candidate_id=fp.fingerprint[:8],
                    attempt_id=attempt.attempt_id,
                    iteration=state.iteration,
                    payload=payload,
                    fp=fp.fingerprint,
                )

                # Update attempt record
                attempt.validator_result = prev.status
                attempt.evidence_refs    = prev.evidence_refs
                attempt.finished_at      = datetime.now(UTC)
                attempt.duration_ms      = obs.duration_ms

                # Record in state
                state.record_attempt(prev, attempt)

                # Log result
                self._progress(
                    f"    #{state.total_candidates:02d}  {payload[:55]!r:<55}"
                    f"  {'REFLECTED' if prev.reflected and not prev.encoded else 'encoded' if prev.encoded else 'stripped' if prev.stripped else 'no-reflect'}"
                    + (f"  [{prev.failure_class}]" if prev.failure_class and prev.failure_class != "unknown" else "")
                )

                # Check confirmation (deterministic only)
                if obs.promising and not obs.payload_encoded and self._budget.stop_on_confirmation:
                    state.confirm(payload, prev.evidence_refs)
                    confirmed_this_iteration = True
                    self._progress(f"    CONFIRMED: {payload[:60]!r}")
                    break

                # Track failed hypothesis for replanning
                if hypothesis and not prev.was_useful and hypothesis not in failed_hypotheses:
                    failed_hypotheses.append(hypothesis)

            if state.status.is_terminal:
                break
            if confirmed_this_iteration and self._budget.stop_on_confirmation:
                break

            # Early-exit: if ALL attempts this iteration were encoded (server
            # is encoding every breakout char we have), there is nothing more
            # HTTP-only testing can do — mark inconclusive immediately.
            if state.previous_results and state.iteration >= 1:
                this_iter = [
                    r for r in state.previous_results
                    if r.iteration == state.iteration
                ]
                if this_iter and all(r.encoded for r in this_iter):
                    self._progress(
                        "  All payloads encoded by server — "
                        "HTTP validation cannot confirm. Stopping early."
                    )
                    state.status = IterationStatus.INCONCLUSIVE
                    break

        # Final status
        if state.status == IterationStatus.RUNNING:
            ok, reason = state.can_continue()
            if not ok:
                state.exhaust(reason)
            else:
                state.status = IterationStatus.INCONCLUSIVE

        state.elapsed_s = time.monotonic() - t0
        return state

    # ------------------------------------------------------------------
    # Planning
    # ------------------------------------------------------------------

    def _plan_iteration(
        self,
        state:              IterationState,
        context_analysis:   dict[str, Any],
        encoding_profile:   dict[str, Any],
        skills_text:        str,
        failed_hypotheses:  list[str],
        all_contexts:       list[dict[str, Any]] | None = None,
        execution_semantics:dict[str, Any] | None = None,
        technologies:       list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Return candidates for this iteration.

        Iteration 1: skill-aware heuristic plan covering ALL reflection contexts.
        Iteration 2+: deterministic refinement from observed failures first; the
        LLM replanner (when enabled) consumes the same observation history.
        """
        budget_remaining = self._budget.remaining_candidates(state.total_candidates)
        per_iter = min(
            self._budget.max_candidates_per_iteration,
            budget_remaining,
        )
        if per_iter <= 0:
            return []

        # Iteration 2+ (deterministic first): failure analysis turns the
        # structured observations into new constraints (which characters the
        # server encodes/strips), and the synthesiser builds the next
        # generation of candidates from the narrowed constraint set.
        if state.total_candidates > 0:
            refined = self._refine_from_history(
                state, context_analysis, encoding_profile,
                all_contexts or [context_analysis],
                execution_semantics or {}, per_iter,
            )
            if refined:
                return refined
            if self._no_llm:
                # Refinement learned nothing exploitable - without an LLM there
                # is no other source of new candidates; stop instead of
                # regenerating the iteration-1 plan.
                return []

        if not self._no_llm and state.total_candidates > 0:
            try:
                return self._llm_plan(
                    state, context_analysis, encoding_profile,
                    skills_text, failed_hypotheses, per_iter,
                    technologies=technologies,
                )
            except Exception as exc:
                logger.warning("LLM iterative planner failed: %s — using heuristic", exc)

        # Skill-aware heuristic: covers ALL contexts + DOM-specific strategies
        return self._skill_heuristic_plan(
            context_analysis, encoding_profile,
            per_iter, skills_text,
            all_contexts or [context_analysis],
            execution_semantics or {},
        )

    def _refine_from_history(
        self,
        state:              IterationState,
        context_analysis:   dict[str, Any],
        encoding_profile:   dict[str, Any],
        all_contexts:       list[dict[str, Any]],
        execution_semantics:dict[str, Any],
        max_candidates:     int,
    ) -> list[dict[str, Any]]:
        """
        Deterministic failure analysis -> new constraints -> next candidates.

        Applies each ConstraintDelta from the attempt history to narrow the
        scenario before synthesis, so subsequent candidates never re-use
        characters or patterns already proven ineffective.
        """
        from xscan.validation.payload_synthesis import (
            refine_from_observations,
            scenario_from_evidence,
        )

        history = [r.model_dump(mode="json") for r in state.previous_results]
        if not history:
            return []

        # Primary scenario from the strongest available evidence.
        primary_ctx = context_analysis or (all_contexts or [{}])[0]
        scenario = scenario_from_evidence(
            primary_ctx, encoding_profile,
            sink_kind=str(execution_semantics.get("sink_kind", "") or ""),
            source_type=str(execution_semantics.get("source_type", "") or ""),
        )

        # Apply learned ConstraintDeltas from all previous attempts.
        # This is the mechanism that stops the loop from re-generating
        # candidates with characters proven to be encoded/stripped.
        for result in state.previous_results:
            delta = result.constraint_delta
            if delta is None:
                continue
            if delta.add_encoded_chars:
                scenario.encoded_chars = sorted(
                    set(scenario.encoded_chars) | set(delta.add_encoded_chars)
                )
            if delta.add_stripped_chars:
                scenario.stripped_chars = sorted(
                    set(scenario.stripped_chars) | set(delta.add_stripped_chars)
                )
            if delta.remove_raw_chars:
                scenario.raw_chars = [
                    c for c in scenario.raw_chars
                    if c not in delta.remove_raw_chars
                ]
            if delta.scheme_blocked and ":" not in scenario.stripped_chars:
                scenario.stripped_chars = sorted(
                    set(scenario.stripped_chars) | {":"}
                )
                scenario.raw_chars = [c for c in scenario.raw_chars if c != ":"]
            if delta.context_reclassified:
                scenario.context = delta.context_reclassified

        payloads = refine_from_observations(scenario, history, max_payloads=max_candidates)
        if not payloads:
            return []

        return [{
            "payload":              p.payload,
            "hypothesis":           p.hypothesis,
            "expected_observation": p.expected_observation,
            "rationale":            p.rationale,
            "generation_mode":      "failure_refinement",
            "priority":             p.priority,
        } for p in payloads]

    def _skill_heuristic_plan(
        self,
        primary_ctx:         dict[str, Any],
        ep:                  dict[str, Any],
        max_cands:           int,
        skills_text:         str,
        all_contexts:        list[dict[str, Any]],
        execution_semantics: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Generate candidates from ALL reflection contexts + execution semantics.

        For DOM candidates with execution_semantics:
          - Uses source_type/sink_capability to select sink-specific payloads
          - Generates correct hash-fragment test URLs for hashchange sinks
          - Adds jQuery selector-specific payloads for jQuery $() sinks
        """
        from xscan.nodes.validation.xss_validate import XssValidatorNode

        esem = execution_semantics or {}
        is_dom       = esem.get("xss_type") == "dom"
        source_type  = esem.get("source_type", "")
        sink_cap     = esem.get("sink_capability", "")
        event_type   = esem.get("event_type", "")

        all_candidates: list[dict[str, Any]] = []
        seen_payloads: set[str] = set()

        # ── DOM-specific candidates (execution-semantics driven) ─────────
        if is_dom and source_type:
            # Payloads the detector already matched to this sink come first: it
            # knows the concrete sink (.attr('href') -> javascript: URI).
            for payload in esem.get("payloads") or []:
                if payload and payload not in seen_payloads:
                    seen_payloads.add(payload)
                    all_candidates.append({
                        "payload":              payload,
                        "hypothesis":           "sink-matched payload",
                        "expected_observation": "tainted value reaches the sink",
                        "rationale":            "selected for this sink by dom-xss-detector",
                        "generation_mode":      "dom_sink_candidate",
                        "priority":             1,
                    })

            dom_cands = _dom_sink_payloads(source_type, sink_cap, event_type)
            for item in dom_cands:
                p = item["payload"]
                if p not in seen_payloads:
                    seen_payloads.add(p)
                    all_candidates.append(item)

        # ── Reflected/attributed candidates from reflection contexts ─────
        for ctx in all_contexts:
            plan = XssValidatorNode._heuristic_plan(
                ctx, ep,
                sink_kind=esem.get("sink_kind", ""),
                source_type=source_type,
            )
            for tc in plan.get("test_cases", []):
                p = tc.get("payload", "")
                if p and p not in seen_payloads:
                    seen_payloads.add(p)
                    all_candidates.append({
                        "payload":              p,
                        "hypothesis":           tc.get("rationale", ""),
                        "expected_observation": tc.get("expected_observation", ""),
                        "rationale":            f"[{ctx.get('context','?')}] {tc.get('rationale','')}",
                        # The synthesiser tags every case it derived with a category.
                        "generation_mode":      (
                            "scenario_synthesis" if tc.get("category") else "skill_candidate"
                        ),
                        "priority":             tc.get("priority", 99),
                    })

        # ── Skill-derived payloads ───────────────────────────────────────
        if skills_text:
            skill_payloads = _extract_payloads_from_skills(skills_text, ep)
            for p in skill_payloads:
                if p not in seen_payloads:
                    seen_payloads.add(p)
                    all_candidates.append({
                        "payload":              p,
                        "hypothesis":           "skill-derived payload",
                        "expected_observation": "XSS execution",
                        "rationale":            "From loaded skill pack",
                        "generation_mode":      "skill_candidate",
                        "priority":             50,
                    })

        all_candidates.sort(key=lambda x: x.get("priority", 99))
        return all_candidates[:max_cands]

    def _llm_plan(
        self,
        state:             IterationState,
        ca:                dict[str, Any],
        ep:                dict[str, Any],
        skills_text:       str,
        failed_hypotheses: list[str],
        max_candidates:    int,
        technologies:      list[str] | None = None,
    ) -> list[dict[str, Any]]:
        from xscan.llm.specialists.iterative_planner import (
            IterativePlanInput,
            IterativePlannerSpecialist,
        )
        from xscan.validation.ctf_detection import (
            detect_ctf_context,
            get_ctf_planner_hint,
        )

        # Detect CTF context and generate hint for LLM
        ctf_ctx = detect_ctf_context(state.url, technologies or [])
        ctf_hint = get_ctf_planner_hint(ctf_ctx)

        specialist = IterativePlannerSpecialist()
        plan_input = IterativePlanInput(
            scan_id=state.scan_id,
            url=state.url,
            parameter=state.parameter,
            context_analysis=ca,
            encoding_profile=ep,
            previous_results=state.previous_results[-10:],  # last 10
            skills_text=skills_text,
            max_candidates=max_candidates,
            total_tested=state.total_candidates,
            max_total=self._budget.max_total_candidates,
            failed_hypotheses=failed_hypotheses[-5:],
            ctf_hint=ctf_hint,
        )
        output = specialist.run(plan_input)

        # Hard enforcement: never more than per_iter candidates
        candidates = [
            {
                "payload":              c.payload,
                "hypothesis":           c.hypothesis,
                "expected_observation": c.expected_observation,
                "rationale":            c.rationale,
                "generation_mode":      c.generation_mode,
                "priority":             c.priority,
            }
            for c in output.candidates[:max_candidates]
            if c.payload
        ]
        return candidates

    @staticmethod
    def _heuristic_plan(
        ca: dict[str, Any],
        ep: dict[str, Any],
        max_candidates: int,
    ) -> list[dict[str, Any]]:
        """Deterministic fallback plan — same logic as XssValidatorNode._heuristic_plan."""
        from xscan.nodes.validation.xss_validate import XssValidatorNode
        plan = XssValidatorNode._heuristic_plan(ca, ep)
        return [
            {"payload": tc["payload"], "hypothesis": tc.get("rationale", ""),
             "expected_observation": tc.get("expected_observation", ""),
             "rationale": tc.get("rationale", ""), "generation_mode": "skill_candidate"}
            for tc in plan.get("test_cases", [])[:max_candidates]
            if tc.get("payload")
        ]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _obs_to_result(
        obs:          Observation,
        candidate_id: str,
        attempt_id:   str,
        iteration:    int,
        payload:      str,
        fp:           str,
    ) -> PreviousTestResult:
        status = "tested"
        if obs.confirmed:
            status = "confirmed"
        elif obs.promising:
            status = "validated"
        elif obs.payload_encoded:
            status = "encoded"
        elif obs.payload_stripped:
            status = "stripped"

        # Build structured failure analysis — deterministic, no LLM
        from xscan.schemas.iteration import ConstraintDelta
        delta = ConstraintDelta.from_observation(
            payload=payload,
            status=status,
            reflection_snippet=obs.reflection_snippet,
            http_status=obs.http_status,
        )

        return PreviousTestResult(
            candidate_id=candidate_id,
            attempt_id=attempt_id,
            iteration=iteration,
            payload=payload,
            fingerprint=fp,
            reflected=obs.payload_reflected,
            encoded=obs.payload_encoded,
            stripped=obs.payload_stripped,
            transformed=obs.response_changed and not obs.payload_reflected,
            http_status=obs.http_status,
            response_changed=obs.response_changed,
            reflection_context=obs.reflection_context,
            reflection_snippet=obs.reflection_snippet[:200],
            browser_effect=obs.confirmed,
            status=status,
            rejection_reason=obs.error if obs.error else None,
            failure_class=delta.failure_class.value,
            constraint_delta=delta,
        )

    @staticmethod
    def _load_skills(ca: dict[str, Any], technologies: list[str]) -> str:
        try:
            from xscan.skills import skill_manager
            skill_manager.load_all()
            ctx_name = ca.get("context", "")
            skills = skill_manager.for_context(
                techs=technologies,
                context=ctx_name,
                category="xss",
                xss_context=ctx_name,
            )
            return skill_manager.render(skills)
        except Exception:
            return ""

# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

_CONTEXT_RANK: dict[str, int] = {
    "html_attribute":           5,
    "html_attribute_unquoted":  5,
    "script_string_double":     4,
    "script_string_single":     4,
    "script_string_template":   4,
    "script_expression":        4,
    "url_param":                3,
    "html_text":                2,
    "html_comment":             1,
    "css_value":                1,
    "dom":                      4,   # event-driven DOM has high exploitability
    "unknown":                  0,
}


def _rank_contexts(contexts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Sort reflection contexts by exploitability (most exploitable first).
    Ensures attribute/script contexts are tried before html_text.
    """
    return sorted(
        contexts,
        key=lambda c: _CONTEXT_RANK.get(c.get("context", "unknown"), 0),
        reverse=True,
    )


def _dom_sink_payloads(
    source_type: str,
    sink_capability: str,
    event_type: str,
) -> list[dict[str, Any]]:
    """
    Generate sink-specific, execution-context-aware payloads for DOM candidates.

    Delegates to the scenario synthesiser, which composes the payload from the
    sink's execution capability (markup / URL / JS / selector) and the source
    type rather than replaying a per-capability list. The previous table is
    kept as ``_dom_sink_payloads_legacy`` for reference and fallback.
    """
    from xscan.validation.payload_synthesis import dom_sink_payloads

    generated = dom_sink_payloads(source_type, sink_capability, event_type)
    if generated:
        return generated
    return _dom_sink_payloads_legacy(source_type, sink_capability, event_type)


def _dom_sink_payloads_legacy(
    source_type: str,
    sink_capability: str,
    event_type: str,
) -> list[dict[str, Any]]:
    """Static per-capability payload table — fallback when synthesis is empty."""
    candidates: list[dict[str, Any]] = []
    is_hash     = source_type == "hash"
    is_selector = "selector" in sink_capability
    is_html_inj = "html_injection" in sink_capability
    is_js_exec  = "js_execution" in sink_capability
    is_url_sink = "url_sink" in sink_capability
    is_event    = event_type in ("hashchange", "popstate", "message")

    prefix = "#" if is_hash else ""

    if is_selector:
        # jQuery $() interprets HTML when the string starts with <
        # The :contains() pattern means the value flows into the selector —
        # injecting HTML breaks out of the selector context
        candidates = [
            {"priority": 1,
             "payload": f"{prefix}<img src=x onerror=alert(1)>",
             "hypothesis": "jQuery selector interprets HTML — img tag with onerror",
             "expected_observation": "onerror event fires in browser",
             "rationale": "jQuery $() parses HTML when string starts with <",
             "generation_mode": "skill_candidate"},
            {"priority": 2,
             "payload": f"{prefix}<svg onload=alert(1)>",
             "hypothesis": "jQuery selector interprets SVG HTML",
             "expected_observation": "onload fires",
             "rationale": "SVG element injected via jQuery $() selector",
             "generation_mode": "skill_candidate"},
            {"priority": 3,
             "payload": f"{prefix}<iframe onload=alert(1)>",
             "hypothesis": "jQuery selector interprets iframe",
             "expected_observation": "onload fires",
             "rationale": "iframe injected via jQuery $() selector",
             "generation_mode": "skill_candidate"},
            {"priority": 4,
             "payload": f"{prefix}<script>alert(1)</script>",
             "hypothesis": "script tag injection via jQuery selector",
             "expected_observation": "script executes",
             "rationale": "direct script injection",
             "generation_mode": "skill_candidate"},
        ]
    elif is_html_inj:
        candidates = [
            {"priority": 1,
             "payload": f"{prefix}<img src=x onerror=alert(1)>",
             "hypothesis": "HTML injection into innerHTML/outerHTML",
             "expected_observation": "onerror fires",
             "rationale": "direct HTML tag injection",
             "generation_mode": "skill_candidate"},
            {"priority": 2,
             "payload": f"{prefix}<svg onload=alert(1)>",
             "hypothesis": "SVG injection",
             "expected_observation": "onload fires",
             "rationale": "SVG without closing tag",
             "generation_mode": "skill_candidate"},
        ]
    elif is_js_exec:
        # eval() / Function() / setTimeout(str) — hash value becomes JS code
        candidates = [
            {"priority": 1,
             "payload": f"{prefix}alert(1)",
             "hypothesis": "direct JS code injection into eval/Function",
             "expected_observation": "alert fires",
             "rationale": "source value used directly as code string",
             "generation_mode": "skill_candidate"},
            {"priority": 2,
             "payload": f"{prefix}1;alert(1)//",
             "hypothesis": "statement injection after arithmetic",
             "expected_observation": "alert fires after numeric literal",
             "rationale": "break arithmetic context then inject statement",
             "generation_mode": "skill_candidate"},
        ]
    elif is_url_sink:
        # href/src/action sinks: markup is inert inside a URI attribute, so the
        # payload has to be a scheme that executes when the element is activated.
        candidates = [
            {"priority": 1,
             "payload": "javascript:alert(document.cookie)",
             "hypothesis": "javascript: URI in a URL attribute",
             "expected_observation": "script runs when the element is clicked",
             "rationale": "URL attribute sink — needs a javascript: scheme, not markup",
             "generation_mode": "skill_candidate"},
            {"priority": 2,
             "payload": "javascript:alert(1)",
             "hypothesis": "javascript: URI (short)",
             "expected_observation": "alert fires on activation",
             "rationale": "alternative javascript: payload",
             "generation_mode": "skill_candidate"},
            {"priority": 3,
             "payload": "data:text/html,<script>alert(1)</script>",
             "hypothesis": "data: URI executes in a URL attribute",
             "expected_observation": "script runs after navigation",
             "rationale": "data: scheme fallback",
             "generation_mode": "skill_candidate"},
        ]
    else:
        # Generic DOM fallback
        candidates = [
            {"priority": 1,
             "payload": f"{prefix}<img src=x onerror=alert(1)>",
             "hypothesis": "generic HTML injection",
             "expected_observation": "onerror fires",
             "rationale": "fallback DOM payload",
             "generation_mode": "skill_candidate"},
        ]

    # Note for event-triggered sinks: the test URL must trigger the event
    # The validator uses the URL as-is for now; browser validation (Phase 10)
    # will handle the hashchange trigger properly
    if is_event and is_hash:
        for c in candidates:
            c["rationale"] += f" (requires {event_type} event trigger)"

    return candidates


def _extract_payloads_from_skills(skills_text: str, ep: dict[str, Any]) -> list[str]:
    """
    Extract individual payloads from skill markdown text.
    Only extracts payloads compatible with the encoding profile.
    """
    import re
    encoded = ep.get("encoded_chars", [])
    payloads: list[str] = []

    # Extract code blocks from skill markdown
    code_blocks = re.findall(r'```(?:javascript|js|html)?\s*\n(.*?)\n```', skills_text, re.DOTALL)
    for block in code_blocks:
        for line in block.splitlines():
            line = line.strip()
            # Skip comments, empty lines, long explanations
            if not line or line.startswith("//") or line.startswith("#") or len(line) > 200:
                continue
            # Skip payloads that require characters the server encodes
            skip = False
            for char in encoded:
                if char in line and char in ("<", ">"):
                    skip = True
                    break
            if not skip and any(
                kw in line.lower()
                for kw in ("alert", "confirm", "prompt", "onerror", "onload", "onfocus", "onmouseover")
            ):
                payloads.append(line)

    # Deduplicate, cap at 10 skill payloads
    seen: set[str] = set()
    result: list[str] = []
    for p in payloads:
        if p not in seen:
            seen.add(p)
            result.append(p)
        if len(result) >= 10:
            break
    return result
