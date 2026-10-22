"""
AgentLoop — the core observe → reason → act → observe cycle.

The loop:
  1. Builds context from AgentState (condensed, bounded)
  2. Calls AgentPlannerSpecialist → AgentDecision (Pydantic-validated)
  3. Validates decision against scope + policy + capability + budget
  4. Executes the tool via HarnessToolRegistry
  5. Converts raw output to structured observation
  6. Stores evidence in EvidenceGraph
  7. Updates hypothesis based on observation
  8. Updates AgentState
  9. Decides whether to continue or terminate

The LLM cannot:
  - approve its own actions
  - modify scope
  - bypass policy
  - run indefinitely
  - claim confirmation without evidence
"""
from __future__ import annotations

import logging
import time
from typing import Any, Callable

from xscan.agent.decisions import AgentDecision, AgentDecisionError, DecisionType
from xscan.agent.experiment import Experiment, ExperimentStatus
from xscan.agent.harness_tool_registry import HarnessToolRegistry, harness_tool_registry
from xscan.agent.hypothesis import Hypothesis, HypothesisStatus
from xscan.agent.planner import AgentPlannerInput, AgentPlannerSpecialist
from xscan.agent.state import AgentState, AgentStatus
from xscan.core.scope.engine import ScopeEngine
from xscan.core.scope.policy import PolicyEngine
from xscan.errors import PolicyViolation
from xscan.evidence.graph import EvidenceGraph

logger = logging.getLogger(__name__)

ProgressCb = Callable[[str], None]


class AgentLoop:
    """
    The core agent loop.

    Usage::

        loop = AgentLoop(scope, policy, tool_registry, evidence_graph)
        state = loop.run(state)
    """

    def __init__(
        self,
        scope:          ScopeEngine,
        policy:         PolicyEngine,
        tool_registry:  HarnessToolRegistry | None = None,
        evidence_graph: EvidenceGraph | None = None,
        no_llm:         bool = False,
        progress_cb:    ProgressCb | None = None,
    ) -> None:
        self._scope    = scope
        self._policy   = policy
        self._tools    = tool_registry or harness_tool_registry
        self._evidence = evidence_graph
        self._no_llm   = no_llm
        self._progress = progress_cb or (lambda msg: None)
        self._planner  = AgentPlannerSpecialist()

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def run(self, state: AgentState) -> AgentState:
        """Execute the agent loop until a terminal state is reached."""
        t0 = time.monotonic()

        while True:
            state.elapsed_s = time.monotonic() - t0

            # Budget gate
            can_go, reason = state.can_continue()
            if not can_go:
                self._progress(f"  Agent budget exhausted: {reason}")
                state.exhaust(reason)
                break

            state.iteration += 1
            self._progress(
                f"  Agent iteration {state.iteration}  "
                f"({len(state.experiments)} experiments, "
                f"{state.requests_made} requests)"
            )

            # Build condensed context for LLM
            planner_input = self._build_context(state)

            # Get structured decision from LLM (or heuristic if no_llm)
            try:
                if self._no_llm:
                    decision = self._heuristic_decision(state)
                else:
                    decision = self._planner.decide(planner_input)
            except AgentDecisionError as exc:
                logger.warning("Agent planner invalid output: %s", exc)
                # One retry with heuristic
                decision = self._heuristic_decision(state)
            except Exception as exc:
                logger.error("Agent planner error: %s", exc)
                state.status = AgentStatus.ERROR
                break

            self._progress(
                f"    Decision: {decision.decision_type}  "
                f"reason={decision.reasoning[:60]!r}"
            )

            # Dispatch on decision type
            if decision.decision_type == DecisionType.FINAL:
                self._handle_final(state, decision)
                break

            elif decision.decision_type == DecisionType.ABANDON:
                state.reject(decision.abandon_reason)
                break

            elif decision.decision_type == DecisionType.ASK_APPROVAL:
                # Phase 1: auto-approve if risk is low, else mark for review
                tool_name = ""
                if decision.tool_call:
                    tool_name = decision.tool_call.tool
                tool = self._tools.get(tool_name) if tool_name else None
                if tool and tool.risk_level == "low":
                    self._progress(f"    Auto-approved (low risk): {tool_name}")
                    # Fall through to execute as tool_call
                    decision = AgentDecision(
                        decision_type=DecisionType.TOOL_CALL,
                        reasoning=decision.reasoning,
                        tool_call=decision.tool_call,
                    )
                else:
                    state.status = AgentStatus.APPROVAL_REQUIRED
                    state._log_decision("approval_required", {"reason": decision.approval_reason})
                    break

            if decision.decision_type == DecisionType.TOOL_CALL:
                if not decision.tool_call:
                    continue
                finished = self._execute_tool(state, decision)
                if state.status.is_terminal:
                    break
                if finished:
                    break

            elif decision.decision_type == DecisionType.CONTINUE_REASONING:
                # LLM wants to reason more — count as an iteration but no request
                self._progress("    Continuing reasoning...")

        state.elapsed_s = time.monotonic() - t0
        if not state.status.is_terminal:
            state.mark_inconclusive()

        return state

    # ------------------------------------------------------------------
    # Tool execution
    # ------------------------------------------------------------------

    def _execute_tool(self, state: AgentState, decision: AgentDecision) -> bool:
        """
        Execute a tool call. Returns True if investigation should stop.
        """
        tc        = decision.tool_call
        tool_name = tc.tool
        arguments = tc.arguments

        # Look up tool
        tool = self._tools.get(tool_name)
        if not tool:
            self._progress(f"    Unknown tool: {tool_name!r}")
            state.tool_failures += 1
            return False

        if not tool.available:
            self._progress(f"    Tool not available yet: {tool_name}")
            return False

        # Deduplication check
        fp = Experiment.compute_fingerprint(tool_name, arguments, state.active_hypothesis or "")
        if state.is_duplicate_experiment(fp):
            self._progress(f"    Duplicate experiment skipped: {tool_name}")
            return False

        # Scope check (for tools that need it)
        if tool.requires_scope and "url" in arguments:
            try:
                self._scope.assert_allowed(arguments["url"], operation="agent_tool")
            except PolicyViolation as exc:
                self._progress(f"    Scope blocked: {exc}")
                exp = Experiment(
                    hypothesis_id=tc.hypothesis_id or state.active_hypothesis or "",
                    iteration=state.iteration,
                    objective=tc.reason,
                    tool=tool_name,
                    arguments=arguments,
                    expected_observation=tc.expected_observation,
                    fingerprint=fp,
                )
                exp.block(str(exc))
                state.record_experiment(exp)
                state.log_decision(
                    state.iteration, "tool_call", tool_name, arguments,
                    False, f"scope_blocked: {exc}", ""
                )
                return False

        # Policy check
        if tool.requires_policy:
            try:
                self._policy.assert_permitted(
                    "http_request" if tool.capability == "http" else tool.capability,
                    {"node_type": "agent_investigation", "url": arguments.get("url", "")},
                )
            except PolicyViolation as exc:
                self._progress(f"    Policy blocked: {exc}")
                exp = Experiment(
                    hypothesis_id=tc.hypothesis_id or state.active_hypothesis or "",
                    iteration=state.iteration,
                    objective=tc.reason,
                    tool=tool_name,
                    arguments=arguments,
                    expected_observation=tc.expected_observation,
                    fingerprint=fp,
                )
                exp.block(str(exc))
                state.record_experiment(exp)
                state.log_decision(
                    state.iteration, "tool_call", tool_name, arguments,
                    False, f"policy_blocked: {exc}", ""
                )
                return False

        # Build experiment record
        exp = Experiment(
            hypothesis_id=tc.hypothesis_id or state.active_hypothesis or "",
            iteration=state.iteration,
            objective=tc.reason[:200],
            tool=tool_name,
            arguments=arguments,
            expected_observation=tc.expected_observation[:200],
            fingerprint=fp,
        )
        exp.start()

        # Execute tool
        self._progress(f"    Executing {tool_name} ...")
        raw_output: dict[str, Any] = {}
        t_start = time.monotonic()
        try:
            if tool.handler:
                raw_output = tool.handler(arguments, self._scope, self._policy)
            else:
                raw_output = {"error": "no handler"}
        except Exception as exc:
            logger.warning("Tool %s failed: %s", tool_name, exc)
            exp.fail(str(exc)[:200])
            state.record_experiment(exp)
            state.log_decision(
                state.iteration, "tool_call", tool_name, arguments,
                True, f"tool_failed: {exc}", ""
            )
            return False

        elapsed_ms = (time.monotonic() - t_start) * 1000

        # Build observation and evidence
        observation_summary = self._summarise_output(tool_name, raw_output)
        evidence_ids        = self._store_evidence(state.scan_id, tool_name, arguments, raw_output)

        # Complete experiment
        exp.complete(
            actual_observation=observation_summary,
            interpretation=self._interpret(raw_output, exp.expected_observation),
            evidence_ids=evidence_ids,
            raw_output=str(raw_output)[:500],
        )
        state.record_experiment(exp)
        state.evidence_ids.extend(evidence_ids)

        # Update hypothesis based on result
        hyp = state.get_active_hypothesis()
        hyp_update = ""
        if hyp and not hyp.is_terminal:
            hyp_update = self._update_hypothesis(hyp, tool_name, raw_output, evidence_ids)

        state.log_decision(
            state.iteration, "tool_call", tool_name, arguments,
            True, observation_summary, hyp_update
        )

        # Check if iterative validator confirmed
        if tool_name == "validator.iterative":
            if raw_output.get("validated"):
                payload = raw_output.get("best_payload", "")
                state.confirm(payload, evidence_ids)
                if hyp:
                    hyp.confirm(evidence_ids)
                self._progress(f"    CONFIRMED by validator: {payload[:60]!r}")
                return True

        self._progress(f"    Result: {observation_summary[:80]}")
        return False

    # ------------------------------------------------------------------
    # Context builder (bounded — never sends full history to LLM)
    # ------------------------------------------------------------------

    def _build_context(self, state: AgentState) -> AgentPlannerInput:
        hyp = state.get_active_hypothesis()
        recent_exps = state.experiments[-4:]

        skills_text = ""
        try:
            from xscan.skills import skill_manager
            skill_manager.load_all()
            techs = list(state.application_model.get("technologies", []))
            ctx   = hyp.context if hyp else ""
            skills_text = skill_manager.render(
                skill_manager.for_context(techs=techs, context=ctx, category="xss")
            )[:400]
        except Exception:
            pass

        budget_ok, budget_reason = state.can_continue()
        budget_info = (
            f"Iterations left: {state.budget.max_iterations - state.iteration}  "
            f"Experiments left: {state.budget.max_experiments - len(state.experiments)}  "
            f"Requests left: {state.budget.max_requests - state.requests_made}"
        )

        return AgentPlannerInput(
            scan_id=state.scan_id,
            investigation_summary=state.investigation_summary(),
            hypothesis_summary=hyp.summary() if hyp else "No active hypothesis",
            tools_summary=self._tools.tool_schema_summary(),
            recent_experiments="\n".join(e.summary() for e in recent_exps),
            skills_text=skills_text,
            budget_info=budget_info,
            hypothesis_id=hyp.id if hyp else "",
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _handle_final(self, state: AgentState, decision: AgentDecision) -> None:
        fin = decision.final
        if not fin:
            return
        if fin.status == "confirmed":
            # Final decision from LLM alone is NOT confirmed — needs evidence
            # Downgrade to validated if no browser evidence
            state.mark_inconclusive()
            state.decision_log.append({
                "kind": "llm_final_downgraded",
                "reason": "LLM claimed confirmation but no browser evidence yet",
                "llm_summary": fin.summary,
            })
            self._progress("    LLM claimed confirmed — marked INCONCLUSIVE (needs browser evidence)")
        elif fin.status == "rejected":
            state.reject(fin.reason)
        else:
            state.mark_inconclusive()

    def _heuristic_decision(self, state: AgentState) -> AgentDecision:
        """Fallback decision when LLM is unavailable."""
        from xscan.agent.decisions import ToolCall
        hyp = state.get_active_hypothesis()
        if not hyp or hyp.is_terminal:
            return AgentDecision(
                decision_type=DecisionType.FINAL,
                reasoning="No active hypothesis",
                final={"status": "inconclusive", "confidence": 0.0,
                       "reason": "no_llm mode", "evidence_ids": [], "summary": ""},
            )
        # Default: run iterative validator
        ca    = {}
        esem  = {}
        return AgentDecision(
            decision_type=DecisionType.TOOL_CALL,
            reasoning="Heuristic: run iterative validator",
            tool_call=ToolCall(
                tool="validator.iterative",
                arguments={
                    "url":                state.target_url,
                    "parameter":          state.parameter,
                    "context_analysis":   ca,
                    "execution_semantics":esem,
                },
                reason="Run bounded iterative validation",
                expected_observation="Reflected unencoded payload",
                hypothesis_id=hyp.id,
            ),
        )

    def _update_hypothesis(
        self, hyp: Hypothesis, tool_name: str, raw: dict, evidence_ids: list[str]
    ) -> str:
        if tool_name == "validator.reflect":
            if raw.get("reflected") and not raw.get("encoded"):
                hyp.support(evidence_ids[0] if evidence_ids else "", 0.2)
                return "reflected unencoded — hypothesis supported"
            elif raw.get("encoded"):
                hyp.contradict(evidence_ids[0] if evidence_ids else "", 0.05)
                return "encoded — slight contradiction"
            elif raw.get("stripped"):
                hyp.contradict(evidence_ids[0] if evidence_ids else "", 0.15)
                return "stripped — hypothesis weakened"
        elif tool_name == "js.analyse":
            paths = raw.get("taint_paths", [])
            if paths:
                hyp.support(evidence_ids[0] if evidence_ids else "", 0.3)
                return f"taint paths found ({len(paths)}) — hypothesis supported"
        return ""

    def _summarise_output(self, tool_name: str, raw: dict) -> str:
        if "error" in raw:
            return f"error: {raw['error'][:80]}"
        if tool_name == "http.get":
            return f"HTTP {raw.get('status_code')}  body_len={len(raw.get('body_snippet',''))}"
        if tool_name == "validator.reflect":
            status = ("REFLECTED" if raw.get("reflected") and not raw.get("encoded")
                      else "encoded" if raw.get("encoded")
                      else "stripped" if raw.get("stripped") else "not_reflected")
            return f"reflection={status}  status={raw.get('http_status')}"
        if tool_name == "validator.iterative":
            return f"validated={raw.get('validated')}  status={raw.get('status')}  payload={raw.get('best_payload','')[:40]!r}"
        if tool_name == "js.analyse":
            return (f"sources={len(raw.get('sources',[]))}  sinks={len(raw.get('sinks',[]))}  "
                    f"events={len(raw.get('events',[]))}  paths={len(raw.get('taint_paths',[]))}")
        return str(raw)[:120]

    def _interpret(self, raw: dict, expected: str) -> str:
        if "error" in raw:
            return f"Tool failed: {raw['error'][:80]}"
        return f"Observed vs expected: {expected[:60]!r}"

    def _store_evidence(
        self, scan_id: str, tool_name: str, arguments: dict, raw: dict
    ) -> list[str]:
        if not self._evidence:
            return []
        evidence_ids = []
        try:
            if tool_name in ("http.get", "validator.reflect"):
                url = arguments.get("url", raw.get("url_sent", ""))
                req_node = self._evidence.add_http_request(
                    url=url, method=arguments.get("method", "GET"), node_id="agent"
                )
                evidence_ids.append(req_node.id)
                status = raw.get("status_code", raw.get("http_status", 0))
                if status:
                    resp_node = self._evidence.add_http_response(
                        status_code=status, url=url,
                        body=raw.get("body_snippet", raw.get("snippet", ""))[:200],
                        parent_id=req_node.id, node_id="agent",
                    )
                    evidence_ids.append(resp_node.id)
        except Exception as exc:
            logger.debug("Evidence store failed: %s", exc)
        return evidence_ids
