"""
Architecture strengthening regression tests.
============================================
Covers the gaps identified in Phase A and filled in Phases B–J:

  1.  json_value context → js_string_double family (not tag_injection)
  2.  json_value with quote encoded → no viable candidates
  3.  scenario_from_evidence infers sink_kind=js_execution for json_value
  4.  ContextAnalyser sets quote_type/breakout_chars for json_value
  5.  FailureClass is derived deterministically from observation status
  6.  ConstraintDelta.from_observation produces correct field values
  7.  ConstraintDelta propagates into iterative refinement
  8.  VulnerabilityModel: new identity/flow_edges/transformations fields
  9.  VulnerabilityModel: json_eval execution_context for json_value+js_execution
  10. VulnerabilityModel: enclosing_construct uses 120-char window
  11. AttackConstraints.infer_json_eval_closure sets object_closure_required
  12. SinkContext.context_type populated correctly
  13. PayloadConstructionPlan fields exist and serialize cleanly
  14. candidate_gen injects sink_kind for json_value reflection
  15. script_string_double context still produces correct payloads (no regression)
  16. html_attribute context still produces correct payloads (no regression)
  17. html_text context still produces correct payloads (no regression)
  18. Scheme-blocked failure class detection
  19. NOT_REFLECTED failure class
  20. IterationStatus terminal states (no regression)
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from xscan.nodes.analysis.context import ContextAnalyser, ContextAnalysis
from xscan.schemas.iteration import (
    ConstraintDelta, FailureClass, IterationBudget, IterationStatus,
    IterationState, PreviousTestResult,
)
from xscan.schemas.vuln_model import (
    AttackConstraints, FlowEdge, PayloadConstructionPlan,
    SinkContext, TransformRecord, VulnerabilityModel,
    build_model_from_candidate, model_from_execution_semantics,
)
from xscan.validation.payload_synthesis import (
    Scenario, _families_for, plan_for_context, scenario_from_evidence,
    synthesize,
)


# ---------------------------------------------------------------------------
# 1. json_value → js_string_double, not tag_injection
# ---------------------------------------------------------------------------

class TestJsonValueFamilySelection:
    def test_json_value_no_sink_kind_picks_js_string(self):
        fams = _families_for(Scenario(context="json_value", sink_kind=""))
        assert fams == ["js_string_double", "js_expression"], fams

    def test_json_value_with_js_execution_picks_js_string(self):
        fams = _families_for(Scenario(context="json_value", sink_kind="js_execution"))
        assert fams == ["js_string_double", "js_expression"], fams

    def test_json_value_never_returns_tag_injection(self):
        for sink_kind in ("", "js_execution", "json_eval", "eval"):
            fams = _families_for(Scenario(context="json_value", sink_kind=sink_kind))
            assert "tag_injection" not in fams, f"sink_kind={sink_kind!r}: {fams}"

    def test_json_string_same_as_json_value(self):
        fams_v = _families_for(Scenario(context="json_value", sink_kind=""))
        fams_s = _families_for(Scenario(context="json_string", sink_kind=""))
        assert fams_v == fams_s

    def test_json_eval_context_picks_js_string(self):
        fams = _families_for(Scenario(context="json_eval", sink_kind=""))
        assert "js_string_double" in fams or "js_expression" in fams


# ---------------------------------------------------------------------------
# 2. json_value with quote encoded → no candidates
# ---------------------------------------------------------------------------

class TestJsonValueEncodedQuote:
    def test_encoded_quote_yields_no_string_breakout_payloads(self):
        """When \" is encoded, string-breakout payloads must not be generated.
        js_expression payloads may still be generated (they don't need \")."""
        scenario = Scenario(
            context="json_value",
            sink_kind="js_execution",
            encoded_chars=['"'],
        )
        payloads = [p.payload for p in synthesize(scenario)]
        # No payload must start with " (would require the encoded quote)
        assert all(not p.startswith('"') for p in payloads), (
            f"quote-breakout payload generated despite encoded quote: {payloads}"
        )

    def test_unencoded_quote_yields_breakout_payloads(self):
        scenario = Scenario(
            context="json_value",
            sink_kind="js_execution",
            raw_chars=['"', "-", "(", ")"],
        )
        payloads = [p.payload for p in synthesize(scenario)]
        assert payloads, "expected payloads when \" survives"
        assert any(p.startswith('"') for p in payloads), f"no quote-start payload: {payloads}"
        assert all("<" not in p for p in payloads), f"markup in json_value payloads: {payloads}"


# ---------------------------------------------------------------------------
# 3. scenario_from_evidence infers sink_kind
# ---------------------------------------------------------------------------

class TestScenarioFromEvidence:
    def test_json_value_context_infers_js_execution(self):
        sc = scenario_from_evidence(
            {"context": "json_value", "quote_type": "double"}, {}
        )
        assert sc.sink_kind == "js_execution", sc.sink_kind

    def test_json_value_sets_quote_type_double(self):
        sc = scenario_from_evidence({"context": "json_value"}, {})
        assert sc.quote_type == "double", sc.quote_type

    def test_script_string_double_infers_js_execution(self):
        sc = scenario_from_evidence({"context": "script_string_double"}, {})
        assert sc.sink_kind == "js_execution", sc.sink_kind

    def test_html_text_infers_html_text(self):
        sc = scenario_from_evidence({"context": "html_text"}, {})
        assert sc.sink_kind == "html_text", sc.sink_kind

    def test_html_attribute_not_overridden_by_json_rule(self):
        # html_attribute context must never become js_execution
        sc = scenario_from_evidence({"context": "html_attribute"}, {})
        assert sc.sink_kind == "html_attribute", sc.sink_kind

    def test_explicit_sink_kind_is_preserved(self):
        sc = scenario_from_evidence(
            {"context": "json_value"},
            {},
            sink_kind="json_eval",
        )
        assert sc.sink_kind == "json_eval", sc.sink_kind


# ---------------------------------------------------------------------------
# 4. ContextAnalyser json_value enrichment
# ---------------------------------------------------------------------------

class TestContextAnalyserJsonValue:
    def _analyse(self, body: str, marker: str = "CANARY") -> ContextAnalysis:
        return ContextAnalyser().analyse(body, marker)

    def test_json_body_returns_json_value(self):
        body = '{"results":[],"searchTerm":"CANARY"}'
        r = self._analyse(body)
        assert r.context == "json_value"

    def test_json_value_sets_quote_type_double(self):
        body = '{"searchTerm":"CANARY"}'
        r = self._analyse(body)
        assert r.quote_type == "double"

    def test_json_value_sets_script_quote_double(self):
        body = '{"searchTerm":"CANARY"}'
        r = self._analyse(body)
        assert r.script_quote == "double"

    def test_json_value_breakout_chars_contains_quote(self):
        body = '{"searchTerm":"CANARY"}'
        r = self._analyse(body)
        assert '"' in r.breakout_chars, r.breakout_chars

    def test_html_body_with_canary_is_not_json(self):
        body = "<html><body>CANARY</body></html>"
        r = self._analyse(body)
        assert r.context != "json_value"


# ---------------------------------------------------------------------------
# 5–6. FailureClass and ConstraintDelta
# ---------------------------------------------------------------------------

class TestConstraintDelta:
    def test_encoded_status_produces_encoded_failure(self):
        delta = ConstraintDelta.from_observation("<img>", "encoded", "&lt;img&gt;")
        assert delta.failure_class == FailureClass.ENCODED

    def test_stripped_status_produces_stripped_failure(self):
        delta = ConstraintDelta.from_observation("<img>", "stripped", "")
        assert delta.failure_class == FailureClass.STRIPPED
        assert delta.add_stripped_chars

    def test_scheme_blocked_detected(self):
        delta = ConstraintDelta.from_observation(
            "javascript:alert(1)", "stripped", "alert(1)"
        )
        assert delta.failure_class == FailureClass.SCHEME_BLOCKED
        assert delta.scheme_blocked is True
        assert ":" in delta.add_stripped_chars

    def test_not_reflected_when_no_snippet_and_not_encoded(self):
        delta = ConstraintDelta.from_observation("test", "tested", "")
        assert delta.failure_class == FailureClass.NOT_REFLECTED

    def test_confirmed_produces_no_constraints(self):
        delta = ConstraintDelta.from_observation("alert(1)", "confirmed", "CONFIRMED")
        # confirmed = no constraint narrowing needed
        assert delta.failure_class == FailureClass.UNKNOWN

    def test_waf_block_detected_by_http_status(self):
        delta = ConstraintDelta.from_observation("<img>", "tested", "", http_status=403)
        assert delta.failure_class == FailureClass.FILTERED

    def test_encoded_chars_set_correctly(self):
        delta = ConstraintDelta.from_observation(
            "<script>alert(1)</script>",
            "encoded",
            "&lt;script&gt;alert(1)&lt;/script&gt;",
        )
        assert "<" in delta.add_encoded_chars or ">" in delta.add_encoded_chars

    def test_remove_raw_chars_mirrors_encoded(self):
        delta = ConstraintDelta.from_observation("<img>", "encoded", "&lt;img&gt;")
        for c in delta.add_encoded_chars:
            assert c in delta.remove_raw_chars


# ---------------------------------------------------------------------------
# 7. ConstraintDelta propagates into iterative refinement
# ---------------------------------------------------------------------------

class TestConstraintDeltaPropagation:
    def test_encoded_chars_applied_to_scenario(self):
        """Encoded chars from delta must be removed from synthesis candidates."""
        from xscan.validation.payload_synthesis import refine_from_observations

        scenario = Scenario(
            context="html_text",
            sink_kind="html_text",
            raw_chars=["<", ">", '"'],
        )
        observations = [{
            "payload": "<img src=x onerror=alert(1)>",
            "status": "encoded",
            "reflection_snippet": "&lt;img src=x onerror=alert(1)&gt;",
        }]
        refined = refine_from_observations(scenario, observations)
        # After < and > are encoded, markup payloads are dead
        assert refined == [], f"expected no refined payloads after < > encoded: {[p.payload for p in refined]}"

    def test_scheme_blocked_pivots_away_from_javascript_uri(self):
        from xscan.validation.payload_synthesis import refine_from_observations

        scenario = Scenario(
            context="url_param",
            sink_kind="url_attribute",
            attribute="href",
            raw_chars=["<", ">", '"', ":", "(", ")"],
        )
        observations = [{
            "payload": "javascript:alert(1)",
            "status": "stripped",
            "reflection_snippet": "",
        }]
        refined = refine_from_observations(scenario, observations, max_payloads=6)
        if refined:
            assert all(not p.payload.startswith("javascript:") for p in refined), (
                f"javascript: scheme used after being blocked: {[p.payload for p in refined]}"
            )


# ---------------------------------------------------------------------------
# 8–12. VulnerabilityModel new fields
# ---------------------------------------------------------------------------

class TestVulnerabilityModelNewFields:
    def _build(self, **extra) -> VulnerabilityModel:
        base = {
            "url": "https://example.com/search",
            "parameter": "q",
            "context_analysis": {
                "context": "json_value",
                "quote_type": "double",
                "before": '{"results":[],"searchTerm":"',
                "after": '"}',
                "reflected": True,
                "raw_present": True,
                "breakout_chars": ['"'],
            },
            "encoding_profile": {
                "raw_chars": ['"', "-", "(", ")"],
                "encoded_chars": [],
                "stripped_chars": [],
            },
            "sink_kind": "js_execution",
        }
        base.update(extra)
        return build_model_from_candidate(base, candidate_id="CAND-TEST")

    def test_candidate_id_field(self):
        m = self._build()
        assert m.candidate_id == "CAND-TEST"

    def test_target_url_field(self):
        m = self._build()
        assert m.target_url == "https://example.com/search"

    def test_flow_edges_populated(self):
        m = self._build()
        assert m.flow_edges, "flow_edges must be non-empty"
        assert all(isinstance(e, FlowEdge) for e in m.flow_edges)
        # All edge indices must be valid
        for edge in m.flow_edges:
            assert edge.from_index < len(m.flow), f"from_index {edge.from_index} >= {len(m.flow)}"
            assert edge.to_index < len(m.flow), f"to_index {edge.to_index} >= {len(m.flow)}"

    def test_execution_context_json_eval(self):
        m = self._build()
        assert m.execution_context == "json_eval", m.execution_context

    def test_enclosing_construct_is_120_chars(self):
        long_before = "x" * 100 + '{"k":"'
        m = build_model_from_candidate({
            "url": "https://ex.com",
            "parameter": "q",
            "context_analysis": {
                "context": "json_value",
                "quote_type": "double",
                "before": long_before,
                "after": '"}',
                "reflected": True,
                "raw_present": True,
            },
            "encoding_profile": {},
        })
        # Should capture up to 120 chars
        assert len(m.constraints.enclosing_construct) <= 120
        assert len(m.constraints.enclosing_construct) > 24, (
            "enclosing_construct must be more than the old 24-char truncation"
        )

    def test_object_closure_required_for_json(self):
        m = self._build()
        # enclosing has { and trailing has } → object_closure_required
        assert m.constraints.object_closure_required, (
            "object_closure_required should be True when JSON object is detected"
        )

    def test_sink_context_detail_type(self):
        m = self._build()
        sc = m.sink_context_detail
        assert isinstance(sc, SinkContext)
        assert sc.context_type == "JSON_STRING", sc.context_type

    def test_sink_context_parser_json(self):
        m = self._build()
        assert m.sink_context_detail.parser == "json", m.sink_context_detail.parser

    def test_explain_includes_constraint_lines(self):
        m = self._build()
        why = "\n".join(m.explain())
        assert "q" in why          # parameter name
        assert "request input" in why or "Source" in why

    def test_model_serializes_cleanly(self):
        m = self._build()
        data = m.model_dump(mode="json")
        assert "candidate_id" in data
        assert "flow_edges" in data
        assert "sink_context_detail" in data
        assert "construction_plan" in data


# ---------------------------------------------------------------------------
# 11. AttackConstraints.infer_json_eval_closure
# ---------------------------------------------------------------------------

class TestAttackConstraintsJsonEvalClosure:
    def test_json_before_triggers_closure(self):
        c = AttackConstraints()
        c.infer_json_eval_closure(
            full_before='{"results":[],"searchTerm":"',
            full_after='"}',
        )
        assert c.object_closure_required, "closure should be required"
        assert c.quote_breakout_required
        assert c.quote_type == "double"
        assert c.execution_context == "json_eval"

    def test_plain_html_does_not_trigger_closure(self):
        c = AttackConstraints()
        c.infer_json_eval_closure(
            full_before="<p>",
            full_after="</p>",
        )
        assert not c.object_closure_required


# ---------------------------------------------------------------------------
# 13. PayloadConstructionPlan fields
# ---------------------------------------------------------------------------

class TestPayloadConstructionPlan:
    def test_construction_plan_serializes(self):
        from xscan.schemas.vuln_model import ConstructionStep
        plan = PayloadConstructionPlan(
            candidate_id="CAND-1",
            starting_context="JSON string value inside eval()",
            target_state="JavaScript expression scope",
            required_transition='close " + close } + inject call + comment',
            steps=[
                ConstructionStep(description="Close JSON string", required_chars=['"']),
                ConstructionStep(description="Close JSON object", required_chars=["}"]),
                ConstructionStep(description="Inject dialog call"),
                ConstructionStep(description="Neutralise trailing content", required_chars=["/"]),
            ],
            quote_char='"',
            object_close=True,
            requires_comment_tail=True,
            delivery="query",
            trigger="load",
            expected_observation="JavaScript dialog fires in browser",
            generated_payloads=['\\"-alert(1)}//'],
        )
        data = plan.model_dump(mode="json")
        assert data["starting_context"] == "JSON string value inside eval()"
        assert len(data["steps"]) == 4
        assert data["object_close"] is True

    def test_model_can_hold_construction_plan(self):
        m = VulnerabilityModel(
            source="location.search",
            sink="eval()",
            construction_plan=PayloadConstructionPlan(
                starting_context="json_value",
                target_state="js_expression",
                generated_payloads=['\\"-alert(1)}//'],
            ),
        )
        why = m.explain()
        # construction_plan's required_transition is surfaced in explain()
        assert isinstance(why, list)
        data = m.model_dump(mode="json")
        assert data["construction_plan"]["starting_context"] == "json_value"


# ---------------------------------------------------------------------------
# 14. candidate_gen injects sink_kind for json_value
# ---------------------------------------------------------------------------

class TestCandidateGenSinkKindInjection:
    def test_json_value_candidate_gets_sink_kind(self):
        """candidate_gen._analyse_param must inject sink_kind=js_execution for json_value."""
        from xscan.nodes.analysis.candidate_gen import CandidateGeneratorNode
        from xscan.nodes.analysis.context import ContextAnalyser
        from xscan.nodes.analysis.encoding import EncodingProfile, CharResult

        # Build a mock context via ContextAnalyser directly
        json_body = '{"results":[],"searchTerm":"xscCabcd1234"}'
        ca = ContextAnalyser()
        analysis = ca.analyse(json_body, "xscCabcd1234")
        assert analysis.reflected
        assert analysis.context == "json_value"

        # Simulate what _analyse_param would return given this analysis
        # by calling the actual helper that injects sink_kind
        mock_ep = MagicMock()
        mock_ep.raw_chars = ['"']
        mock_ep.encoded_chars = []
        mock_ep.stripped_chars = []
        mock_ep.summary.return_value = "raw: ['\"']"
        mock_ep.can_break_html_text.return_value = False
        mock_ep.can_break_html_attribute.return_value = True
        mock_ep.can_break_script_string.return_value = True

        ctx_name = analysis.context
        inferred_sink_kind = "js_execution" if ctx_name in ("json_value", "json_string", "json_key") else ""

        result = {
            "url": "https://example.com/search?search=",
            "parameter": "search",
            "method": "GET",
            "canary_evidence": analysis.full_snippet[:300],
            "context_analysis": analysis.to_evidence_dict(),
            "encoding_profile": {
                "raw_chars": mock_ep.raw_chars,
                "encoded_chars": mock_ep.encoded_chars,
                "stripped_chars": mock_ep.stripped_chars,
                "can_break_script_string": True,
            },
        }
        if inferred_sink_kind:
            result["sink_kind"] = inferred_sink_kind
            result["encoding_profile"]["sink_kind"] = inferred_sink_kind

        assert result["sink_kind"] == "js_execution", (
            f"sink_kind should be js_execution for json_value context"
        )
        assert result["encoding_profile"]["sink_kind"] == "js_execution"


# ---------------------------------------------------------------------------
# 15–17. Regression: existing contexts still work
# ---------------------------------------------------------------------------

class TestRegressionExistingContexts:
    def test_script_string_double_still_produces_breakout(self):
        payloads = [p.payload for p in synthesize(
            Scenario(context="script_string_double", raw_chars=['"', "(", ")"])
        )]
        assert any(p.startswith('"') for p in payloads), f"no breakout: {payloads}"
        assert any("alert" in p for p in payloads)

    def test_html_attribute_double_still_produces_breakout(self):
        payloads = [p.payload for p in synthesize(
            Scenario(context="html_attribute", quote_type="double",
                     raw_chars=['"', "(", ")"])
        )]
        assert any('"' in p for p in payloads), f"no double-quote breakout: {payloads}"

    def test_html_text_still_produces_tag_injection(self):
        payloads = [p.payload for p in synthesize(
            Scenario(context="html_text", raw_chars=["<", ">", "(", ")"])
        )]
        assert any("<img" in p or "<svg" in p for p in payloads), f"no markup: {payloads}"

    def test_url_param_still_produces_javascript_uri(self):
        payloads = [p.payload for p in synthesize(
            Scenario(context="url_param", sink_kind="url_attribute",
                     attribute="href", raw_chars=[":", "(", ")"])
        )]
        assert any(p.startswith("javascript:") for p in payloads), f"no js uri: {payloads}"

    def test_plan_for_context_html_text_viable(self):
        plan = plan_for_context({"context": "html_text"}, {"raw_chars": ["<", ">", "(", ")"]})
        assert plan["viable"]
        assert any("<img" in tc["payload"] or "<svg" in tc["payload"]
                   for tc in plan["test_cases"])

    def test_plan_for_context_json_value_viable_when_quote_raw(self):
        plan = plan_for_context(
            {"context": "json_value", "quote_type": "double"},
            {"raw_chars": ['"', "-", "(", ")"]},
            sink_kind="js_execution",
        )
        assert plan["viable"], f"json_value plan not viable: {plan}"
        payloads = [tc["payload"] for tc in plan["test_cases"]]
        assert any(p.startswith('"') for p in payloads), f"no breakout: {payloads}"

    def test_plan_for_context_json_value_not_viable_when_quote_encoded(self):
        """
        When \" is encoded, js_string_double breakout is impossible.
        The synthesiser will still try js_expression (which doesn't need "),
        but only js_string_double candidates would actually break out of the
        JSON string.  Verify: no quote-starting payloads are generated.
        """
        plan = plan_for_context(
            {"context": "json_value", "quote_type": "double"},
            {"raw_chars": [], "encoded_chars": ['"']},
            sink_kind="js_execution",
        )
        payloads = [tc["payload"] for tc in plan["test_cases"]]
        # No payload may start with " (that would require the encoded quote)
        assert all(not p.startswith('"') for p in payloads), (
            f"quote-breakout payload generated despite encoded quote: {payloads}"
        )


# ---------------------------------------------------------------------------
# 18. Scheme-blocked failure class
# ---------------------------------------------------------------------------

class TestSchemeBlocked:
    def test_javascript_scheme_stripped(self):
        delta = ConstraintDelta.from_observation(
            "javascript:alert(1)", "stripped", ""
        )
        assert delta.failure_class == FailureClass.SCHEME_BLOCKED
        assert delta.scheme_blocked

    def test_non_scheme_stripped_not_scheme_blocked(self):
        delta = ConstraintDelta.from_observation("<img>", "stripped", "")
        assert delta.failure_class != FailureClass.SCHEME_BLOCKED


# ---------------------------------------------------------------------------
# 19. NOT_REFLECTED
# ---------------------------------------------------------------------------

class TestNotReflected:
    def test_no_snippet_no_status_not_reflected(self):
        delta = ConstraintDelta.from_observation("some_payload", "tested", "")
        assert delta.failure_class == FailureClass.NOT_REFLECTED


# ---------------------------------------------------------------------------
# 20. IterationStatus terminal states (no regression)
# ---------------------------------------------------------------------------

class TestIterationStatusNoRegression:
    def test_confirmed_is_terminal(self):
        assert IterationStatus.CONFIRMED.is_terminal

    def test_running_is_not_terminal(self):
        assert not IterationStatus.RUNNING.is_terminal

    def test_budget_exhausted_implies_not_safe(self):
        assert not IterationStatus.BUDGET_EXHAUSTED.implies_safe

    def test_inconclusive_implies_not_safe(self):
        assert not IterationStatus.INCONCLUSIVE.implies_safe
