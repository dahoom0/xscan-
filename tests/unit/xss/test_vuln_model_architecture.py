"""
Architecture tests — synthesis from observed evidence, not payload tables
=========================================================================
These tests verify the REASONING LAYER, not specific payload strings:

  * the vulnerability model is built from real candidate evidence and can
    explain itself (source / flow / sink / constraints);
  * synthesis follows the classified execution context (different contexts
    produce structurally different candidates for the same sink);
  * enclosing-construct closure is derived from the OBSERVED reflection, not
    a lookup;
  * failure analysis converts observations into new constraints and the next
    candidate generation;
  * refinement is wired into the bounded iteration loop (no-LLM mode).

Known-lab regression tests (which DO pin exact payload strings) live in
test_csti_xss.py / test_dom_detection.py — those fixtures keep the reasoning
honest; these tests keep it general.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from xscan.core.scope.engine import ScopeEngine
from xscan.core.scope.policy import PolicyEngine
from xscan.schemas.iteration import IterationBudget
from xscan.schemas.vuln_model import (
    AttackConstraints,
    build_model_from_candidate,
    model_from_execution_semantics,
)
from xscan.validation import http as vhttp
from xscan.validation.iterative import IterativeValidator
from xscan.validation.payload_synthesis import (
    Scenario,
    refine_from_observations,
    synthesize_from_constraints,
)

from .dom_lab import LabServer


def _ctx(**inputs):
    ctx = MagicMock()
    ctx.scan_id, ctx.node_id, ctx.run_id = "TEST", "test-node", "RUN"
    ctx.inputs = dict(inputs)
    ctx.config = {}
    ctx.get = lambda key, default=None: ctx.inputs.get(key, default)
    ctx.scope = ScopeEngine.allow_all("TEST")
    ctx.policy = MagicMock()
    ctx.logger = MagicMock()
    ctx.no_llm = True
    return ctx


# ---------------------------------------------------------------------------
# Vulnerability model
# ---------------------------------------------------------------------------

class TestVulnerabilityModel:
    def test_model_records_only_observed_evidence(self):
        model = build_model_from_candidate({
            "source": "location.search",
            "parameter": "q",
            "sink": "jQuery .attr()",
            "sink_kind": "url_attribute",
            "sink_attribute": "href",
            "source_type": "query",
            "context_analysis": {
                "context": "url_param", "quote_type": "double",
                "before": 'href="', "after": '">Click',
            },
            "encoding_profile": {
                "raw_chars": ["<", ">", '"'], "encoded_chars": [],
                "summary": "no encoding observed",
            },
        })

        assert model.source == "location.search"
        assert model.source_parameter == "q"
        assert model.sink_argument == "href"
        assert model.execution_context == "url_valued_attribute"
        assert model.attacker_control == "confirmed"
        kinds = [s.kind for s in model.flow]
        assert kinds == ["source", "transformation", "sink"]

        why = model.explain()
        joined = "\n".join(why)
        # Every claim traces to the evidence above.
        assert "location.search[q]" in joined
        assert "href" in joined
        assert "Attacker control: confirmed" in joined

    def test_model_explains_encoding_constraints(self):
        model = build_model_from_candidate({
            "parameter": "q",
            "sink_kind": "html_attribute",
            "context_analysis": {"context": "html_attribute", "quote_type": "double"},
            "encoding_profile": {"raw_chars": [], "encoded_chars": ["<", ">"]},
        })
        joined = "\n".join(model.explain())
        assert "HTML-encodes: < >" in joined
        assert model.constraints.filtered is True
        assert model.attacker_control == "suspected"

    def test_dom_model_without_server_evidence_states_its_limits(self):
        model = model_from_execution_semantics(
            {"sink_kind": "selector", "sink_capability": "html_injection",
             "source_type": "hash"},
            parameter="",
        )
        assert model.source == "location.hash"
        assert model.attacker_control == "suspected"
        assert "never reaches the server" in "\n".join(model.encoding_notes)


# ---------------------------------------------------------------------------
# Constraint-driven synthesis
# ---------------------------------------------------------------------------

class TestConstraintDrivenSynthesis:
    def test_same_sink_different_context_produces_different_candidates(self):
        """The delivery class follows the execution context, not a type label."""
        json_ctx = AttackConstraints(
            sink_kind="js_execution", execution_context="js_string",
            quote_type="double",
            enclosing_construct='JSON.parse("{"', trailing_construct='}")',
            raw_chars=list("<>()"),
        )
        markup_ctx = AttackConstraints(
            sink_kind="html_text", execution_context="markup",
            raw_chars=list('<>"()'),
        )
        json_payloads = [p.payload for p in synthesize_from_constraints(json_ctx)]
        markup_payloads = [p.payload for p in synthesize_from_constraints(markup_ctx)]

        assert json_payloads, "JSON context must synthesise candidates"
        assert markup_payloads, "markup context must synthesise candidates"
        # Structurally different: closure syntax vs elements.
        assert all(p.startswith('"') for p in json_payloads[:1])
        assert any(p.startswith("<img") or p.startswith("<svg") for p in markup_payloads)
        # The JSON-context candidates never inject bare markup.
        assert not any(p.startswith("<") for p in json_payloads)

    def test_construct_closure_derived_from_observed_reflection(self):
        """A coherent JSON-object reflection must produce closure syntax that
        terminates the string AND the object before executing."""
        constraints = AttackConstraints(
            sink_kind="js_execution", execution_context="js_string",
            quote_type="double",
            enclosing_construct='JSON.parse("{"', trailing_construct='}")',
            raw_chars=list('"()'),
        )
        payloads = [p.payload for p in synthesize_from_constraints(constraints)]
        assert payloads, "closure candidate must be synthesised"
        first = payloads[0]
        assert first.startswith('"'), "must terminate the observed quote"
        assert "alert(1)" in first, "must contain the execution call"
        assert "}" in first, "must close the observed object construct"

    def test_no_candidates_when_required_chars_are_encoded(self):
        constraints = AttackConstraints(
            sink_kind="js_execution", execution_context="js_string",
            quote_type="double", raw_chars=[], encoded_chars=list('"()'),
        )
        payloads = synthesize_from_constraints(constraints)
        assert payloads == [], "no viable payload when every escape char is encoded"

    def test_context_specific_candidates_respect_their_constraints(self):
        c = AttackConstraints(
            sink_kind="html_attribute", execution_context="attribute",
            quote_type="double", raw_chars=list('"'),
            encoded_chars=list("<>"),
        )
        payloads = [p.payload for p in synthesize_from_constraints(c)]
        assert payloads, "attribute breakout must be viable without angle brackets"
        assert all("<" not in p for p in payloads), "never uses an encoded char"


# ---------------------------------------------------------------------------
# Failure-driven refinement
# ---------------------------------------------------------------------------

class TestFailureRefinement:
    def test_snippet_diff_identifies_exactly_the_encoded_chars(self):
        scenario = Scenario(context="html_text", sink_kind="html_text")
        refined = refine_from_observations(scenario, [{
            "payload": "<img src=x onerror=alert(1)>",
            "status": "encoded",
            "reflection_snippet": "&lt;img src=x onerror=alert(1)&gt;",
        }], max_payloads=3)
        # Markup is provably dead here: refinement must produce nothing rather
        # than another markup candidate.
        assert refined == []

    def test_refinement_narrows_to_surviving_vectors(self):
        scenario = Scenario(
            context="html_attribute", sink_kind="html_attribute",
            quote_type="double", raw_chars=list('"'),
        )
        payloads = refine_from_observations(scenario, [{
            "payload": '"><img src=x onerror=alert(1)>',
            "status": "encoded",
            # Server encoded ONLY the angle brackets — the quote survived raw.
            "reflection_snippet": '"&gt;&lt;img src=x onerror=alert(1)&gt;',
        }], max_payloads=4)
        # The quote survived raw, so attribute breakouts remain viable while
        # tag injection is gone.
        assert payloads
        assert all("<" not in p.payload for p in payloads)

    def test_no_failure_produces_no_refinement(self):
        scenario = Scenario(context="html_text", sink_kind="html_text")
        assert refine_from_observations(scenario, [
            {"payload": "<img src=x onerror=alert(1)>", "status": "confirmed"},
        ]) == []


class TestIterationWiresRefinement:
    """The bounded loop must USE observations, not just record them."""

    @pytest.fixture()
    def engine(self):
        return IterativeValidator(
            ScopeEngine.allow_all("T"), PolicyEngine(),
            budget=IterationBudget(
                max_iterations=3, max_candidates_per_iteration=3,
                max_total_candidates=9, stop_on_confirmation=True,
            ),
            scan_id="T", no_llm=True,
        )

    @staticmethod
    def _encoded_obs(payload: str) -> object:
        from types import SimpleNamespace
        return SimpleNamespace(
            duration_ms=1.0, http_status=200,
            payload_reflected=True, payload_encoded=True, payload_stripped=False,
            response_changed=True, reflection_context="html_attribute",
            reflection_snippet="", error="",
            confirmed=False, promising=False,
        )

    def test_all_encoded_stops_without_new_candidates(self, engine, monkeypatch):
        monkeypatch.setattr(vhttp.HTTPValidator, "execute", lambda self, **kw: self._encoded_obs("x"))
        monkeypatch.setattr(vhttp.HTTPValidator, "_encoded_obs", classmethod(
            lambda cls, payload: TestIterationWiresRefinement._encoded_obs(payload)
        ), raising=False)
        state = engine.run(
            url="http://lab.test/?q=x", parameter="q", method="GET",
            context_analysis={"context": "html_attribute", "quote_type": "double"},
            encoding_profile={"raw_chars": ['"', "<", ">"]},
        )
        assert state.total_candidates == 3
        assert state.status.value == "inconclusive"

    def test_refinement_pivots_when_scheme_is_blocked(self, engine, monkeypatch):
        """Failure analysis must CHANGE the constraint set: a blocked javascript:
        candidate teaches the loop the scheme is unavailable, so the next
        generation comes from a different delivery family."""
        from types import SimpleNamespace

        seen: list[str] = []

        def fake_execute(self, **kw):
            payload = kw["payload"]
            seen.append(payload)
            # javascript: reaches the server intact but is normalized to inert:
            # reflected, not encoded, never executes.
            return SimpleNamespace(
                duration_ms=1.0, http_status=200,
                payload_reflected=True, payload_encoded=False,
                payload_stripped=bool(payload.startswith("javascript:")),
                response_changed=True, reflection_context="url_param",
                reflection_snippet=f'<a href="{payload}">x</a>'
                if payload.startswith("javascript:") else f'<a href="x">{payload}</a>',
                error="", confirmed=False, promising=False,
            )

        monkeypatch.setattr(vhttp.HTTPValidator, "execute", fake_execute)
        state = engine.run(
            url="http://lab.test/?q=x", parameter="q", method="GET",
            context_analysis={"context": "url_param", "quote_type": "double",
                              "attribute": "href"},
            encoding_profile={"raw_chars": ['<', '>', '"', ":"]},
        )
        it1 = [a.payload for a in state.all_attempts if a.iteration == 1]
        it2 = [a.payload for a in state.all_attempts if a.iteration == 2]
        assert it1, "iteration 1 must test the initial plan"
        assert it2, "iteration 2 must test candidates refined from the failure"
        assert set(it1).isdisjoint(it2), "refinement must not repeat failed payloads"
        javascript_tried = [p for p in it1 if p.startswith("javascript:")]
        assert javascript_tried, "iteration 1 must have tried the scheme"
        # After the scheme was stripped, no later candidate repeats it.
        assert all(not p.startswith("javascript:") for p in it2), (
            "failure analysis must exclude the blocked scheme from later generations"
        )


# ---------------------------------------------------------------------------
# End-to-end on the reflected-DOM lab fixture
# ---------------------------------------------------------------------------

class TestReflectedDomLab:
    """
    The lab class "reflected DOM XSS": the server reflects ?search= into a JSON
    object literal embedded in an inline script that the page then eval()s.

    The static DOM detector legitimately finds nothing here — the page's JS
    never reads location.search (the server reflects INTO the script) — so the
    flow is discovered by the reflection pipeline: crawler expands the GET
    form -> candidate-gen classifies the reflection context (script_string)
    -> the synthesiser builds construct-closure candidates from that context.
    """

    @pytest.fixture(scope="class")
    def lab(self):
        server = LabServer()
        yield server
        server.close()

    def test_crawler_expands_search_form(self, lab):
        from xscan.nodes.crawler.discover import CrawlerNode

        crawl = CrawlerNode().execute(_ctx(target_url=lab.base + "/"))
        assert any(u.endswith("/search?search=") for u in crawl["urls_with_params"])

    def test_reflection_pipeline_classifies_script_context_and_synthesises(self, lab):
        """The full discovery->classification->synthesis chain for this lab."""
        from xscan.nodes.analysis.candidate_gen import CandidateGeneratorNode
        from xscan.nodes.crawler.discover import CrawlerNode

        crawl = CrawlerNode().execute(_ctx(target_url=lab.base + "/"))
        result = CandidateGeneratorNode().execute(_ctx(
            target_url=lab.base + "/",
            urls_with_params=crawl["urls_with_params"],
            forms=crawl["forms"],
        ))
        candidates = result["xss_candidates"]
        assert candidates, "reflection analysis must produce candidates"
        # The search reflection is classified INSIDE the script's JSON string.
        json_cands = [
            c for c in candidates
            if c.get("parameter") == "search"
            and str((c.get("context_analysis") or {}).get("context", "")).startswith("script_string")
        ]
        assert json_cands, (
            "search reflection must be classified as a script string: "
            f"{[(c.get('parameter'), (c.get('context_analysis') or {}).get('context')) for c in candidates]}"
        )
        ca = json_cands[0]["context_analysis"]
        assert ca.get("before") or ca.get("after"), "enclosing construct must be captured"

        # Synthesis from that classification yields closure-style candidates —
        # NOT markup (which is inert inside a JS string).
        from xscan.validation.payload_synthesis import plan_for_context

        plan = plan_for_context(ca, json_cands[0].get("encoding_profile") or {},
                                sink_kind="js_execution", source_type="query")
        assert plan["viable"]
        payloads = [tc["payload"] for tc in plan["test_cases"]]
        assert payloads
        assert all(not p.lstrip().startswith("<img") for p in payloads), (
            "markup must not be the delivery class for a script-string reflection"
        )

    def test_static_dom_detector_finds_nothing_here_by_design(self, lab):
        """No source->sink JS flow exists (server-side reflection into script);
        asserting this keeps the two detection pipelines honest."""
        from xscan.nodes.analysis.dom_xss import DomXssDetectorNode
        from xscan.nodes.crawler.discover import CrawlerNode

        crawl = CrawlerNode().execute(_ctx(target_url=lab.base + "/"))
        result = DomXssDetectorNode().execute(_ctx(
            target_url=lab.base + "/",
            urls=crawl["urls"],
            urls_with_params=crawl["urls_with_params"],
        ))
        eval_candidates = [
            c for c in result["dom_candidates"]
            if "eval" in str(c.get("sink", "")).lower()
            and str(c.get("sink", "")).startswith("eval")
            and c.get("param") == "search"
        ]
        assert not eval_candidates

    def test_model_explains_the_reflected_flow(self, lab):
        """A candidate for this lab produces a WHY explanation from evidence."""
        from xscan.nodes.analysis.candidate_gen import CandidateGeneratorNode
        from xscan.nodes.crawler.discover import CrawlerNode

        crawl = CrawlerNode().execute(_ctx(target_url=lab.base + "/"))
        result = CandidateGeneratorNode().execute(_ctx(
            target_url=lab.base + "/",
            urls_with_params=crawl["urls_with_params"],
            forms=crawl["forms"],
        ))
        c = next(
            c for c in result["xss_candidates"]
            if (c.get("param") or c.get("parameter")) == "search"
            and str((c.get("context_analysis") or {}).get("context", "")).startswith("script_string")
        )
        c["sink"] = "eval()"          # the sink the page actually applies
        model = build_model_from_candidate(c)
        why = "\n".join(model.explain())
        assert "search" in why
        assert model.flow, "flow must be reconstructed"
        assert model.constraints.enclosing_construct, "enclosing construct from reflection evidence"
