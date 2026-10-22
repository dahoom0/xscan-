"""
Scenario-driven payload synthesis tests.

These assert the engine *derives* payloads from the observed scenario: the
delivery class follows the sink, the breakout follows the quote/style, and no
payload uses a character the server was seen to encode or strip. Novel
scenarios (a context with no static entry) must still produce payloads.
"""
from __future__ import annotations

from xscan.validation.payload_synthesis import (
    Scenario,
    dom_sink_payloads,
    payloads_for_sink_kind,
    plan_for_context,
    scenario_from_evidence,
    synthesize,
)

# ---------------------------------------------------------------------------
# Delivery class follows the sink
# ---------------------------------------------------------------------------

def test_url_sink_prioritises_scheme_payloads():
    payloads = synthesize(
        Scenario(context="url_param", sink_kind="url_attribute", attribute="href")
    )

    assert payloads
    assert payloads[0].payload.startswith("javascript:")
    # Bare markup is inert inside a URL attribute and must not be offered.
    assert not any(p.payload.startswith("<img") for p in payloads)
    assert all(p.requires_browser for p in payloads)


def test_html_sink_yields_markup():
    payloads = [p.payload for p in synthesize(Scenario(context="html_text"))]

    assert any(p.startswith("<img") for p in payloads)


def test_js_sink_yields_code():
    payloads = [p.payload for p in synthesize(
        Scenario(context="script_expression", sink_kind="js_execution")
    )]

    assert any("<" not in p for p in payloads)
    assert any("alert(1)" in p for p in payloads)


def test_trigger_matches_delivery():
    url = synthesize(Scenario(context="url_param", sink_kind="url_attribute", attribute="href"))
    assert url[0].trigger == "click"

    markup = synthesize(Scenario(context="html_text"))
    assert markup[0].trigger == "load"


# ---------------------------------------------------------------------------
# Encoding constraints prune the payload space
# ---------------------------------------------------------------------------

def test_encoded_angles_disable_markup_payloads():
    plan = plan_for_context({"context": "html_text"}, {"encoded_chars": ["<", ">"]})

    assert plan["viable"] is False
    assert plan["test_cases"] == []


def test_encoded_quote_leaves_no_way_out_of_the_attribute():
    # A quoted attribute cannot be escaped without its quote.
    payloads = synthesize(
        Scenario(context="html_attribute", quote_type="double",
                 encoded_chars=['"'])
    )

    assert payloads == []


def test_quote_encoded_but_angles_raw_still_cannot_escape():
    # Closing the tag also needs the quote, so no payload is possible.
    payloads = synthesize(
        Scenario(context="html_attribute", quote_type="double",
                 encoded_chars=['"'], raw_chars=["<", ">"])
    )

    assert payloads == []


def test_raw_quote_allows_close_tag_markup_when_angles_raw():
    payloads = [p.payload for p in synthesize(
        Scenario(context="html_attribute", quote_type="double",
                 raw_chars=['"', "<", ">"])
    )]

    assert any(p.startswith('"><img') for p in payloads)


def test_encoded_parens_use_entity_fallback_in_html_context():
    payloads = [p.payload for p in synthesize(
        Scenario(context="html_attribute", quote_type="double",
                 encoded_chars=["(", ")"], raw_chars=['"'])
    )]

    assert payloads
    assert all("&#40;" in p for p in payloads), payloads


def test_encoded_parens_disable_script_context_payloads():
    """Entities do not decode inside <script>, so a call is impossible."""
    payloads = synthesize(
        Scenario(context="script_string_double", encoded_chars=["(", ")"]),
    )

    assert payloads == []


# ---------------------------------------------------------------------------
# Filters gate the obfuscated variants
# ---------------------------------------------------------------------------

def test_no_obfuscation_without_an_observed_filter():
    payloads = [p.payload for p in synthesize(
        Scenario(context="url_param", sink_kind="url_attribute", attribute="href")
    )]

    assert "javascript:alert(1)" in payloads
    assert not any("/*a*/" in p for p in payloads)
    assert not any("\t" in p for p in payloads)


def test_obfuscation_appears_when_a_filter_is_observed():
    payloads = [p.payload for p in synthesize(
        Scenario(context="url_param", sink_kind="url_attribute", attribute="href",
                 encoded_chars=["<"], raw_chars=[":", " "])
    )]

    assert any("/*a*/" in p for p in payloads)


# ---------------------------------------------------------------------------
# AngularJS
# ---------------------------------------------------------------------------

def test_angular_csti_from_sink_kind():
    plan = plan_for_context({"context": "html_text"}, {}, sink_kind="csti")

    assert plan["viable"]
    assert plan["breakout_strategy"] == "csti"
    assert plan["test_cases"][0]["payload"] == "{{$on.constructor('alert(1)')()}}"


def test_angular_from_technology_list():
    plan = plan_for_context({"context": "html_text"}, {}, technologies=["AngularJS"])

    assert plan["test_cases"][0]["category"] == "csti"


# ---------------------------------------------------------------------------
# Novel / unknown scenarios still synthesise
# ---------------------------------------------------------------------------

def test_unknown_context_still_produces_payloads():
    plan = plan_for_context({"context": "unknown"}, {})

    assert plan["viable"]
    assert len(plan["test_cases"]) >= 1


def test_novel_context_name_defaults_to_generic_families():
    """A context the tool has never seen is not left without payloads."""
    plan = plan_for_context({"context": "some-new-sink-2026"}, {})

    assert plan["viable"]
    assert plan["test_cases"]


# ---------------------------------------------------------------------------
# Evidence adapters and helpers
# ---------------------------------------------------------------------------

def test_scenario_from_evidence_infers_quote_and_sink():
    scenario = scenario_from_evidence(
        {"context": "html_attribute", "attribute": "href", "breakout_chars": ['"']},
        {},
    )

    assert scenario.quote_type == "double"
    assert scenario.sink_kind == "url_attribute"


def test_plan_shape_matches_planner_contract():
    plan = plan_for_context({"context": "html_text"}, {})

    for key in ("viable", "test_cases", "breakout_strategy", "reasoning",
                "context_interpretation", "encoding_interpretation",
                "estimated_confidence"):
        assert key in plan
    for case in plan["test_cases"]:
        assert {"priority", "payload", "expected_observation", "rationale"} <= set(case)


def test_payloads_for_sink_kind_are_family_appropriate():
    assert all(p.startswith(("javascript:", "data:")) for p in payloads_for_sink_kind("url_attribute"))
    assert any(p.startswith("<img") for p in payloads_for_sink_kind("html_text"))
    assert any(p.startswith("{{") for p in payloads_for_sink_kind("csti"))
    # A hashchange selector sink needs a print() variant too.
    selector = payloads_for_sink_kind("selector_hashchange", max_payloads=6)
    assert any("print()" in p for p in selector)
    assert any("alert(1)" in p for p in selector)


def test_dom_sink_payloads_prefix_hash_sources():
    candidates = dom_sink_payloads("hash", "selector", "hashchange")

    assert candidates
    assert all(c["payload"].startswith("#") for c in candidates)
    assert all("hashchange" in c["rationale"] for c in candidates)


def test_dom_sink_payloads_url_capability_is_uri_only():
    payloads = [c["payload"] for c in dom_sink_payloads("query", "url_sink", "")]

    assert payloads
    assert all(p.startswith(("javascript:", "data:")) for p in payloads)
