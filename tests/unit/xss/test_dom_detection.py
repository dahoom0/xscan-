"""
Regression tests for DOM XSS detection.

Root causes these pin down (found against a PortSwigger lab — jQuery anchor href
sink fed by location.search):

  (a) dom-xss-detector analysed only the entry page, ignoring crawled URLs
  (b) the .attr('href', v) sink existed nowhere in the knowledge registry, so
      the flow was mislabelled "jQuery $()" and got an HTML payload that is
      inert inside an href attribute
  (c) test URLs invented a "q" parameter instead of using the parameter the page
      actually reads
  (d) tool_scan treated the substring "XSS" in XSStrike's own banner as a finding
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from xscan.core.scope.engine import ScopeEngine
from xscan.knowledge import xss_knowledge
from xscan.nodes.analysis.dom_xss import (
    DomXssDetectorNode,
    build_test_url,
    payloads_for_kind,
    resolve_sink_context,
)

from .dom_lab import LabServer


def _ctx(**inputs):
    ctx = MagicMock()
    ctx.scan_id, ctx.node_id, ctx.run_id = "TEST", "dom-xss-detector", "RUN"
    ctx.inputs = dict(inputs)
    ctx.config = inputs.pop("config", {})
    ctx.get = lambda key, default=None: ctx.inputs.get(key, default)
    ctx.scope = ScopeEngine.allow_all("TEST")
    ctx.policy = MagicMock()
    ctx.logger = MagicMock()
    ctx.no_llm = True
    return ctx


@pytest.fixture(scope="module")
def lab():
    server = LabServer()
    yield server
    server.close()


class TestCoverage:
    """The entry page alone is not enough — crawled pages must be analysed."""

    def test_entry_page_alone_finds_nothing(self, lab):
        result = DomXssDetectorNode().execute(_ctx(target_url=lab.base + "/"))

        assert result["dom_candidate_count"] == 0

    def test_crawled_pages_are_analysed(self, lab):
        result = DomXssDetectorNode().execute(
            _ctx(target_url=lab.base + "/", urls=[lab.feedback_url])
        )

        assert result["dom_candidate_count"] >= 1

    def test_jquery_ready_call_is_not_a_sink(self, lab):
        """$(function () {...}) only wires a ready handler — it taints nothing."""
        result = DomXssDetectorNode().execute(
            _ctx(target_url=lab.base + "/", urls=[lab.feedback_url])
        )

        sinks = [(c["sink"], c["sink_kind"]) for c in result["dom_candidates"]]
        assert sinks, "the real .attr('href') flow must still be reported"
        assert all(kind != "selector" for _, kind in sinks), sinks


class TestSinkContext:
    """Payload family and trigger come from the sink, not a (source, sink) pair."""

    def test_attribute_sink_is_modelled(self):
        sink = xss_knowledge.sink_by_label("jQuery .attr()")
        assert sink is not None, "knowledge/sinks.yaml must register the .attr() sink"

        context = resolve_sink_context(sink, "$('#backLink').attr('href', returnPath);")

        assert context.kind == "url_attribute"
        assert context.interaction == "click"
        assert context.attribute == "href"
        assert "href" in context.label

    def test_non_url_attribute_is_markup(self):
        sink = xss_knowledge.sink_by_label("jQuery .attr()")

        context = resolve_sink_context(sink, "$('#x').attr('title', tainted);")

        assert context.kind == "html_attribute"
        assert context.interaction == "none"

    def test_event_attribute_needs_the_event(self):
        sink = xss_knowledge.sink_by_label("jQuery .attr()")

        context = resolve_sink_context(sink, "$('#x').attr('onclick', tainted);")

        assert context.kind == "event_handler"
        assert context.interaction == "event"

    def test_url_sink_payloads_are_javascript_uris(self):
        payloads = payloads_for_kind("url_attribute")

        assert payloads
        assert all(p.startswith("javascript:") or p.startswith("data:") for p in payloads)

    def test_html_sink_payloads_are_markup(self):
        payloads = payloads_for_kind("html_text")

        assert any(p.startswith("<img") for p in payloads)


class TestDetectedCandidateShape:
    """The candidate must be actionable: right sink, right payload, right param."""

    @pytest.fixture(scope="class")
    def candidate(self, lab):
        result = DomXssDetectorNode().execute(
            _ctx(target_url=lab.base + "/", urls=[lab.feedback_url])
        )
        strong = [
            c for c in result["dom_candidates"]
            if c["sink_kind"] == "url_attribute"
        ]
        assert strong, (
            "the .attr('href') flow must be reported as a url_attribute sink, "
            f"got: {[(c['sink'], c['sink_kind']) for c in result['dom_candidates']]}"
        )
        return strong[0]

    def test_sink_and_trigger_are_recorded(self, candidate):
        assert "href" in candidate["sink"]
        assert candidate["interaction"] == "click"
        assert candidate["requires_browser"] is True

    def test_payload_matches_the_sink(self, candidate):
        assert candidate["best_payload"].startswith("javascript:")

    def test_payload_is_bound_to_the_real_parameter(self, candidate):
        assert candidate["param"] == "returnPath"
        assert "returnPath=" in candidate["best_test_url"]
        assert "q=" not in candidate["best_test_url"]

    def test_url_encoding_preserves_the_payload(self, lab):
        url = build_test_url(
            lab.feedback_url, "query", "javascript:alert(document.cookie)", "returnPath"
        )

        assert "returnPath=javascript%3Aalert%28document.cookie%29" in url

    def test_hash_sources_use_the_fragment(self, lab):
        url = build_test_url(lab.feedback_url, "hash", "<img src=x onerror=alert(1)>")

        assert url.endswith("#<img src=x onerror=alert(1)>")

    def test_page_url_spellings_are_one_page(self, lab):
        """Trailing slash and fragment spellings must not split the analysis."""
        from xscan.nodes.analysis.dom_xss import normalise_page_url

        assert normalise_page_url(lab.hash_url) == normalise_page_url(lab.hash_url + "/")
        assert normalise_page_url(lab.hash_url + "#x") == normalise_page_url(lab.hash_url)

    def test_hashchange_sink_is_resolved_with_trigger(self):
        """The jQuery hashchange lab: $() + hashchange needs a second navigation."""
        sink = xss_knowledge.sink_by_label("jQuery $()")

        context = resolve_sink_context(
            sink, "$(window).on('hashchange', function(){ ... $('#comments').html(v); })"
        )

        assert context.kind == "selector_hashchange"
        assert context.interaction == "event"
        assert "hashchange" in context.label

    def test_hashchange_payloads_include_print(self):
        payloads = payloads_for_kind("selector_hashchange")

        assert any("print()" in p for p in payloads)
        assert any("alert(1)" in p for p in payloads)

    def test_hashchange_page_is_detected_once(self, lab):
        """The /hash page crawled under two spellings yields ONE candidate."""
        result = DomXssDetectorNode().execute(
            _ctx(target_url=lab.base + "/", urls=[lab.hash_url, lab.hash_url + "/"])
        )

        candidates = [
            c for c in result["dom_candidates"]
            if c["sink_kind"] == "selector_hashchange"
        ]
        assert len(candidates) == 1
        assert candidates[0]["trigger_event"] == "hashchange"
        assert candidates[0]["best_test_url"].startswith(lab.hash_url + "#")


class TestValidatorGetsSinkContext:
    """Fusion must hand the validator the sink's capability and payload family."""

    def test_fused_dom_candidate_carries_capability_and_payloads(self, lab):
        from xscan.nodes.xss.fusion import EvidenceFusionNode

        detected = DomXssDetectorNode().execute(
            _ctx(target_url=lab.base + "/", urls=[lab.feedback_url])
        )
        fused = EvidenceFusionNode().execute(
            _ctx(dom_candidates=detected["dom_candidates"], target_url=lab.base + "/")
        )

        dom = [c for c in fused["fused_candidates"] if c["xss_type"] == "dom"]
        assert dom, "fusion must keep the DOM candidate"
        profile = dom[0]["encoding_profile"]
        assert profile["sink_kind"] == "url_attribute"
        assert profile["sink_capability"] == "url_sink"
        assert any(p.startswith("javascript:") for p in profile["payloads"])

    def test_url_sink_capability_yields_uri_payloads(self):
        """Regression: html fallback payloads are inert inside an href."""
        from xscan.validation.iterative import _dom_sink_payloads

        payloads = [c["payload"] for c in _dom_sink_payloads("query", "url_sink", "")]

        assert payloads
        assert all(p.startswith(("javascript:", "data:")) for p in payloads)


class TestToolScanNoise:
    """XSStrike's banner must not be reported as a finding."""

    @staticmethod
    def _run(stdout: str):
        from xscan.nodes.analysis import tool_scan as ts

        class _Result:
            returncode = 0
            stderr = ""

        _Result.stdout = stdout
        original = ts.subprocess.run
        ts.subprocess.run = lambda *a, **k: _Result()
        try:
            return ts.ToolXssScanNode()._run_xsstrike(
                Path("xsstrike.py"), "http://example.com/?q=1", _ctx()
            )
        finally:
            ts.subprocess.run = original

    def test_banner_only_is_not_a_candidate(self):
        from xscan.schemas.xss import ToolStatus

        obs = self._run(
            "XSStrike v3.1.5\n WAF Status: Offline\n"
            " Testing parameter: returnPath\n No ref"
        )

        assert obs.status == ToolStatus.NO_CANDIDATES
        assert obs.payloads == []

    def test_structured_payload_is_a_candidate(self):
        from xscan.schemas.xss import ToolStatus

        obs = self._run(
            "XSStrike v3.1.5\n[+] Payload: <img src=x onerror=alert(1)>\n"
        )

        assert obs.status == ToolStatus.CANDIDATE
        assert obs.payloads == ["<img src=x onerror=alert(1)>"]
