"""
Tests for dom-confirm — browser confirmation of DOM XSS candidates.

The lab pattern (anchor href sink fed by location.search) never executes on page
load: it needs the victim to click. These tests cover the full chain
detector -> fusion -> confirmation, and the failure semantics: a candidate that
does not execute must be reported as inconclusive evidence, never as a finding
and never as "safe".
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from xscan.core.scope.engine import ScopeEngine
from xscan.nodes.analysis.dom_xss import DomXssDetectorNode, build_test_url
from xscan.nodes.analysis.dompurify_scan import _system_browser_present
from xscan.nodes.validation.dom_confirm import DomConfirmNode
from xscan.nodes.xss.fusion import EvidenceFusionNode

from .dom_lab import LabServer

pytestmark = pytest.mark.skipif(
    not _system_browser_present(), reason="needs a system Chrome/Edge browser"
)


def _ctx(**inputs):
    ctx = MagicMock()
    ctx.scan_id, ctx.node_id, ctx.run_id = "TEST", "dom-confirm", "RUN"
    ctx.inputs = dict(inputs)
    ctx.inputs.pop("scope", None)
    ctx.config = {}
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


def _dom_candidate(url: str, payload: str, param: str = "returnPath") -> dict:
    return {
        "xss_type":    "dom",
        "url":         url,
        "parameter":   param,
        "best_payload": payload,
        "best_test_url": build_test_url(url, "query", payload, param),
        "encoding_profile": {
            "xss_type":    "dom",
            "sink":        "jQuery .attr() [href]",
            "sink_kind":   "url_attribute",
            "interaction": "click",
        },
        "confidence": "medium",
    }


class TestLabChain:
    def test_detected_then_confirmed_end_to_end(self, lab):
        detected = DomXssDetectorNode().execute(
            _ctx(target_url=lab.base + "/", urls=[lab.feedback_url])
        )
        assert detected["dom_candidate_count"] >= 1

        fused = EvidenceFusionNode().execute(
            _ctx(dom_candidates=detected["dom_candidates"], target_url=lab.base + "/")
        )
        assert fused["fused_count"] >= 1

        result = DomConfirmNode().execute(_ctx(fused_candidates=fused["fused_candidates"]))

        assert result["confirmed_count"] >= 1
        confirmation = next(c for c in result["dom_confirmations"] if c["confirmed"])
        assert confirmation["dialog_fired"] is True
        assert confirmation["sink_kind"] == "url_attribute"
        assert confirmation["triggered"], "the javascript: link must be clicked"
        assert any(
            "javascript:" in str(state.get("value", ""))
            for state in confirmation["dom_state"]
        ), "browser evidence must show the tainted href"

    def test_confirmed_candidate_carries_evidence(self, lab):
        candidate = _dom_candidate(
            lab.feedback_url, "javascript:alert(document.cookie)"
        )

        result = DomConfirmNode().execute(_ctx(fused_candidates=[candidate]))

        assert result["confirmed_count"] == 1
        confirmed = result["confirmed_candidates"][0]
        assert confirmed["confirmed"] is True
        assert confirmed["validated"] is True
        assert confirmed["validation_status"] == "confirmed"
        assert confirmed["browser_evidence"]["dialog_fired"] is True
        assert confirmed["browser_evidence"]["dom_state"]
        assert result["validated_candidates"]


class TestFailureSemantics:
    def test_sink_reached_without_execution_is_not_validated(self, lab):
        """An inert payload sitting in an href is evidence — never a finding."""
        candidate = _dom_candidate(lab.feedback_url, "<img src=x onerror=alert(1)>")

        result = DomConfirmNode().execute(_ctx(fused_candidates=[candidate]))

        assert result["confirmed_count"] == 0
        marked = result["validated_candidates"][0]
        assert marked["sink_reached"] is True, "the payload did reach the href"
        assert marked["validated"] is False, "reaching a sink is not execution"
        assert marked["validation_status"] == "inconclusive"
        assert result["validated_count"] == 0

    def test_page_without_the_sink_is_inconclusive(self, lab):
        candidate = _dom_candidate(lab.base + "/", "javascript:alert(document.cookie)")

        result = DomConfirmNode().execute(_ctx(fused_candidates=[candidate]))

        assert result["confirmed_count"] == 0
        assert result["dom_confirmations"][0]["note"]
        # Not confirmed is not "safe" — the attempt is preserved as evidence.
        assert result["validated_candidates"]

    def test_scope_blocked_candidate_is_not_confirmed(self, lab):
        ctx = _ctx(fused_candidates=[_dom_candidate(lab.feedback_url, "javascript:alert(1)")])
        blocking_scope = MagicMock()
        blocking_scope.assert_allowed = MagicMock(side_effect=RuntimeError("out of scope"))
        ctx.scope = blocking_scope

        result = DomConfirmNode().execute(ctx)

        assert result["confirmed_count"] == 0
        assert "scope_blocked" in result["dom_confirmations"][0]["note"]

    def test_existing_validation_results_are_preserved(self):
        existing = [{"url": "http://example.com/?q=1", "validated": True}]

        result = DomConfirmNode().execute(
            _ctx(validated_candidates=existing, fused_candidates=[])
        )

        assert result["validated_candidates"] == existing

    def test_non_dom_candidates_are_skipped(self, lab):
        reflected = {"xss_type": "reflected", "url": lab.feedback_url + "?q=1"}

        result = DomConfirmNode().execute(_ctx(fused_candidates=[reflected]))

        assert result["dom_confirmations"] == []


class TestHashchangeSink:
    """The jQuery hashchange lab: the fragment must CHANGE to execute."""

    @staticmethod
    def _hash_candidate(url: str, payload: str) -> dict:
        return {
            "xss_type":      "dom",
            "url":           url,
            "parameter":     "",
            "best_payload":  payload,
            "best_test_url": f"{url}#{payload}",
            "trigger_event": "hashchange",
            "encoding_profile": {
                "xss_type":      "dom",
                "sink":          "jQuery $() [hashchange]",
                "sink_kind":     "selector_hashchange",
                "source_type":   "hash",
                "interaction":   "event",
                "trigger_event": "hashchange",
            },
            "confidence": "medium",
        }

    def test_two_step_fragment_delivery_confirms(self, lab):
        candidate = self._hash_candidate(lab.hash_url, "<img src=x onerror=print()>")

        result = DomConfirmNode().execute(_ctx(fused_candidates=[candidate]))

        assert result["confirmed_count"] == 1, (
            f"hashchange trigger must fire: {result['dom_confirmations'][0]['note']}"
        )
        confirmation = result["dom_confirmations"][0]
        assert confirmation["confirmed"] is True
        assert confirmation["dialog_fired"] is True
        assert confirmation["trigger_event"] == "hashchange"

    def test_hash_event_is_replayed_when_first_navigation_misses(self, lab):
        """Defence in depth: a single navigation must still be retried in-page."""
        candidate = self._hash_candidate(lab.hash_url, "<img src=x onerror=alert('xscan')>")
        candidate["best_test_url"] = lab.hash_url  # fragment lost upstream
        candidate["url"] = lab.hash_url + "#<img src=x onerror=alert('xscan')>"

        result = DomConfirmNode().execute(_ctx(fused_candidates=[candidate]))

        confirmation = result["dom_confirmations"][0]
        assert result["confirmed_count"] == 0, (
            "no fragment was delivered, so nothing may be claimed as confirmed"
        )
        assert confirmation["note"]

    def test_http_validated_entry_is_replaced_not_duplicated(self, lab):
        http_entry = {
            "url":            lab.hash_url,
            "parameter":      "",
            "validated":      True,
            "validation_status": "budget_exhausted",
            "best_payload":   "<img src=x onerror=alert(1)>",
            "best_test_url":  lab.hash_url,
        }
        candidate = self._hash_candidate(lab.hash_url, "<img src=x onerror=alert(1)>")

        result = DomConfirmNode().execute(
            _ctx(validated_candidates=[http_entry], fused_candidates=[candidate])
        )

        entries = [
            v for v in result["validated_candidates"]
            if (v.get("best_test_url") or v.get("url", "")).split("#")[0].rstrip("/")
            == lab.hash_url
        ]
        assert len(entries) == 1, "browser result must replace the HTTP entry"
        assert entries[0]["validation_status"] == "confirmed"

    def test_duplicate_pages_are_confirmed_once(self, lab):
        """The same page crawled as /hash and /hash/ is one browser test."""
        cand_a = self._hash_candidate(lab.hash_url, "<img src=x onerror=print()>")
        cand_b = self._hash_candidate(lab.hash_url + "/", "<img src=x onerror=print()>")

        result = DomConfirmNode().execute(_ctx(fused_candidates=[cand_a, cand_b]))

        assert result["confirmed_count"] == 1
        assert len(result["dom_confirmations"]) == 1
