"""
Tests for the stored-XSS pipeline — the PortSwigger "stored XSS into HTML
context" comment-form lab shape.

The lab: a comment form has a "Website" input; viewing the post renders the
website value inside an anchor href attribute, so ``javascript:alert(1)`` in
that input executes when a user clicks the commenter's name. Detecting it
requires (1) probing URL-shaped fields, not just the comment textarea,
(2) finding the canary on the post view that only exists after the POST,
(3) classifying the reflection as a url_param context, and (4) confirming it
in a browser by submitting the payload and clicking the poisoned link —
no HTTP response ever shows the execution.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from xscan.core.scope.engine import ScopeEngine
from xscan.core.scope.policy import PolicyEngine
from xscan.nodes.analysis.stored_xss import StoredXssDetectorNode
from xscan.nodes.validation.dom_confirm import DomConfirmNode
from xscan.nodes.xss.fusion import EvidenceFusionNode
from xscan.validation.iterative import IterativeValidator

from .dom_lab import LabServer


def _ctx(**inputs):
    ctx = MagicMock()
    ctx.scan_id, ctx.node_id, ctx.run_id = "TEST", "test-node", "RUN"
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


@pytest.fixture()
def comment_form(lab):
    """The comment form as the crawler would report it."""
    return {
        "action":     lab.comment_action,
        "method":     "POST",
        "inputs":     [
            {"name": "comment", "type": "textarea", "value": ""},
            {"name": "name",    "type": "text",     "value": ""},
            {"name": "website", "type": "text",     "value": ""},
        ],
        "source_url": lab.comment_url,
    }


def _website_candidate(candidates: list[dict]) -> dict:
    return next(c for c in candidates if c.get("parameter") == "website")


class TestStoredDetection:
    def test_website_field_href_sink_detected(self, lab, comment_form):
        """The website canary must be found on the post view, in an href."""
        result = StoredXssDetectorNode().execute(_ctx(
            target_url=lab.base + "/",
            urls=[lab.base + "/", lab.comment_url],
            forms=[comment_form],
        ))
        assert result["stored_candidate_count"] >= 1
        stored = _website_candidate(result["stored_candidates"])
        assert stored["sink_kind"] == "url_attribute"
        assert stored["context"] == "url_param"
        assert stored["method"] == "POST"
        assert stored["form_action"] == lab.comment_action
        # found_at is the per-post display page (from the POST redirect)
        assert stored["found_at"].startswith(lab.base + "/post/")
        # the reflection evidence names the anchor href attribute
        ca = stored["context_analysis"]
        assert ca["tag"] == "a"
        assert ca["attribute"] == "href"
        assert 'href="' in ca["snippet"]

    def test_every_free_text_input_is_probed(self, lab, comment_form):
        """Comment textarea must not shadow the website field."""
        result = StoredXssDetectorNode().execute(_ctx(
            target_url=lab.base + "/", urls=[], forms=[comment_form],
        ))
        params = {c["parameter"] for c in result["stored_candidates"]}
        assert "website" in params

    def test_url_shaped_fields_count_as_storage(self):
        node = StoredXssDetectorNode()
        assert node._looks_like_storage_form({
            "inputs": [{"name": "website", "type": "text"}],
        })
        assert node._looks_like_storage_form({
            "inputs": [{"name": "homepage", "type": "url"}],
        })

    def test_csrf_token_refreshed_before_post(self, lab, comment_form):
        """
        CSRF token from the crawl phase is stale; must be refreshed before
        each POST to avoid 400 errors. This test verifies that the detector
        completes successfully — failure would be a 400 on the POST attempt.
        """
        result = StoredXssDetectorNode().execute(_ctx(
            target_url=lab.base + "/",
            urls=[lab.comment_url],
            forms=[comment_form],
        ))
        # If CSRF refresh failed, we'd have 0 candidates (all POSTs rejected)
        # If refresh worked, we'd have at least the website field candidate
        assert result["stored_candidate_count"] >= 1


class TestStoredFusion:
    def test_stored_candidate_gets_href_semantics(self, lab, comment_form):
        detected = StoredXssDetectorNode().execute(_ctx(
            target_url=lab.base + "/", urls=[], forms=[comment_form],
        ))
        fused = EvidenceFusionNode().execute(_ctx(
            stored_candidates=detected["stored_candidates"],
            target_url=lab.base + "/",
        ))
        raw = _website_candidate(fused["fused_candidates"])
        assert raw["xss_type"] == "stored"
        assert raw["method"] == "POST"
        assert raw["stored_at"] == lab.comment_action
        # href sink -> javascript: URI payload + click interaction, so the
        # browser confirmer knows how to trigger it
        assert raw["best_payload"] == "javascript:alert(1)"
        assert raw["best_test_url"] == raw["found_at"]
        profile = raw["encoding_profile"]
        assert profile["xss_type"] == "stored"
        assert profile["sink_kind"] == "url_attribute"
        assert profile["sink_capability"] == "url_sink"
        assert profile["interaction"] == "click"
        # reflection context carried through for downstream classification
        ca = raw["context_analysis"]
        assert ca["context"] == "url_param"
        assert ca["attribute_name"] == "href"

    def test_stored_type_survives_candidate_roundtrip(self):
        from xscan.schemas.xss import XSSCandidate, XSSType
        c = XSSCandidate.from_dict({
            "xss_type": "stored", "url": "http://x/post/1",
            "parameter": "website", "method": "POST",
        })
        assert c.xss_type == XSSType.STORED
        assert c.method == "POST"


class TestStoredValidationRouting:
    def test_href_sink_stored_candidate_delegates_to_browser(self, lab):
        """HTTP validation cannot confirm a javascript: href — it must
        short-circuit without burning its request budget."""
        scope = ScopeEngine.allow_all("TEST")
        engine = IterativeValidator(scope, PolicyEngine(), scan_id="TEST", no_llm=True)
        state = engine.run(
            url=lab.base + "/post/0",
            parameter="website",
            method="POST",
            execution_semantics={
                "xss_type": "stored", "sink_kind": "url_attribute",
                "sink_capability": "url_sink",
            },
        )
        assert state.status.value == "inconclusive"
        assert state.total_candidates == 0  # no HTTP attempts wasted


@pytest.mark.skipif(
    not True, reason="needs a system Chrome/Edge browser"
)
class TestStoredConfirm:
    def test_end_to_end_post_click_alert(self, lab, comment_form):
        """
        Full chain: detector -> fusion -> browser confirm. The browser must
        submit the payload through the real form (the post view does not exist
        before the POST), land on the post page, and trigger the alert by
        clicking the commenter's name link.
        """
        detected = StoredXssDetectorNode().execute(_ctx(
            target_url=lab.base + "/", urls=[lab.comment_url],
            forms=[comment_form],
        ))
        fused = EvidenceFusionNode().execute(_ctx(
            stored_candidates=detected["stored_candidates"],
            target_url=lab.base + "/",
        ))

        result = DomConfirmNode().execute(_ctx(
            fused_candidates=fused["fused_candidates"],
        ))

        # Only the website (url_attribute) candidate is browser-relevant
        confirmation = next(
            c for c in result["dom_confirmations"]
            if c["param"] == "website"
        )
        assert confirmation["delivered"] is True
        assert confirmation["sink_kind"] == "url_attribute"
        assert confirmation["dialog_fired"] is True
        assert confirmation["triggered"], "the poisoned link was never clicked"
        dialogs = confirmation["dialogs"]
        assert any(d.get("type") == "alert" for d in dialogs)
        # alert(1) ran from the javascript: URL — the scheme is consumed by the
        # navigation, so the dialog records the argument, not the scheme.
        assert any(
            d.get("type") == "alert" and (d.get("args") or [])
            for d in dialogs
        )
        # DOM proof: an anchor href holds the javascript: payload
        dom_state = confirmation["dom_state"]
        assert any(
            entry["tag"] == "a" and entry["attribute"] == "href"
            and "javascript:" in entry["value"]
            for entry in dom_state
        )

        # The confirmed candidate flows back through validated_candidates
        confirmed_entry = next(
            v for v in result["validated_candidates"]
            if v.get("parameter") == "website"
        )
        assert confirmed_entry["validated"] is True
        assert confirmed_entry["confirmed"] is True
        assert confirmed_entry["validation_status"] == "confirmed"
        assert confirmed_entry["best_payload"] == "javascript:alert(1)"
        assert result["confirmed_count"] >= 1
