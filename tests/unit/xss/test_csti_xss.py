"""
Tests for the AngularJS expression (CSTI) lab class and vendor-library noise.

Lab shape (PortSwigger "DOM XSS in AngularJS expression with angle brackets
and double quotes HTML-encoded"): the server reflects the `search` query value
into a page with an active ng-app scope, HTML-encoding < and >. The exploit is
a template expression — {{$on.constructor('alert(1)')()}} — evaluated by
Angular client-side on page load. Testing markup payloads here is a dead end;
detection requires probing reflection + ng-app together.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from xscan.core.scope.engine import ScopeEngine
from xscan.core.scope.policy import PolicyEngine
from xscan.nodes.analysis.dom_xss import (
    ANGULAR_CSTI_PAYLOADS,
    DomXssDetectorNode,
    _is_vendor_js,
    build_test_url,
)
from xscan.nodes.analysis.dompurify_scan import _system_browser_present
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


class TestVendorSkip:
    def test_angular_bundle_urls_are_skipped(self):
        assert _is_vendor_js("https://lab/js/angular.min.js", "")
        assert _is_vendor_js("https://lab/js/angular-1.8.2.js", "")
        assert _is_vendor_js("https://lab/vendor/jquery.min.js", "")

    def test_angular_internals_content_is_skipped(self):
        angular = 'function $$minErr(a){return function(){var b=arguments;}}window.angular={version:"1.8"}'
        assert _is_vendor_js("https://lab/bundle.js", angular)

    def test_application_code_is_not_skipped(self):
        assert not _is_vendor_js(
            "inline",
            'var el = document.getElementById("backLink");'
            '$("#backLink").attr("href", new URLSearchParams(location.search).get("returnPath"));',
        )


class TestCstiDetection:
    def test_reflected_ng_app_page_produces_csti_candidate(self, lab):
        param_url = lab.angular_url + "?search=xscProbe123"
        result = DomXssDetectorNode().execute(_ctx(
            target_url=lab.base + "/",
            urls=[lab.angular_url],
            urls_with_params=[param_url],
        ))
        csti = [c for c in result["dom_candidates"] if c.get("sink_kind") == "csti"]
        assert csti, "expected a CSTI candidate for the reflected ng-app page"
        c = csti[0]
        assert c["param"] == "search"
        assert c["best_payload"] == ANGULAR_CSTI_PAYLOADS[0]
        expected = build_test_url(lab.angular_url, "query", c["best_payload"], "search")
        assert c["best_test_url"] == expected
        assert "{{" in c["best_test_url"] or "%7B%7B" in c["best_test_url"]

    def test_crawler_expands_get_form_into_param_url(self, lab):
        """End-to-end discovery: a GET search form must reach dom_xss as a
        parameterised URL, or the ng-app reflection is never probed."""
        from xscan.nodes.crawler.discover import CrawlerNode

        crawl = CrawlerNode().execute(_ctx(target_url=lab.base + "/"))
        assert any(
            u.endswith("/angular?search=") for u in crawl["urls_with_params"]
        ), crawl["urls_with_params"]

        result = DomXssDetectorNode().execute(_ctx(
            target_url=lab.base + "/",
            urls=crawl["urls"],
            urls_with_params=crawl["urls_with_params"],
        ))
        csti = [c for c in result["dom_candidates"] if c.get("sink_kind") == "csti"]
        assert csti, "crawling the entry page must yield the ng-app CSTI candidate"
        assert csti[0]["param"] == "search"

    def test_non_angular_reflection_produces_no_csti(self, lab):
        result = DomXssDetectorNode().execute(_ctx(
            target_url=lab.base + "/",
            urls=[lab.base + "/", lab.feedback_url],
            urls_with_params=[lab.base + "/?search=xscProbe123"],
        ))
        assert not [c for c in result["dom_candidates"] if c.get("sink_kind") == "csti"]


class TestCstiFusionAndRouting:
    def test_fusion_carries_csti_capability(self):
        raw = DomXssDetectorNode()._build_csti_candidate(
            page_url="https://lab.net/", param="search", body="<body ng-app>",
        )
        fused = EvidenceFusionNode().execute(_ctx(
            dom_candidates=[raw], target_url="https://lab.net/",
        ))
        c = next(c for c in fused["fused_candidates"] if c["encoding_profile"].get("sink_kind") == "csti")
        assert c["xss_type"] == "dom"
        assert c["encoding_profile"]["sink_capability"] == "js_execution"
        assert c["best_payload"] == ANGULAR_CSTI_PAYLOADS[0]

    def test_csti_candidate_delegates_to_browser(self):
        scope = ScopeEngine.allow_all("TEST")
        engine = IterativeValidator(scope, PolicyEngine(), scan_id="TEST", no_llm=True)
        state = engine.run(
            url="https://lab.net/?search=x",
            parameter="search",
            method="GET",
            execution_semantics={
                "xss_type": "dom",
                "sink_capability": "js_execution",
                "sink_kind": "csti",
            },
        )
        assert state.status.value == "inconclusive"
        assert state.total_candidates == 0


@pytest.mark.skipif(
    not _system_browser_present(), reason="needs a system Chrome/Edge browser"
)
class TestCstiConfirm:
    def test_expression_executes_on_load(self, lab):
        """The browser loads the test URL; the template expression runs and
        the dialog hook records alert(1) with no click required."""
        raw = DomXssDetectorNode()._build_csti_candidate(
            page_url=lab.angular_url, param="search", body="<body ng-app>",
        )
        fused = EvidenceFusionNode().execute(_ctx(
            dom_candidates=[raw], target_url=lab.base + "/",
        ))
        result = DomConfirmNode().execute(_ctx(
            fused_candidates=fused["fused_candidates"],
        ))
        confirmation = next(
            c for c in result["dom_confirmations"] if c["sink_kind"] == "csti"
        )
        assert confirmation["dialog_fired"] is True
        assert any(d.get("type") == "alert" for d in confirmation["dialogs"])
        assert result["confirmed_count"] >= 1


class TestStoredUnknownContextGated:
    def test_unknown_context_reflection_is_not_a_candidate(self, lab):
        """A canary echoed back in an unclassifiable position (the lab's
        /post/comment echo) must not become a stored candidate."""
        comment_form = {
            "action":     lab.comment_action,
            "method":     "POST",
            "inputs":     [
                {"name": "comment", "type": "textarea", "value": ""},
                {"name": "name",    "type": "text",     "value": ""},
                {"name": "website", "type": "text",     "value": ""},
            ],
            "source_url": lab.comment_url,
        }
        result = StoredXssDetectorNode().execute(_ctx(
            target_url=lab.base + "/", urls=[], forms=[comment_form],
        ))
        assert not [
            c for c in result["stored_candidates"] if c.get("context") == "unknown"
        ]
