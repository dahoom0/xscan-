"""
Tests for the dompurify-scan node.

Regression context: DOMPurify could be cloned but was never part of the scan
pipeline, and ``tool-xss-scan`` only knew XSStrike/dalfox. These tests pin the
node's contracts: it must not drop other tools' observations, it must include
candidate payloads alongside the built-in probes, and its danger detection must
flag exactly the active content that sanitization is supposed to remove.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest


def _make_ctx(**inputs):
    ctx = MagicMock()
    ctx.scan_id = "TEST"
    ctx.node_id = "dompurify-scan"
    ctx.run_id = "RUN-TEST"
    ctx.config = inputs.pop("config", {})
    ctx.inputs = dict(inputs)
    ctx.get = lambda key, default=None: ctx.inputs.get(key, default)

    from xscan.core.scope.engine import ScopeEngine
    ctx.scope = ScopeEngine.allow_all("TEST")

    from xscan.core.scope.policy import PolicyEngine
    ctx.policy = PolicyEngine()
    ctx.logger = MagicMock()
    ctx.no_llm = True
    return ctx


class TestRegistration:
    def test_node_type_is_registered(self):
        import xscan.nodes.registry  # noqa: F401 — imports register node types
        from xscan.core.dag.node_registry import registry

        assert registry.is_registered("dompurify-scan")


class TestSoftSkip:
    def test_missing_install_returns_no_observations(self, monkeypatch, tmp_path):
        from xscan.nodes.analysis import dompurify_scan

        monkeypatch.setattr(dompurify_scan, "_TOOLS_DIR", tmp_path)
        node = dompurify_scan.DomPurifyScanNode()
        existing = [{"tool": "dalfox", "payloads": ["<svg onload=alert(1)>"]}]
        ctx = _make_ctx(target_url="http://example.com/", tool_observations=existing)

        result = node.execute(ctx)

        assert result["dompurify_observations"] == []
        assert result["dompurify_usage"]["available"] is False
        # Other tools' observations must survive untouched.
        assert result["tool_observations"] == existing


class TestPayloadCollection:
    def test_candidate_payloads_and_probes_are_merged_and_deduped(self):
        from xscan.nodes.analysis.dompurify_scan import DomPurifyScanNode

        shared = "<img src=x onerror=alert(1)>"
        ctx = _make_ctx(
            xss_candidates=[
                {"url": "http://example.com/?q=1", "best_payload": shared},
            ],
        )

        payloads = DomPurifyScanNode._collect_payloads(ctx)

        assert shared in payloads
        assert "<script>alert(1)</script>" in payloads
        assert payloads.count(shared) == 1
        assert len(payloads) == len(set(payloads))

    def test_max_payloads_config_is_respected(self):
        from xscan.nodes.analysis.dompurify_scan import DomPurifyScanNode

        ctx = _make_ctx(config={"max_payloads": 3})

        assert len(DomPurifyScanNode._collect_payloads(ctx)) == 3

    def test_payloads_are_pulled_from_tool_observations(self):
        from xscan.nodes.analysis.dompurify_scan import DomPurifyScanNode

        ctx = _make_ctx(
            xss_candidates=[{
                "url": "http://example.com/?q=1",
                "tool_observations": [{"payloads": ["<svg/onload=alert(1)>"]}],
            }],
        )

        assert "<svg/onload=alert(1)>" in DomPurifyScanNode._collect_payloads(ctx)


class TestTestUrlCollection:
    def test_candidate_urls_and_params_are_combined(self):
        from xscan.nodes.analysis.dompurify_scan import DomPurifyScanNode

        ctx = _make_ctx(
            xss_candidates=[{"best_test_url": "http://example.com/?q=1"}],
            urls_with_params=["http://example.com/?name=2", "http://example.com/?q=1"],
        )

        urls = DomPurifyScanNode._collect_test_urls(ctx)

        assert urls == ["http://example.com/?q=1", "http://example.com/?name=2"]


class TestResultClassification:
    """Sanitized output is judged on the parsed DOM, not on raw strings."""

    @staticmethod
    def _classify(results):
        from xscan.nodes.analysis.dompurify_scan import DomPurifyScanNode

        return DomPurifyScanNode._classify_results(results)

    def test_active_content_in_sanitized_dom_is_a_survivor(self):
        survivors, details = self._classify([{
            "payload": "<img src=x onerror=alert(1)>",
            "sanitized": "<img src=x onerror=alert(1)>",
            "active": ["img@onerror"],
        }])

        assert survivors == ["<img src=x onerror=alert(1)>"]
        assert details[0]["survived"] is True
        assert details[0]["active"] == ["img@onerror"]

    def test_inert_text_is_not_a_survivor(self):
        """Regression: DOMPurify cannot strip a URL scheme that is plain text."""
        survivors, details = self._classify([{
            "payload": "javascript:alert(1)",
            "sanitized": "javascript:alert(1)",
            "active": [],
        }])

        assert survivors == []
        assert details[0]["survived"] is False

    def test_neutralised_payload_is_not_a_survivor(self):
        survivors, details = self._classify([{
            "payload": "<script>alert(1)</script>",
            "sanitized": "",
            "active": [],
        }])

        assert survivors == []
        assert details[0]["sanitized"] == ""

    def test_probe_errors_are_recorded_not_treated_as_safe(self):
        survivors, details = self._classify([{
            "payload": "<svg onload=alert(1)>",
            "error": "boom",
        }])

        assert survivors == []
        assert details[0]["error"] == "boom"
        assert details[0].get("survived") is None


class TestWorkflowWiring:
    @staticmethod
    def _definitions() -> Path:
        import xscan

        return Path(xscan.__file__).parent / "workflows" / "definitions"

    @pytest.mark.parametrize("workflow", ["xss-deep.yaml", "xss-balanced.yaml"])
    def test_workflow_runs_dompurify_after_tool_scan(self, workflow):
        text = (self._definitions() / workflow).read_text(encoding="utf-8")

        assert "id: dompurify-scan" in text
        assert "type: dompurify-scan" in text
        block = text.split("id: dompurify-scan", 1)[1].split("timeout", 1)[0]
        assert "tool-scan" in block

    def test_deep_workflow_feeds_fusion(self):
        text = (self._definitions() / "xss-deep.yaml").read_text(encoding="utf-8")
        fusion = text.split("id: evidence-fusion", 1)[1]
        depends_on = fusion.split("depends_on:", 1)[1].split("\n", 1)[0]

        assert "dompurify-scan" in depends_on

    def test_balanced_workflow_feeds_report(self):
        text = (self._definitions() / "xss-balanced.yaml").read_text(encoding="utf-8")
        report = text.split("id: report", 1)[1]
        depends_on = report.split("depends_on:", 1)[1].split("\n", 1)[0]

        assert "dompurify-scan" in depends_on


def _live_env_ready() -> bool:
    from xscan.nodes.analysis import dompurify_scan

    return (
        dompurify_scan._find_purify_build() is not None
        and dompurify_scan._system_browser_present()
    )


@pytest.mark.skipif(
    not _live_env_ready(),
    reason="DOMPurify clone + system Chrome/Edge required",
)
class TestDifferentialProbeLive:
    """Runs the real DOMPurify build in a real browser."""

    def test_script_and_event_payloads_do_not_survive(self):
        from playwright.sync_api import sync_playwright

        from xscan.nodes.analysis import dompurify_scan
        from xscan.schemas.xss import ToolStatus

        build = dompurify_scan._find_purify_build()
        assert build is not None
        node = dompurify_scan.DomPurifyScanNode()
        ctx = _make_ctx(target_url="http://example.com/")
        payloads = list(dompurify_scan._PROBE_PAYLOADS)

        with sync_playwright() as playwright:
            browser = dompurify_scan._launch_browser(playwright)
            try:
                obs = node._differential_probe(ctx, browser, build, payloads)
            finally:
                browser.close()

        assert obs.version  # browser reported the loaded DOMPurify version
        # Default DOMPurify config neutralises every probe payload, including
        # the historical mutation-XSS vectors and inert "javascript:" text.
        assert obs.payloads == []
        assert obs.status == ToolStatus.NO_CANDIDATES
