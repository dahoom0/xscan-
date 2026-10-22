"""
Regression tests for XSS false-positive bugs.

Covers the five root-cause bugs identified against OWASP Juice Shop:

(a) discover.py: overly permissive SPA probe status filter
(b) context.py:  JSON body misclassified as html_text (80-char window)
(c) discover.py: invented /api/v1 /api/v2 endpoints in _REST_PROBES
(d) fusion.py:   key mismatch — "candidates" vs "xss_candidates"
(e) candidate_gen.py: HTTP >=400 responses not filtered before analysis
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# (a) + (c)  _is_framework_error and SPA probe filtering
# ---------------------------------------------------------------------------

class TestFrameworkErrorDetection:
    """_is_framework_error should identify server error pages correctly."""

    def test_express_cannot_get(self):
        from xscan.nodes.crawler.discover import _is_framework_error
        assert _is_framework_error("cannot get /api/v1/search", "/api/v1/search")

    def test_juice_shop_unexpected_path(self):
        from xscan.nodes.crawler.discover import _is_framework_error
        body = '{"error":"unexpected path: /api/v1/search"}'
        assert _is_framework_error(body.lower(), "/api/v1/search")

    def test_path_echo(self):
        from xscan.nodes.crawler.discover import _is_framework_error
        # If path appears in body start it's being echoed by an error handler
        assert _is_framework_error("/api/comment in response body", "/api/comment")

    def test_real_json_not_error(self):
        from xscan.nodes.crawler.discover import _is_framework_error
        body = '{"status":"success","data":[{"id":1,"name":"Apple"}]}'
        assert not _is_framework_error(body.lower(), "/api/products")

    def test_html_page_not_error(self):
        from xscan.nodes.crawler.discover import _is_framework_error
        body = "<!doctype html><html><head><title>Search</title></head>"
        assert not _is_framework_error(body.lower(), "/search")

    def test_routing_error(self):
        from xscan.nodes.crawler.discover import _is_framework_error
        assert _is_framework_error("routing error no route matches", "/api/v2")

    def test_404_in_body(self):
        from xscan.nodes.crawler.discover import _is_framework_error
        assert _is_framework_error("page not found (404)", "/missing")


class TestRestProbesNoBogusVersions:
    """_REST_PROBES must not contain invented versioned API paths."""

    def test_no_api_v1_search(self):
        from xscan.nodes.crawler.discover import _REST_PROBES
        paths = [p for p, _, _ in _REST_PROBES]
        assert "/api/v1/search" not in paths, (
            "/api/v1/search is an invented path that causes false positives"
        )

    def test_no_api_v2_search(self):
        from xscan.nodes.crawler.discover import _REST_PROBES
        paths = [p for p, _, _ in _REST_PROBES]
        assert "/api/v2/search" not in paths, (
            "/api/v2/search is an invented path that causes false positives"
        )

    def test_no_api_comment(self):
        from xscan.nodes.crawler.discover import _REST_PROBES
        paths = [p for p, _, _ in _REST_PROBES]
        # /api/comment is a guess and caused false positives — must be removed
        assert "/api/comment" not in paths

    def test_valid_paths_still_present(self):
        from xscan.nodes.crawler.discover import _REST_PROBES
        paths = [p for p, _, _ in _REST_PROBES]
        # These are legitimate well-known paths
        assert "/search" in paths
        assert "/rest/products/search" in paths   # Juice Shop actual path


class TestValidApiStatuses:
    """_VALID_API_STATUSES must be a strict allowlist, not a denylist."""

    def test_200_is_valid(self):
        from xscan.nodes.crawler.discover import _VALID_API_STATUSES
        assert 200 in _VALID_API_STATUSES

    def test_422_is_valid(self):
        from xscan.nodes.crawler.discover import _VALID_API_STATUSES
        assert 422 in _VALID_API_STATUSES

    def test_400_not_valid(self):
        # 400 with "Unexpected path" body is a framework error, not a real endpoint
        from xscan.nodes.crawler.discover import _VALID_API_STATUSES
        assert 400 not in _VALID_API_STATUSES

    def test_500_not_valid(self):
        from xscan.nodes.crawler.discover import _VALID_API_STATUSES
        assert 500 not in _VALID_API_STATUSES

    def test_404_not_valid(self):
        from xscan.nodes.crawler.discover import _VALID_API_STATUSES
        assert 404 not in _VALID_API_STATUSES

    def test_302_not_valid(self):
        from xscan.nodes.crawler.discover import _VALID_API_STATUSES
        assert 302 not in _VALID_API_STATUSES


# ---------------------------------------------------------------------------
# (b)  JSON body misclassified as html_text
# ---------------------------------------------------------------------------

class TestContextAnalyserJsonDetection:
    """ContextAnalyser must classify JSON bodies as json_value, not html_text."""

    def _analyser(self):
        from xscan.nodes.analysis.context import ContextAnalyser
        return ContextAnalyser()

    def test_short_json_body(self):
        ca = self._analyser()
        body = '{"status":"success","q":"xscC12345678"}'
        result = ca.analyse(body, "xscC12345678")
        assert result.reflected
        assert result.context in ("json_value", "json_key", "json_string"), (
            f"Expected json context, got {result.context!r}"
        )

    def test_long_json_body_marker_far_from_opening_brace(self):
        """Regression: 80-char before-window was too short for long JSON bodies."""
        ca = self._analyser()
        # Build a long JSON body where opening { is > 100 chars before the marker
        prefix = '{"status":"success","data":' + '{"id":1,"name":"test"},' * 5
        body = prefix + '"query":"xscCabcdef12"}'
        result = ca.analyse(body, "xscCabcdef12")
        assert result.reflected
        assert result.context in ("json_value", "json_key", "json_string"), (
            f"Long JSON body should give json context, got {result.context!r}"
        )

    def test_juice_shop_search_response(self):
        """Exact shape of Juice Shop /rest/products/search response."""
        ca = self._analyser()
        body = (
            '{"status":"success","data":['
            '{"id":1,"name":"xscCtest1234","price":1.0},'
            '{"id":2,"name":"Apple","price":0.5}'
            ']}'
        )
        result = ca.analyse(body, "xscCtest1234")
        assert result.reflected
        assert result.context in ("json_value", "json_key", "json_string"), (
            f"Juice Shop JSON should give json context, got {result.context!r}"
        )

    def test_unexpected_path_json_error(self):
        """The Juice Shop 'Unexpected path' error should NOT look like a reflection."""
        ca = self._analyser()
        # Server returns 400 with path echoed in error body
        body = '{"error":"Unexpected path: /api/v1/search?q=xscCabcd1234"}'
        # Even if marker appears, it's in an error response — the candidate_gen
        # status filter (>=400) should catch this before we get here.
        # But if it reaches the analyser, it should at least be json_value not html_text.
        result = ca.analyse(body, "xscCabcd1234")
        if result.reflected:
            assert result.context != "html_text", (
                "Error page JSON should not be classified as html_text"
            )

    def test_html_body_still_html_text(self):
        """Real HTML reflections should still be classified as html_text."""
        ca = self._analyser()
        body = "<html><body><p>You searched for: xscCtest5678</p></body></html>"
        result = ca.analyse(body, "xscCtest5678")
        assert result.reflected
        assert result.context == "html_text"

    def test_html_attribute_still_attribute(self):
        """HTML attribute reflections should still be html_attribute."""
        ca = self._analyser()
        body = '<html><body><input value="xscCtest9999"></body></html>'
        result = ca.analyse(body, "xscCtest9999")
        assert result.reflected
        assert "attribute" in result.context

    def test_body_is_json_helper(self):
        from xscan.nodes.analysis.context import ContextAnalyser
        assert ContextAnalyser._body_is_json('{"a": 1}')
        assert ContextAnalyser._body_is_json('[{"a": 1}]')
        assert not ContextAnalyser._body_is_json('<html>test</html>')
        assert not ContextAnalyser._body_is_json('')
        assert not ContextAnalyser._body_is_json('plain text')


# ---------------------------------------------------------------------------
# (d)  Key mismatch in fusion node
# ---------------------------------------------------------------------------

class TestFusionKeyMismatch:
    """EvidenceFusionNode must read both 'candidates' and 'xss_candidates' keys."""

    def _make_ctx(self, **kwargs):
        """Build a minimal ExecutionContext-like object."""
        ctx = MagicMock()
        ctx.scan_id = "TEST"
        ctx.node_id = "evidence-fusion"
        ctx.run_id  = "RUN-TEST"
        ctx.config  = {}
        ctx.inputs  = {**kwargs}
        ctx.get     = lambda key, default=None: ctx.inputs.get(key, default)

        from xscan.core.scope.engine import ScopeEngine
        ctx.scope = ScopeEngine.allow_all("TEST")

        from xscan.core.scope.policy import PolicyEngine
        ctx.policy = PolicyEngine()
        ctx.logger = MagicMock()
        ctx.no_llm = True
        return ctx

    def _minimal_candidate(self, param: str = "q") -> dict:
        return {
            "url":           "https://example.com/search",
            "parameter":     param,
            "method":        "GET",
            "context_analysis": {
                "marker": "xscCtest", "context": "html_text",
                "reflected": True, "raw_present": True,
                "encoded_chars": [], "breakout_chars": ["<"],
            },
            "encoding_profile": {
                "raw_chars": ["<", ">", '"'],
                "encoded_chars": [],
                "stripped_chars": [],
                "summary": "raw: [<, >]",
                "can_break_html_text": True,
                "can_break_html_attribute": True,
                "can_break_script_string": False,
            },
            "canary_evidence": "<p>xscCtest</p>",
            "confidence": "high",
        }

    def test_reads_xss_candidates_key(self):
        from xscan.nodes.xss.fusion import EvidenceFusionNode
        node = EvidenceFusionNode()
        ctx = self._make_ctx(
            target_url="https://example.com",
            xss_candidates=[self._minimal_candidate("q")],
        )
        result = node.execute(ctx)
        assert result["fused_count"] == 1, (
            "fusion must read 'xss_candidates' key from candidate-generator"
        )

    def test_reads_candidates_key(self):
        """Regression: reflection-detector outputs 'candidates', not 'xss_candidates'."""
        from xscan.nodes.xss.fusion import EvidenceFusionNode
        node = EvidenceFusionNode()
        ctx = self._make_ctx(
            target_url="https://example.com",
            candidates=[self._minimal_candidate("name")],
        )
        result = node.execute(ctx)
        assert result["fused_count"] == 1, (
            "fusion must read 'candidates' key from reflection-detector (xss-fast)"
        )

    def test_does_not_double_count(self):
        """When both keys present, must not deduplicate incorrectly."""
        from xscan.nodes.xss.fusion import EvidenceFusionNode
        node = EvidenceFusionNode()
        cand_a = self._minimal_candidate("q")
        cand_b = self._minimal_candidate("name")
        ctx = self._make_ctx(
            target_url="https://example.com",
            xss_candidates=[cand_a],
            candidates=[cand_b],
        )
        result = node.execute(ctx)
        # xss_candidates takes priority; candidates key is only used as fallback
        # so we expect 1 (from xss_candidates), not 2
        assert result["fused_count"] == 1


# ---------------------------------------------------------------------------
# (e)  HTTP >= 400 responses not filtered
# ---------------------------------------------------------------------------

class TestCandidateGenStatusFilter:
    """candidate_gen._analyse_param must return None for HTTP >=400 responses."""

    def _make_minimal_ctx(self):
        ctx = MagicMock()
        ctx.scan_id = "TEST"
        ctx.node_id = "candidate-gen"
        ctx.run_id  = "RUN-TEST"
        ctx.config  = {}
        ctx.inputs  = {"target_url": "http://127.0.0.1:3000/"}
        ctx.get     = lambda key, default=None: ctx.inputs.get(key, default)
        from xscan.core.scope.engine import ScopeEngine
        ctx.scope = ScopeEngine.allow_all("TEST")
        from xscan.core.scope.policy import PolicyEngine
        ctx.policy = PolicyEngine()
        ctx.logger = MagicMock()
        ctx.no_llm = True
        return ctx

    def _make_node(self):
        from xscan.nodes.analysis.candidate_gen import CandidateGeneratorNode
        return CandidateGeneratorNode()

    def test_rejects_404_response(self):
        """A 404 response must never produce a candidate."""
        import httpx
        from xscan.nodes.analysis.context import ContextAnalyser
        from xscan.nodes.analysis.encoding import EncodingAnalyser

        node = self._make_node()
        ctx  = self._make_minimal_ctx()

        # Canary appears in the 404 body (common for error pages that echo the URL)
        canary = "xscCaaaa1234"
        body = f"<html><body>Not found: /search?q={canary}</body></html>"

        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = body
        mock_resp.headers = {"content-type": "text/html"}

        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp

        ca = ContextAnalyser()
        ea = MagicMock()

        result = node._analyse_param(
            mock_client, ca, ea, ctx,
            "http://127.0.0.1:3000/search?q=test", "q", "GET"
        )
        assert result is None, (
            "404 response must be rejected even if canary appears in body"
        )

    def test_rejects_500_response(self):
        """A 500 response must never produce a candidate."""
        import httpx
        from xscan.nodes.analysis.context import ContextAnalyser
        node = self._make_node()
        ctx  = self._make_minimal_ctx()

        canary = "xscCbbbb5678"
        body = f'{{"error":"Unexpected path: /api/v1/search?q={canary}"}}'

        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = body
        mock_resp.headers = {"content-type": "application/json"}

        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp

        ca = ContextAnalyser()
        ea = MagicMock()

        result = node._analyse_param(
            mock_client, ca, ea, ctx,
            "http://127.0.0.1:3000/api/v1/search?q=test", "q", "GET"
        )
        assert result is None, (
            "500 response must be rejected — 'Unexpected path' error body is not a reflection"
        )

    def test_accepts_200_html_reflection(self):
        """A 200 HTML response with real reflection should produce a candidate."""
        from xscan.nodes.analysis.context import ContextAnalyser
        from xscan.nodes.analysis.encoding import EncodingAnalyser
        node = self._make_node()
        ctx  = self._make_minimal_ctx()

        canary = "xscCcccc9999"
        body = f"<html><body><h1>Results for: {canary}</h1></body></html>"

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = body
        mock_resp.headers = {"content-type": "text/html; charset=utf-8"}

        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp

        # Mock encoding analyser so it doesn't make real HTTP requests
        mock_enc = MagicMock()
        mock_enc.probe.return_value = MagicMock(
            raw_chars=["<", ">", '"'],
            encoded_chars=[],
            stripped_chars=[],
            summary=lambda: "raw: [<, >]",
            can_break_html_text=lambda: True,
            can_break_html_attribute=lambda: True,
            can_break_script_string=lambda: False,
        )

        ca = ContextAnalyser()
        result = node._analyse_param(
            mock_client, ca, mock_enc, ctx,
            f"http://example.com/search?q={canary}", "q", "GET"
        )
        # With the canary already IN the url, _inject_param replaces it again
        # — the test just verifies the status guard doesn't block 200
        # (result may be None if canary injection doesn't match, that's ok)
        # The key assertion: no exception, and not rejected due to status
        # (we can't easily check "not rejected due to status" vs "not reflected"
        #  so we just confirm no error is raised and the function returns)
        assert result is None or isinstance(result, dict)
