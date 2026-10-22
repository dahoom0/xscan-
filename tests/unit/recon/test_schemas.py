"""Tests for recon schemas — asset deduplication, scope, tool states."""
import pytest
from xscan.schemas.recon import (
    ReconAsset, ReconToolObservation, ReconToolStatus,
    HttpProbeResult, HttpProbeStatus, DiscoveredPath, DiscoveredPathStatus,
    Endpoint,
)


class TestReconAsset:
    def test_normalise_hostname(self):
        assert ReconAsset.normalise_hostname("API.Example.COM.") == "api.example.com"
        assert ReconAsset.normalise_hostname("  sub.domain.tld  ") == "sub.domain.tld"

    def test_add_source_deduplicates(self):
        a = ReconAsset(hostname="api.example.com", normalized_hostname="api.example.com")
        a.add_source("subfinder", "EV-001")
        a.add_source("subfinder", "EV-001")   # duplicate
        a.add_source("amass",     "EV-002")
        assert a.sources == ["subfinder", "amass"]
        assert a.evidence_ids == ["EV-001", "EV-002"]

    def test_three_tools_one_asset(self):
        """Spec: same hostname from 3 tools = 1 asset with 3 sources."""
        a = ReconAsset(hostname="api.example.com", normalized_hostname="api.example.com")
        for tool in ["subfinder", "assetfinder", "amass"]:
            a.add_source(tool)
        assert len(a.sources) == 3
        assert "subfinder" in a.sources
        assert "assetfinder" in a.sources
        assert "amass" in a.sources


class TestReconToolStatus:
    def test_failure_states_not_definitive_negative(self):
        """Timeout/execution_failed must NOT be treated as 'no results'."""
        for status in (ReconToolStatus.TIMEOUT, ReconToolStatus.EXECUTION_FAILED,
                       ReconToolStatus.CONNECTION_FAILED):
            obs = ReconToolObservation(tool="subfinder", target="example.com", status=status)
            assert not obs.has_results
            assert obs.is_failure
            # CRITICAL: these are NOT definitive negatives
            assert not obs.status.is_definitive_negative

    def test_completed_no_results_is_definitive_negative(self):
        obs = ReconToolObservation(
            tool="subfinder", target="example.com",
            status=ReconToolStatus.COMPLETED_NO_RESULTS
        )
        assert obs.status.is_definitive_negative
        assert not obs.is_failure

    def test_tool_unavailable_not_safe(self):
        """Missing tool != no vulnerability."""
        obs = ReconToolObservation(
            tool="amass", target="example.com",
            status=ReconToolStatus.TOOL_UNAVAILABLE
        )
        assert not obs.has_results
        assert not obs.status.is_definitive_negative

    def test_completed_with_results(self):
        obs = ReconToolObservation(
            tool="subfinder", target="example.com",
            status=ReconToolStatus.COMPLETED_WITH_RESULTS,
            results=["api.example.com", "dev.example.com"],
        )
        assert obs.has_results
        assert len(obs.results) == 2


class TestScopeWithAssets:
    """Test that ScopeEngine — not substring matching — determines scope."""

    def _make_scope(self, target_url: str, scan_id: str = "test"):
        from xscan.core.scope.engine import ScopeEngine
        return ScopeEngine.from_target(scan_id, target_url)

    def test_exact_domain_allowed(self):
        engine = self._make_scope("https://example.com")
        assert engine.is_allowed("https://example.com/page")

    def test_subdomain_allowed(self):
        engine = self._make_scope("https://example.com")
        assert engine.is_allowed("https://api.example.com/v1")

    def test_deep_subdomain_allowed(self):
        engine = self._make_scope("https://example.com")
        assert engine.is_allowed("https://dev.api.example.com/test")

    def test_unrelated_domain_denied(self):
        engine = self._make_scope("https://example.com")
        assert not engine.is_allowed("https://notexample.com")

    def test_typosquat_denied(self):
        """example.com.attacker.test must be blocked."""
        engine = self._make_scope("https://example.com")
        assert not engine.is_allowed("https://example.com.attacker.test/steal")

    def test_partial_match_denied(self):
        engine = self._make_scope("https://example.com")
        assert not engine.is_allowed("https://myexample.com")


class TestHttpProbeResult:
    def test_live_200(self):
        p = HttpProbeResult(url="https://example.com", http_status_code=200, live=True,
                            status=HttpProbeStatus.LIVE)
        assert p.live
        assert p.status == HttpProbeStatus.LIVE

    def test_connection_failed_not_live(self):
        p = HttpProbeResult(url="https://dead.example.com",
                            status=HttpProbeStatus.CONNECTION_FAILED)
        assert not p.live

    def test_redirect_preserved(self):
        p = HttpProbeResult(url="https://example.com", http_status_code=301, live=True,
                            status=HttpProbeStatus.REDIRECT,
                            redirect_location="https://www.example.com/")
        assert p.redirect_location == "https://www.example.com/"


class TestDiscoveredPath:
    def test_status_classification(self):
        from xscan.tools.adapters.ffuf import _status_from_code
        assert _status_from_code(200) == DiscoveredPathStatus.REACHABLE
        assert _status_from_code(301) == DiscoveredPathStatus.REDIRECT
        assert _status_from_code(403) == DiscoveredPathStatus.FORBIDDEN
        assert _status_from_code(404) == DiscoveredPathStatus.NOT_FOUND
        assert _status_from_code(500) == DiscoveredPathStatus.ERROR
        assert _status_from_code(0)   == DiscoveredPathStatus.INCONCLUSIVE


class TestEndpointDeduplication:
    """Same URL from crawler + ffuf + probe = ONE endpoint."""

    def test_dedup_same_url_multiple_sources(self):
        seen = {}
        url = "https://example.com/login"

        for source in ("crawler", "ffuf", "probe"):
            norm = url  # simplified normalisation
            if norm not in seen:
                seen[norm] = Endpoint(
                    url=norm, hostname="example.com", path="/login"
                )
            seen[norm].add_source(source)

        assert len(seen) == 1
        ep = seen[url]
        assert set(ep.sources) == {"crawler", "ffuf", "probe"}
