"""Tests for ScopeEngine and PolicyEngine."""
import pytest
from xscan.core.scope.engine import ScopeEngine
from xscan.core.scope.policy import PolicyEngine, PolicyDecision
from xscan.errors import PolicyViolation


class TestScopeEngine:
    def test_allows_target_host(self):
        engine = ScopeEngine.from_target("s1", "https://example.com")
        engine.assert_allowed("https://example.com/search?q=test")  # no exception

    def test_blocks_out_of_scope(self):
        engine = ScopeEngine.from_target("s1", "https://example.com")
        with pytest.raises(PolicyViolation):
            engine.assert_allowed("https://evil.com/steal")

    def test_blocks_exclude_rule(self):
        from xscan.schemas.scope import Scope, ScopeRule, ScopeRuleType
        scope = Scope(scan_id="s1", rules=[
            ScopeRule(type=ScopeRuleType.DOMAIN, value="example.com"),
            ScopeRule(type=ScopeRuleType.EXCLUDE, value="https://example.com/logout"),
        ])
        engine = ScopeEngine(scope)
        with pytest.raises(PolicyViolation):
            engine.assert_allowed("https://example.com/logout")

    def test_is_allowed_returns_bool(self):
        engine = ScopeEngine.from_target("s1", "https://example.com")
        assert engine.is_allowed("https://example.com/page") is True
        assert engine.is_allowed("https://other.com") is False

    def test_filter_urls(self):
        engine = ScopeEngine.from_target("s1", "https://example.com")
        urls = [
            "https://example.com/page",
            "https://evil.com/bad",
            "https://sub.example.com/app",
        ]
        filtered = engine.filter_urls(urls)
        assert "https://example.com/page" in filtered
        assert "https://sub.example.com/app" in filtered
        assert "https://evil.com/bad" not in filtered

    def test_allow_all_permits_everything(self):
        engine = ScopeEngine.allow_all("s1")
        engine.assert_allowed("https://anything.com/path")  # no exception

    def test_violation_carries_url(self):
        engine = ScopeEngine.from_target("s1", "https://example.com")
        try:
            engine.assert_allowed("https://evil.com")
        except PolicyViolation as exc:
            assert exc.url == "https://evil.com"
            assert exc.operation == "request"


class TestPolicyEngine:
    def test_allows_normal_http_request(self):
        engine = PolicyEngine()
        decision = engine.evaluate("http_request", {"node_type": "crawler", "url": "https://x.com"})
        assert decision == PolicyDecision.ALLOW

    def test_denies_llm_direct_http(self):
        engine = PolicyEngine()
        decision = engine.evaluate("http_request", {"node_type": "llm_specialist"})
        assert decision == PolicyDecision.DENY

    def test_denies_llm_dns_lookup(self):
        engine = PolicyEngine()
        decision = engine.evaluate("dns_lookup", {"node_type": "llm_specialist"})
        assert decision == PolicyDecision.DENY

    def test_allows_research_fetch_to_approved_domain(self):
        engine = PolicyEngine()
        decision = engine.evaluate(
            "research_fetch",
            {"url": "https://owasp.org/www-project-top-ten/", "node_type": "research"}
        )
        assert decision == PolicyDecision.ALLOW

    def test_denies_research_fetch_to_unknown_domain(self):
        engine = PolicyEngine()
        decision = engine.evaluate(
            "research_fetch",
            {"url": "https://some-random-site.xyz/data"}
        )
        assert decision == PolicyDecision.DENY

    def test_assert_permitted_raises_on_deny(self):
        engine = PolicyEngine()
        with pytest.raises(PolicyViolation):
            engine.assert_permitted("http_request", {"node_type": "llm_specialist"})

    def test_assert_permitted_passes_on_allow(self):
        engine = PolicyEngine()
        engine.assert_permitted("http_request", {"node_type": "crawler"})  # no exception
