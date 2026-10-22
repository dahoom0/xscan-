"""Tests for scope schemas."""
import pytest
from xscan.schemas.scope import Scope, ScopeRule, ScopeRuleType


class TestScopeRule:
    def test_domain_exact_match(self):
        rule = ScopeRule(type=ScopeRuleType.DOMAIN, value="example.com")
        assert rule.matches("https://example.com/page")

    def test_domain_wildcard_subdomain(self):
        rule = ScopeRule(type=ScopeRuleType.DOMAIN, value="*.example.com")
        assert rule.matches("https://app.example.com/api")
        assert not rule.matches("https://other.com")

    def test_url_prefix_match(self):
        rule = ScopeRule(type=ScopeRuleType.URL, value="https://example.com/app/*")
        assert rule.matches("https://example.com/app/login")
        assert not rule.matches("https://example.com/admin/login")

    def test_regex_match(self):
        rule = ScopeRule(type=ScopeRuleType.REGEX, value=r"example\.com/api/v\d+")
        assert rule.matches("https://example.com/api/v2/users")
        assert not rule.matches("https://example.com/login")

    def test_exclude_rule_does_not_allow(self):
        rule = ScopeRule(type=ScopeRuleType.EXCLUDE, value="https://example.com/logout")
        assert not rule.matches("https://example.com/logout")
        assert rule.excludes("https://example.com/logout")


class TestScope:
    def test_from_target_url_allows_host(self):
        scope = Scope.from_target_url("scan1", "https://example.com")
        assert scope.is_allowed("https://example.com/search?q=test")

    def test_from_target_url_allows_subdomain(self):
        scope = Scope.from_target_url("scan1", "https://example.com")
        assert scope.is_allowed("https://sub.example.com/page")

    def test_blocks_out_of_scope(self):
        scope = Scope.from_target_url("scan1", "https://example.com")
        assert not scope.is_allowed("https://evil.com/steal")

    def test_exclude_overrides_allow(self):
        scope = Scope(
            scan_id="s1",
            rules=[
                ScopeRule(type=ScopeRuleType.DOMAIN, value="example.com"),
                ScopeRule(type=ScopeRuleType.EXCLUDE, value="https://example.com/logout"),
            ],
        )
        assert scope.is_allowed("https://example.com/login")
        assert not scope.is_allowed("https://example.com/logout")
