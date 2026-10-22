"""
PolicyEngine
============
Second layer after ScopeEngine.  Applies operation-level rules on top of
scope validation.

Current policy rules:
  - LLM nodes may not issue network operations directly
  - Research fetches are restricted to an allowed-domain list
  - Maximum request rate per node (future: rate limiter hook)
  - Scan profiles restrict which node types may run

Policy decisions are structured (allow / deny / warn) so callers can
handle them appropriately rather than catching raw exceptions.
"""
from __future__ import annotations

import logging
from enum import StrEnum
from typing import Any

from xscan.errors import PolicyViolation

logger = logging.getLogger(__name__)


class PolicyDecision(StrEnum):
    ALLOW = "allow"
    DENY  = "deny"
    WARN  = "warn"


class PolicyRule:
    """Base class for a single policy rule."""

    name: str = "unnamed"

    def evaluate(self, operation: str, context: dict[str, Any]) -> PolicyDecision:
        raise NotImplementedError


class NoDirectLLMNetworkRule(PolicyRule):
    """LLM specialist nodes must not issue outbound network requests directly."""

    name = "no_direct_llm_network"

    def evaluate(self, operation: str, context: dict[str, Any]) -> PolicyDecision:
        node_type = context.get("node_type", "")
        if node_type == "llm_specialist" and operation in ("http_request", "dns_lookup"):
            return PolicyDecision.DENY
        return PolicyDecision.ALLOW


class ResearchDomainAllowlistRule(PolicyRule):
    """Research fetches are restricted to approved domains."""

    name = "research_domain_allowlist"
    # Extend via config in future
    _ALLOWED = {
        "nvd.nist.gov", "cve.mitre.org", "cve.org",
        "owasp.org", "portswigger.net", "developer.mozilla.org",
        "github.com", "pkg.go.dev", "npmjs.com",
        "duckduckgo.com", "search.brave.com",
    }

    def evaluate(self, operation: str, context: dict[str, Any]) -> PolicyDecision:
        if operation != "research_fetch":
            return PolicyDecision.ALLOW
        from urllib.parse import urlparse
        url = context.get("url", "")
        host = urlparse(url).hostname or ""
        # Allow if host matches or is subdomain of allowed list
        for allowed in self._ALLOWED:
            if host == allowed or host.endswith("." + allowed):
                return PolicyDecision.ALLOW
        logger.warning("POLICY DENY research_fetch  host=%s", host)
        return PolicyDecision.DENY


class PolicyEngine:
    """
    Evaluates a set of PolicyRules for a given operation + context.

    Usage::

        engine = PolicyEngine()
        engine.assert_permitted("http_request", {"node_type": "crawler", "url": "..."})
        engine.assert_permitted("research_fetch", {"url": "https://owasp.org/..."})
    """

    def __init__(self, rules: list[PolicyRule] | None = None) -> None:
        self._rules: list[PolicyRule] = rules if rules is not None else self._default_rules()

    @staticmethod
    def _default_rules() -> list[PolicyRule]:
        return [
            NoDirectLLMNetworkRule(),
            ResearchDomainAllowlistRule(),
        ]

    def evaluate(self, operation: str, context: dict[str, Any]) -> PolicyDecision:
        """
        Run all rules.  First DENY wins.  Returns ALLOW if all pass.
        """
        for rule in self._rules:
            decision = rule.evaluate(operation, context)
            if decision == PolicyDecision.DENY:
                logger.warning(
                    "POLICY DENY  rule=%s  op=%s  context=%s",
                    rule.name, operation, context,
                )
                return PolicyDecision.DENY
            if decision == PolicyDecision.WARN:
                logger.warning(
                    "POLICY WARN  rule=%s  op=%s  context=%s",
                    rule.name, operation, context,
                )
        return PolicyDecision.ALLOW

    def assert_permitted(self, operation: str, context: dict[str, Any]) -> None:
        """
        Assert that the operation is permitted.

        Raises:
            PolicyViolation: if any rule denies the operation.
        """
        decision = self.evaluate(operation, context)
        if decision == PolicyDecision.DENY:
            raise PolicyViolation(
                f"Policy denied operation '{operation}'.",
                operation=operation,
                url=context.get("url", ""),
            )
