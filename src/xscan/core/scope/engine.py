"""
ScopeEngine
===========
The authoritative gatekeeper for all outbound operations.

Every module that issues a network request, browser navigation, DNS lookup,
or tool invocation MUST call ``ScopeEngine.assert_allowed(url)`` before
executing.  Violations raise ``PolicyViolation`` and are audit-logged.

Rule: Do NOT bypass ScopeEngine.  Ever.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from xscan.errors import PolicyViolation, ScopeError
from xscan.schemas.scope import Scope

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class ScopeEngine:
    """
    Validates URLs against an authorised Scope.

    Usage::

        engine = ScopeEngine(scope)
        engine.assert_allowed("https://example.com/search?q=test")  # ok
        engine.assert_allowed("https://evil.com/steal")              # raises PolicyViolation
    """

    def __init__(self, scope: Scope) -> None:
        self._scope = scope

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def scope(self) -> Scope:
        return self._scope

    def is_allowed(self, url: str) -> bool:
        """Return True if the URL is within authorised scope."""
        return self._scope.is_allowed(url)

    def assert_allowed(self, url: str, operation: str = "request") -> None:
        """
        Assert that *url* is within scope.

        Raises:
            PolicyViolation: if the URL is out of scope or excluded.
        """
        if not self._scope.is_allowed(url):
            logger.warning(
                "SCOPE BLOCK  op=%s  url=%s  scan_id=%s",
                operation, url, self._scope.scan_id,
            )
            raise PolicyViolation(
                f"Operation '{operation}' blocked: {url!r} is outside authorised scope.",
                url=url,
                operation=operation,
            )
        logger.debug("SCOPE ALLOW  op=%s  url=%s", operation, url)

    def filter_urls(self, urls: list[str]) -> list[str]:
        """Return only the subset of *urls* that are within scope."""
        return [u for u in urls if self._scope.is_allowed(u)]

    @classmethod
    def from_target(cls, scan_id: str, target_url: str) -> "ScopeEngine":
        """Convenience: create a ScopeEngine scoped to a single target host."""
        scope = Scope.from_target_url(scan_id, target_url)
        return cls(scope)

    @classmethod
    def allow_all(cls, scan_id: str) -> "ScopeEngine":
        """
        Permissive scope — allows everything.
        Only for use in unit tests; NEVER in production scan code.
        """
        from xscan.schemas.scope import ScopeRule, ScopeRuleType
        scope = Scope(
            scan_id=scan_id,
            rules=[ScopeRule(type=ScopeRuleType.REGEX, value=r".*")],
        )
        return cls(scope)
