"""Scope and ScopeRule schemas."""
from __future__ import annotations

import re
from enum import StrEnum
from ipaddress import IPv4Network, IPv6Network
from urllib.parse import urlparse

from pydantic import BaseModel, Field


class ScopeRuleType(StrEnum):
    DOMAIN   = "domain"     # exact domain or *.domain wildcard
    URL      = "url"        # URL prefix (https://host/path/*)
    CIDR     = "cidr"       # IP network range
    REGEX    = "regex"      # arbitrary regex against full URL
    EXCLUDE  = "exclude"    # always block regardless of other rules


class ScopeRule(BaseModel):
    type: ScopeRuleType
    value: str              # the pattern/domain/cidr/regex string
    comment: str = ""

    def matches(self, url: str) -> bool:
        """Return True if this rule matches the given URL."""
        parsed = urlparse(url)
        host = parsed.hostname or ""

        match self.type:
            case ScopeRuleType.DOMAIN:
                pattern = self.value.lstrip("*").lstrip(".")
                return host == pattern or host.endswith("." + pattern)

            case ScopeRuleType.URL:
                prefix = self.value.rstrip("*").rstrip("/")
                return url.startswith(prefix)

            case ScopeRuleType.CIDR:
                try:
                    net: IPv4Network | IPv6Network
                    from ipaddress import ip_address, ip_network
                    net = ip_network(self.value, strict=False)
                    return ip_address(host) in net
                except ValueError:
                    return False

            case ScopeRuleType.REGEX:
                return bool(re.search(self.value, url))

            case ScopeRuleType.EXCLUDE:
                # Exclude rules are checked separately — never "allow"
                return False

        return False

    def excludes(self, url: str) -> bool:
        """Return True if this rule explicitly excludes the URL."""
        if self.type != ScopeRuleType.EXCLUDE:
            return False
        pattern = self.value.rstrip("*")
        return url.startswith(pattern)


class Scope(BaseModel):
    """Authorised scan scope for a single scan."""
    scan_id: str
    rules: list[ScopeRule] = Field(default_factory=list)

    @classmethod
    def from_target_url(cls, scan_id: str, target_url: str) -> "Scope":
        """
        Create a minimal scope allowing the target host.

        Handles four cases:
          1. Regular domain   — example.com  → DOMAIN rules
          2. Wildcard domain  — *.example.com → single DOMAIN rule
          3. IP address       — 127.0.0.1    → CIDR /32 rule
          4. localhost        — localhost     → both DOMAIN + CIDR 127.0.0.1/32
        """
        from ipaddress import ip_address
        parsed = urlparse(target_url)
        host = parsed.hostname or target_url

        rules: list[ScopeRule] = []

        # Detect bare IP address
        try:
            ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False

        if is_ip:
            # IP/32 CIDR — allows exact IP
            rules.append(ScopeRule(type=ScopeRuleType.CIDR, value=f"{host}/32",
                                   comment=f"auto: target IP {host}"))
        else:
            rules.append(ScopeRule(type=ScopeRuleType.DOMAIN, value=host,
                                   comment=f"auto: target host {host}"))
            # Also allow subdomains (useful for CDN assets / API)
            if not host.startswith("*"):
                rules.append(ScopeRule(type=ScopeRuleType.DOMAIN, value=f"*.{host}",
                                       comment="auto: subdomains"))
            # localhost — also allow 127.0.0.1 so browser tools / redirects work
            if host == "localhost":
                rules.append(ScopeRule(type=ScopeRuleType.CIDR, value="127.0.0.1/32",
                                       comment="auto: localhost loopback IP"))
                rules.append(ScopeRule(type=ScopeRuleType.CIDR, value="::1/128",
                                       comment="auto: localhost IPv6"))

        return cls(scan_id=scan_id, rules=rules)

    def is_allowed(self, url: str) -> bool:
        """
        Return True if url is within scope and not excluded.
        A URL is allowed if at least one non-exclude rule matches
        and no exclude rule matches.
        """
        # Exclusions take priority
        for rule in self.rules:
            if rule.excludes(url):
                return False
        # Must match at least one allow rule
        return any(r.matches(url) for r in self.rules)
