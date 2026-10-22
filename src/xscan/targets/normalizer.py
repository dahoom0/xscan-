"""
URL Normalizer
==============
Deterministic URL normalization for deduplication and stable identity.

Key principles:
  - Deterministic: same input always produces same output
  - Conservative: never change the actual target semantics
  - Preserves original URL for evidence/audit
  - Handles common variations that don't affect security testing

Normalization rules:
  1. Scheme normalization (add https:// if missing)
  2. Trailing slash normalization (keep for paths, remove for root)
  3. Default port removal (80 for http, 443 for https)
  4. Hostname lowercase
  5. URL encoding normalization (decode where safe)
  6. Fragment handling (configurable, usually preserved)
  7. Query parameter ordering (optional, for strict dedup)
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
from typing import Any


class URLNormalizer:
    """
    Deterministic URL normalizer.

    Usage::

        normalizer = URLNormalizer()
        result = normalizer.normalize("https://Example.COM:443/path/")
        # result.normalized_url == "https://example.com/path/"
        # result.original_url == "https://Example.COM:443/path/"
    """

    def __init__(
        self,
        *,
        sort_query_params: bool = False,
        decode_safe_chars: bool = True,
        preserve_fragment: bool = True,
        remove_default_port: bool = True,
        lowercase_host: bool = True,
    ) -> None:
        """
        Initialize normalizer with options.

        Args:
            sort_query_params: Sort query parameters for strict dedup
            decode_safe_chars: Decode URL-encoded alphanumerics
            preserve_fragment: Keep URL fragments (important for DOM XSS)
            remove_default_port: Remove :80 for http, :443 for https
            lowercase_host: Convert hostname to lowercase
        """
        self.sort_query_params = sort_query_params
        self.decode_safe_chars = decode_safe_chars
        self.preserve_fragment = preserve_fragment
        self.remove_default_port = remove_default_port
        self.lowercase_host = lowercase_host

    def normalize(self, url: str) -> "NormalizationResult":
        """
        Normalize a URL.

        Returns a NormalizationResult with both original and normalized URLs.
        """
        original = url.strip()
        if not original:
            return NormalizationResult(
                original_url=original,
                normalized_url=original,
                scheme="",
                hostname="",
                port=None,
                path="/",
                query="",
                fragment="",
                valid=False,
                error="Empty URL",
            )

        # Add scheme if missing
        normalized = original
        if not normalized.startswith(("http://", "https://")):
            # Check if it looks like a URL
            if "." in normalized or "localhost" in normalized or normalized.startswith("/"):
                normalized = "https://" + normalized
            else:
                return NormalizationResult(
                    original_url=original,
                    normalized_url=original,
                    scheme="",
                    hostname="",
                    port=None,
                    path="/",
                    query="",
                    fragment="",
                    valid=False,
                    error="URL must start with http:// or https://",
                )

        try:
            parsed = urlparse(normalized)
        except Exception as e:
            return NormalizationResult(
                original_url=original,
                normalized_url=original,
                scheme="",
                hostname="",
                port=None,
                path="/",
                query="",
                fragment="",
                valid=False,
                error=f"Failed to parse URL: {e}",
            )

        # Extract components
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname or ""
        port = parsed.port
        path = parsed.path or "/"
        query = parsed.query or ""
        fragment = parsed.fragment or ""

        # Validate hostname
        if not hostname:
            return NormalizationResult(
                original_url=original,
                normalized_url=original,
                scheme=scheme,
                hostname="",
                port=port,
                path=path,
                query=query,
                fragment=fragment,
                valid=False,
                error="URL must have a hostname",
            )

        # Apply normalizations
        if self.lowercase_host:
            hostname = hostname.lower()

        # Handle default ports
        default_ports = {"http": 80, "https": 443}
        explicit_port = port
        if self.remove_default_port and port == default_ports.get(scheme):
            port = None

        # Normalize path
        path = self._normalize_path(path)

        # Normalize query string
        if query and self.sort_query_params:
            query = self._sort_query_params(query)

        if query and self.decode_safe_chars:
            query = self._decode_safe_chars(query)

        # Handle fragment
        if not self.preserve_fragment:
            fragment = ""

        # Reconstruct normalized URL
        netloc = hostname
        if port:
            netloc = f"{hostname}:{port}"

        normalized_url = urlunparse((
            scheme,
            netloc,
            path,
            "",  # params (deprecated)
            query,
            fragment,
        ))

        return NormalizationResult(
            original_url=original,
            normalized_url=normalized_url,
            scheme=scheme,
            hostname=hostname,
            port=explicit_port,
            path=path,
            query=query,
            fragment=fragment,
            valid=True,
            error="",
        )

    def _normalize_path(self, path: str) -> str:
        """Normalize the path component."""
        # Remove duplicate slashes
        while "//" in path:
            path = path.replace("//", "/")

        # For root path, ensure it's just "/"
        if path == "":
            path = "/"

        # Don't remove trailing slash for non-root paths
        # (trailing slash can affect routing in some frameworks)
        return path

    def _sort_query_params(self, query: str) -> str:
        """Sort query parameters alphabetically."""
        if not query:
            return ""
        try:
            params = parse_qsl(query, keep_blank_values=True)
            sorted_params = sorted(params, key=lambda x: x[0])
            return urlencode(sorted_params)
        except Exception:
            return query

    def _decode_safe_chars(self, query: str) -> str:
        """Decode URL-encoded alphanumeric characters."""
        # Only decode safe unreserved characters: A-Z a-z 0-9 - . _ ~
        def decode_match(m: re.Match) -> str:
            hex_val = m.group(1)
            try:
                char = chr(int(hex_val, 16))
                if char.isalnum() or char in "-._~":
                    return char
            except ValueError:
                pass
            return m.group(0)

        return re.sub(r"%([0-9A-Fa-f]{2})", decode_match, query)

    def are_equivalent(self, url1: str, url2: str) -> bool:
        """Check if two URLs normalize to the same value."""
        r1 = self.normalize(url1)
        r2 = self.normalize(url2)
        return r1.normalized_url == r2.normalized_url


class NormalizationResult:
    """
    Result of URL normalization.

    Contains both the original URL and the normalized form,
    plus parsed components for further processing.
    """
    __slots__ = (
        "original_url",
        "normalized_url",
        "scheme",
        "hostname",
        "port",
        "path",
        "query",
        "fragment",
        "valid",
        "error",
    )

    def __init__(
        self,
        original_url: str,
        normalized_url: str,
        scheme: str,
        hostname: str,
        port: int | None,
        path: str,
        query: str,
        fragment: str,
        valid: bool,
        error: str,
    ) -> None:
        self.original_url = original_url
        self.normalized_url = normalized_url
        self.scheme = scheme
        self.hostname = hostname
        self.port = port
        self.path = path
        self.query = query
        self.fragment = fragment
        self.valid = valid
        self.error = error

    def __repr__(self) -> str:
        return f"NormalizationResult({self.normalized_url!r}, valid={self.valid})"


def normalize_url(url: str, **options: Any) -> str:
    """
    Convenience function to normalize a URL.

    Returns the normalized URL string, or the original if invalid.
    """
    normalizer = URLNormalizer(**options)
    result = normalizer.normalize(url)
    return result.normalized_url if result.valid else url
