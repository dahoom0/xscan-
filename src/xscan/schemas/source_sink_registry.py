"""
Extensible Source and Sink Registry
===================================
Comprehensive definitions for DOM-based XSS sources and sinks.

This replaces hardcoded regex patterns with structured, extensible definitions
that support:
- Multiple aliases and variations
- Confidence levels
- Library/framework-specific methods
- Runtime vs static detection
- Parameter extraction patterns

Used by:
- DOM analysis pipeline (static detection)
- Browser instrumentation (runtime observation)
- Candidate generation (verification)
"""
from __future__ import annotations

import re
from enum import StrEnum
from typing import Callable

from pydantic import BaseModel


class SourceType(StrEnum):
    """Categories of DOM-based XSS sources."""

    URL_SEARCH = "url_search"  # location.search, URL params
    URL_HASH = "url_hash"  # location.hash, URL fragment
    URL_HREF = "url_href"  # location.href, full URL
    URL_PATHNAME = "url_pathname"  # location.pathname, path component
    DOCUMENT_URL = "document_url"  # document.URL, document.location
    WINDOW_LOCATION = "window_location"  # window.location, window properties
    REFERRER = "referrer"  # document.referrer
    STORAGE = "storage"  # localStorage, sessionStorage
    WINDOW_MESSAGE = "window_message"  # postMessage events
    COOKIE = "cookie"  # document.cookie
    CUSTOM_PARAMETER = "custom_parameter"  # User-defined extraction functions


class SinkType(StrEnum):
    """Categories of XSS-vulnerable sinks."""

    HTML_WRITE = "html_write"  # innerHTML, outerHTML, insertAdjacentHTML
    EVAL = "eval"  # eval(), Function(), setTimeout, setInterval
    EVAL_JSON = "eval_json"  # JSON.parse with eval (e.g., eval of response)
    SCRIPT_WRITE = "script_write"  # document.write, script.textContent
    DOM_TRAVERSAL = "dom_traversal"  # setAttribute, setProperty with event handlers
    JQUERY_HTML = "jquery_html"  # jQuery.html(), .append(), .replaceWith()
    REACT_RENDER = "react_render"  # React.render, ReactDOM.createRoot
    ANGULAR_COMPILE = "angular_compile"  # Angular $compile, $parse
    VUE_RENDER = "vue_render"  # Vue.$mount, template rendering
    DIRECTIVE = "directive"  # Framework directives (v-html, ng-bind-html)
    URL_NAVIGATION = "url_navigation"  # location.href, location.assign with javascript:


class SourceDefinition(BaseModel):
    """Definition of a DOM XSS source."""

    name: str  # e.g., "location.search"
    type: SourceType
    confidence: float = 0.9  # 0.0-1.0: how confident this is a real source
    patterns: list[str] = []  # Regex patterns to match this source
    aliases: list[str] = []  # Alternative names (e.g., "window.location.search")
    description: str = ""
    parameter_extraction: str = ""  # Regex to extract param name if applicable
    framework: str = ""  # If framework-specific (e.g., "angular", "react")
    runtime_detectable: bool = True  # Can be detected at runtime
    static_detectable: bool = True  # Can be detected via static analysis

    def matches(self, code_line: str) -> bool:
        """Check if this source matches a code line."""
        for pattern in self.patterns:
            try:
                if re.search(pattern, code_line):
                    return True
            except re.error:
                pass
        return False


class SinkDefinition(BaseModel):
    """Definition of a DOM XSS sink."""

    name: str  # e.g., "innerHTML"
    type: SinkType
    confidence: float = 0.95  # How confident this is exploitable
    patterns: list[str] = []  # Regex patterns
    aliases: list[str] = []  # Alternative names
    description: str = ""
    requires_assignment: bool = True  # True if must be on RHS of assignment
    framework: str = ""  # If framework-specific
    runtime_detectable: bool = True
    static_detectable: bool = True
    dangerous_with_html: bool = True  # True if HTML parsing enables XSS
    dangerous_with_javascript: bool = True  # True if JS execution enables XSS

    def matches(self, code_line: str) -> bool:
        """Check if this sink matches a code line."""
        for pattern in self.patterns:
            try:
                if re.search(pattern, code_line):
                    return True
            except re.error:
                pass
        return False


class SourceRegistry:
    """Registry of all known DOM XSS sources."""

    def __init__(self):
        self._sources: list[SourceDefinition] = []
        self._populate()

    def _populate(self) -> None:
        """Populate with standard sources."""
        self._sources = [
            # URL-based sources
            SourceDefinition(
                name="location.search",
                type=SourceType.URL_SEARCH,
                patterns=[
                    r"location\.search",
                    r"window\.location\.search",
                    r"document\.location\.search",
                ],
                aliases=["location['search']", 'location["search"]'],
                description="URL query string",
                parameter_extraction=r"location\.search",
            ),
            SourceDefinition(
                name="location.hash",
                type=SourceType.URL_HASH,
                patterns=[
                    r"location\.hash",
                    r"window\.location\.hash",
                    r"document\.location\.hash",
                ],
                aliases=["location['hash']", 'location["hash"]'],
                description="URL fragment identifier",
            ),
            SourceDefinition(
                name="location.href",
                type=SourceType.URL_HREF,
                patterns=[
                    r"location\.href",
                    r"window\.location\.href",
                    r"document\.location\.href",
                ],
                description="Full URL",
            ),
            SourceDefinition(
                name="document.URL",
                type=SourceType.DOCUMENT_URL,
                patterns=[r"document\.URL", r"document\.location"],
                description="Document URL",
            ),
            # URLSearchParams
            SourceDefinition(
                name="URLSearchParams.get",
                type=SourceType.URL_SEARCH,
                patterns=[
                    r"URLSearchParams\(\s*location\.search\s*\)\.get",
                    r"new\s+URLSearchParams\s*\(\s*location\.search\s*\)\.get",
                    r"URLSearchParams\(\s*window\.location\.search\s*\)\.get",
                ],
                description="URL parameter via URLSearchParams API",
                parameter_extraction=r"\.get\s*\(\s*['\"](\w+)['\"]",
            ),
            # Storage
            SourceDefinition(
                name="localStorage",
                type=SourceType.STORAGE,
                patterns=[r"localStorage\.getItem", r"localStorage\["],
                description="Local storage access",
            ),
            SourceDefinition(
                name="sessionStorage",
                type=SourceType.STORAGE,
                patterns=[r"sessionStorage\.getItem", r"sessionStorage\["],
                description="Session storage access",
            ),
            # Referrer
            SourceDefinition(
                name="document.referrer",
                type=SourceType.REFERRER,
                patterns=[r"document\.referrer", r"document\.referrer"],
                description="HTTP Referrer header value",
            ),
            # postMessage
            SourceDefinition(
                name="window.postMessage",
                type=SourceType.WINDOW_MESSAGE,
                patterns=[r"event\.data", r"message\.data"],
                description="Cross-window message data",
                runtime_detectable=True,
                static_detectable=False,  # Requires runtime listener detection
            ),
        ]

    def get_all(self) -> list[SourceDefinition]:
        """Get all registered sources."""
        return self._sources

    def find_by_type(self, source_type: SourceType) -> list[SourceDefinition]:
        """Find sources by type."""
        return [s for s in self._sources if s.type == source_type]

    def find_matching(self, code_line: str) -> list[SourceDefinition]:
        """Find all sources that match a code line."""
        return [s for s in self._sources if s.matches(code_line)]

    def add_custom(self, source: SourceDefinition) -> None:
        """Add a custom source definition."""
        self._sources.append(source)


class SinkRegistry:
    """Registry of all known DOM XSS sinks."""

    def __init__(self):
        self._sinks: list[SinkDefinition] = []
        self._populate()

    def _populate(self) -> None:
        """Populate with standard sinks."""
        self._sinks = [
            # HTML writing sinks
            SinkDefinition(
                name="innerHTML",
                type=SinkType.HTML_WRITE,
                patterns=[r"\.innerHTML\s*=", r"\.innerHTML\s*\+="],
                description="Direct HTML injection into element",
                dangerous_with_html=True,
            ),
            SinkDefinition(
                name="outerHTML",
                type=SinkType.HTML_WRITE,
                patterns=[r"\.outerHTML\s*=", r"\.outerHTML\s*\+="],
                description="Replace entire element with HTML",
                dangerous_with_html=True,
            ),
            SinkDefinition(
                name="insertAdjacentHTML",
                type=SinkType.HTML_WRITE,
                patterns=[r"\.insertAdjacentHTML\s*\("],
                description="Insert HTML at specified position",
                dangerous_with_html=True,
            ),
            SinkDefinition(
                name="document.write",
                type=SinkType.SCRIPT_WRITE,
                patterns=[r"document\.write\s*\("],
                description="Write HTML to document",
                dangerous_with_html=True,
            ),
            # JavaScript evaluation sinks
            SinkDefinition(
                name="eval",
                type=SinkType.EVAL,
                patterns=[r"\beval\s*\("],
                description="Direct JavaScript evaluation",
                dangerous_with_javascript=True,
            ),
            SinkDefinition(
                name="Function",
                type=SinkType.EVAL,
                patterns=[r"new\s+Function\s*\(", r"\bFunction\s*\("],
                description="Dynamic function construction",
                dangerous_with_javascript=True,
            ),
            SinkDefinition(
                name="setTimeout",
                type=SinkType.EVAL,
                patterns=[r"setTimeout\s*\("],
                description="Delayed code execution",
                dangerous_with_javascript=True,
            ),
            SinkDefinition(
                name="setInterval",
                type=SinkType.EVAL,
                patterns=[r"setInterval\s*\("],
                description="Repeated code execution",
                dangerous_with_javascript=True,
            ),
            # jQuery sinks
            SinkDefinition(
                name="jQuery.html",
                type=SinkType.JQUERY_HTML,
                patterns=[r"\$\s*\(\s*.*\s*\)\s*\.html\s*\("],
                framework="jquery",
                description="jQuery HTML injection",
                dangerous_with_html=True,
            ),
            SinkDefinition(
                name="jQuery.append",
                type=SinkType.JQUERY_HTML,
                patterns=[r"\$\s*\(\s*.*\s*\)\s*\.append\s*\("],
                framework="jquery",
                description="jQuery append HTML",
                dangerous_with_html=True,
            ),
            SinkDefinition(
                name="jQuery.replaceWith",
                type=SinkType.JQUERY_HTML,
                patterns=[r"\$\s*\(\s*.*\s*\)\s*\.replaceWith\s*\("],
                framework="jquery",
                description="jQuery replace with HTML",
                dangerous_with_html=True,
            ),
            # React sinks
            SinkDefinition(
                name="ReactDOM.render",
                type=SinkType.REACT_RENDER,
                patterns=[r"ReactDOM\.render\s*\("],
                framework="react",
                description="React element rendering",
                static_detectable=False,  # Usually dangerouslySetInnerHTML needed
            ),
            # Angular sinks
            SinkDefinition(
                name="Angular.$compile",
                type=SinkType.ANGULAR_COMPILE,
                patterns=[r"\$compile\s*\("],
                framework="angular",
                description="Angular template compilation",
                dangerous_with_javascript=True,
            ),
            SinkDefinition(
                name="Angular.innerHTML",
                type=SinkType.DIRECTIVE,
                patterns=[r"ng-bind-html\s*=", r"ng-html-bind\s*="],
                framework="angular",
                description="Angular HTML binding",
                dangerous_with_html=True,
            ),
            # Vue sinks
            SinkDefinition(
                name="Vue.v-html",
                type=SinkType.DIRECTIVE,
                patterns=[r"v-html\s*="],
                framework="vue",
                description="Vue HTML binding",
                dangerous_with_html=True,
            ),
            # setAttribute with event handlers
            SinkDefinition(
                name="setAttribute",
                type=SinkType.DOM_TRAVERSAL,
                patterns=[r"\.setAttribute\s*\(\s*['\"]on\w+"],
                description="Setting event handler attributes",
                dangerous_with_javascript=True,
            ),
            # URL navigation
            SinkDefinition(
                name="location.href",
                type=SinkType.URL_NAVIGATION,
                patterns=[r"location\.href\s*=", r"location\.assign\s*\("],
                description="URL navigation (javascript: protocol XSS)",
            ),
        ]

    def get_all(self) -> list[SinkDefinition]:
        """Get all registered sinks."""
        return self._sinks

    def find_by_type(self, sink_type: SinkType) -> list[SinkDefinition]:
        """Find sinks by type."""
        return [s for s in self._sinks if s.type == sink_type]

    def find_matching(self, code_line: str) -> list[SinkDefinition]:
        """Find all sinks that match a code line."""
        return [s for s in self._sinks if s.matches(code_line)]

    def add_custom(self, sink: SinkDefinition) -> None:
        """Add a custom sink definition."""
        self._sinks.append(sink)


# Global registry instances
source_registry = SourceRegistry()
sink_registry = SinkRegistry()
