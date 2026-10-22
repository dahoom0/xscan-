"""Tool, Capability, ToolHealth, and ToolStatus schemas."""
from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class Capability(StrEnum):
    """Logical capabilities — nodes request these, not specific tool names."""
    WEB_CRAWLER         = "web_crawler"
    HTTP_PROBE          = "http_probe"
    DNS_RESOLUTION      = "dns_resolution"
    SUBDOMAIN_ENUM      = "subdomain_enum"
    PORT_SCAN           = "port_scan"
    VULN_SCAN           = "vuln_scan"
    FUZZING             = "fuzzing"
    URL_DISCOVERY       = "url_discovery"
    JAVASCRIPT_ANALYSIS = "javascript_analysis"
    BROWSER             = "browser"
    XSS_SCAN            = "xss_scan"
    SCREENSHOT          = "screenshot"


class ToolStatus(StrEnum):
    INSTALLED   = "installed"
    MISSING     = "missing"
    UNHEALTHY   = "unhealthy"
    UNKNOWN     = "unknown"


class ToolHealth(BaseModel):
    status: ToolStatus
    version: str = ""
    binary_path: str = ""
    error: str = ""
    checked_at: str = ""


class Tool(BaseModel):
    """
    A registered security tool.

    name must be globally unique within the registry.
    executable is the actual binary name on PATH / in xscan bin dir.
    """
    name: str                           # e.g. "projectdiscovery-httpx"
    display_name: str = ""              # e.g. "httpx (ProjectDiscovery)"
    executable: str                     # e.g. "httpx"
    capabilities: list[Capability] = Field(default_factory=list)
    platform: list[str] = Field(default_factory=lambda: ["linux"])
    source_url: str = ""
    install_via: str = "go"             # go | pip | apt | brew | manual
    health: ToolHealth | None = None
    description: str = ""
