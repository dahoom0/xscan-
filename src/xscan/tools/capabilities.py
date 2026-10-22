"""
Capability catalogue and resolution.

Tools are resolved by *capability* not by hardcoded binary name.
This prevents mistaking the Python httpx CLI for the ProjectDiscovery httpx probe.

Each entry declares:
  - capability enum value
  - preferred tool name
  - fallback tool names (tried in order)
"""
from __future__ import annotations
from xscan.schemas.tool import Capability

# capability → ordered list of tool names to try
CAPABILITY_TOOL_MAP: dict[Capability, list[str]] = {
    Capability.WEB_CRAWLER:         ["katana", "hakrawler", "gospider"],
    Capability.HTTP_PROBE:          ["projectdiscovery-httpx"],   # explicitly NOT "httpx" to avoid Python pkg collision
    Capability.DNS_RESOLUTION:      ["dnsx", "massdns"],
    Capability.SUBDOMAIN_ENUM:      ["subfinder", "amass"],
    Capability.PORT_SCAN:           ["naabu"],
    Capability.VULN_SCAN:           ["nuclei"],
    Capability.FUZZING:             ["ffuf", "feroxbuster"],
    Capability.URL_DISCOVERY:       ["waybackurls", "gau"],
    Capability.JAVASCRIPT_ANALYSIS: ["xscan-js-analyzer"],   # internal
    Capability.BROWSER:             ["playwright-chromium"],
    Capability.XSS_SCAN:            ["dalfox", "kxss"],
    Capability.SCREENSHOT:          ["playwright-chromium"],
}
