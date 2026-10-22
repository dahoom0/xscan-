"""Subfinder adapter — passive subdomain enumeration."""
from __future__ import annotations
import re
from xscan.tools.adapters.base import ToolAdapterBase


class SubfinderAdapter(ToolAdapterBase):
    tool_name = "subfinder"
    capability = "subdomain_enum"
    default_timeout = 120

    def _executable(self) -> str:
        return "subfinder"

    def _build_command(self, target: str, **kwargs) -> list[str]:
        # Extract domain from URL if needed
        domain = _extract_domain(target)
        cmd = ["subfinder", "-d", domain, "-silent"]
        if kwargs.get("all_sources"):
            cmd.append("-all")
        return cmd

    def _parse_output(self, stdout: str, target: str) -> list[str]:
        """Each line is a discovered hostname."""
        hostnames = []
        domain = _extract_domain(target)
        for line in stdout.splitlines():
            line = line.strip().lower()
            if not line or line.startswith("["):
                continue
            # Validate it looks like a hostname
            if re.match(r'^[a-z0-9][a-z0-9\.\-]*[a-z0-9]$', line):
                hostnames.append(line)
        return list(dict.fromkeys(hostnames))  # deduplicate, preserve order


def _extract_domain(target: str) -> str:
    from urllib.parse import urlparse
    if target.startswith(("http://", "https://")):
        return urlparse(target).hostname or target
    return target.split("/")[0]
