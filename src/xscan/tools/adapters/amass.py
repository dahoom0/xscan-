"""Amass adapter — comprehensive subdomain enumeration."""
from __future__ import annotations
import re
from xscan.tools.adapters.base import ToolAdapterBase
from xscan.tools.adapters.subfinder import _extract_domain


class AmassAdapter(ToolAdapterBase):
    tool_name = "amass"
    capability = "subdomain_enum"
    default_timeout = 300  # amass is slow

    def _executable(self) -> str:
        return "amass"

    def _build_command(self, target: str, **kwargs) -> list[str]:
        domain = _extract_domain(target)
        passive = kwargs.get("passive", False)
        cmd = ["amass", "enum", "-d", domain, "-silent"]
        if passive:
            cmd.append("-passive")
        return cmd

    def _parse_output(self, stdout: str, target: str) -> list[str]:
        hostnames = []
        for line in stdout.splitlines():
            line = line.strip().lower()
            if not line:
                continue
            # Amass may output "hostname (IP)" or just hostname
            hostname = line.split(" ")[0].split("(")[0].strip()
            if re.match(r'^[a-z0-9][a-z0-9\.\-]*[a-z0-9]$', hostname):
                hostnames.append(hostname)
        return list(dict.fromkeys(hostnames))
