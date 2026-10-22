"""Assetfinder adapter — passive subdomain enumeration."""
from __future__ import annotations
import re
from xscan.tools.adapters.base import ToolAdapterBase
from xscan.tools.adapters.subfinder import _extract_domain


class AssetfinderAdapter(ToolAdapterBase):
    tool_name = "assetfinder"
    capability = "subdomain_enum"
    default_timeout = 60

    def _executable(self) -> str:
        return "assetfinder"

    def _build_command(self, target: str, **kwargs) -> list[str]:
        domain = _extract_domain(target)
        subs_only = kwargs.get("subs_only", True)
        cmd = ["assetfinder", domain]
        if subs_only:
            cmd = ["assetfinder", "--subs-only", domain]
        return cmd

    def _parse_output(self, stdout: str, target: str) -> list[str]:
        hostnames = []
        for line in stdout.splitlines():
            line = line.strip().lower()
            if not line:
                continue
            if re.match(r'^[a-z0-9][a-z0-9\.\-]*[a-z0-9]$', line):
                hostnames.append(line)
        return list(dict.fromkeys(hostnames))
