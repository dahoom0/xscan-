"""
ToolRegistry
============
Process-wide catalogue of all known security tools.

Key rules:
  - Tools are identified by a unique registry *name* (e.g. "projectdiscovery-httpx"),
    NOT by their binary name alone.
  - Resolving by capability prevents binary-name collisions.
  - Health checks use the runtime abstraction, not raw subprocess.
  - Tool installation uses typed repair recipes, not LLM-generated commands.
"""
from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Any

from xscan.config.defaults import XSCAN_HOME
from xscan.errors import ToolNotFoundError, CapabilityNotAvailableError
from xscan.schemas.tool import Capability, Tool, ToolHealth, ToolStatus
from xscan.tools.capabilities import CAPABILITY_TOOL_MAP

logger = logging.getLogger(__name__)

_XSCAN_BIN = XSCAN_HOME / "bin"

# ── Built-in tool catalogue ────────────────────────────────────────────────

_CATALOGUE: list[Tool] = [
    Tool(
        name="katana",
        display_name="Katana (ProjectDiscovery)",
        executable="katana",
        capabilities=[Capability.WEB_CRAWLER],
        platform=["linux", "darwin", "windows"],
        source_url="https://github.com/projectdiscovery/katana",
        install_via="go",
        description="Fast web crawler for attack surface discovery",
    ),
    Tool(
        name="projectdiscovery-httpx",
        display_name="httpx (ProjectDiscovery)",
        executable="httpx",
        capabilities=[Capability.HTTP_PROBE],
        platform=["linux", "darwin", "windows"],
        source_url="https://github.com/projectdiscovery/httpx",
        install_via="go",
        description="Fast HTTP probe — distinct from Python httpx package",
    ),
    Tool(
        name="dnsx",
        display_name="dnsx (ProjectDiscovery)",
        executable="dnsx",
        capabilities=[Capability.DNS_RESOLUTION],
        platform=["linux", "darwin"],
        source_url="https://github.com/projectdiscovery/dnsx",
        install_via="go",
    ),
    Tool(
        name="subfinder",
        display_name="Subfinder (ProjectDiscovery)",
        executable="subfinder",
        capabilities=[Capability.SUBDOMAIN_ENUM],
        platform=["linux", "darwin"],
        source_url="https://github.com/projectdiscovery/subfinder",
        install_via="go",
    ),
    Tool(
        name="nuclei",
        display_name="Nuclei (ProjectDiscovery)",
        executable="nuclei",
        capabilities=[Capability.VULN_SCAN],
        platform=["linux", "darwin"],
        source_url="https://github.com/projectdiscovery/nuclei",
        install_via="go",
    ),
    Tool(
        name="ffuf",
        display_name="ffuf",
        executable="ffuf",
        capabilities=[Capability.FUZZING],
        platform=["linux", "darwin", "windows"],
        source_url="https://github.com/ffuf/ffuf",
        install_via="go",
    ),
    Tool(
        name="dalfox",
        display_name="DalFox",
        executable="dalfox",
        capabilities=[Capability.XSS_SCAN],
        platform=["linux", "darwin"],
        source_url="https://github.com/hahwul/dalfox",
        install_via="go",
    ),
    Tool(
        name="waybackurls",
        display_name="waybackurls",
        executable="waybackurls",
        capabilities=[Capability.URL_DISCOVERY],
        platform=["linux", "darwin"],
        source_url="https://github.com/tomnomnom/waybackurls",
        install_via="go",
    ),
    Tool(
        name="amass",
        display_name="Amass (OWASP)",
        executable="amass",
        capabilities=[Capability.SUBDOMAIN_ENUM],
        platform=["linux", "darwin"],
        source_url="https://github.com/owasp-amass/amass",
        install_via="go",
    ),
]


class ToolRegistry:
    """
    Registry of all known tools.

    Usage::

        registry = ToolRegistry()
        tool = registry.resolve_capability(Capability.WEB_CRAWLER)
        health = registry.health(tool.name)
    """

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {t.name: t for t in _CATALOGUE}

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------

    def get(self, name: str) -> Tool:
        if name not in self._tools:
            raise ToolNotFoundError(
                f"Tool '{name}' not in registry.", name=name
            )
        return self._tools[name]

    def resolve_capability(self, capability: Capability) -> Tool:
        """
        Return the first installed tool that provides *capability*.
        Raises CapabilityNotAvailableError if none installed.
        """
        preferred = CAPABILITY_TOOL_MAP.get(capability, [])
        for tool_name in preferred:
            if tool_name not in self._tools:
                continue
            tool = self._tools[tool_name]
            if self._is_available(tool):
                return tool
        raise CapabilityNotAvailableError(
            f"No installed tool provides capability '{capability}'. "
            f"Checked: {preferred}"
        )

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health(self, name: str) -> ToolHealth:
        tool = self.get(name)
        return self._check_health(tool)

    def check_all(self) -> list[dict[str, Any]]:
        return [
            {"name": t.name, **self._check_health(t).model_dump()}
            for t in self._tools.values()
        ]

    def check_one(self, name: str) -> dict[str, Any]:
        tool = self.get(name)
        return {"name": name, **self._check_health(tool).model_dump()}

    # ------------------------------------------------------------------
    # Listing / inspection
    # ------------------------------------------------------------------

    def list_with_health(self) -> list[dict[str, Any]]:
        result = []
        for tool in self._tools.values():
            h = self._check_health(tool)
            result.append({
                "name":         tool.name,
                "display_name": tool.display_name or tool.name,
                "capabilities": [c.value for c in tool.capabilities],
                "status":       h.status.value,
                "version":      h.version,
                "binary_path":  h.binary_path,
                "description":  tool.description,
            })
        return result

    def inspect(self, name: str) -> dict[str, Any]:
        tool = self.get(name)
        health = self._check_health(tool)
        return {
            "name":         tool.name,
            "display_name": tool.display_name,
            "capabilities": [c.value for c in tool.capabilities],
            "platform":     tool.platform,
            "source_url":   tool.source_url,
            "install_via":  tool.install_via,
            "description":  tool.description,
            "status":       health.status.value,
            "version":      health.version,
            "binary_path":  health.binary_path,
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _is_available(self, tool: Tool) -> bool:
        return bool(self._find_binary(tool.executable))

    def _check_health(self, tool: Tool) -> ToolHealth:
        from datetime import datetime, UTC
        binary = self._find_binary(tool.executable)
        if not binary:
            return ToolHealth(
                status=ToolStatus.MISSING,
                checked_at=datetime.now(UTC).isoformat(),
            )
        version = self._get_version(binary)
        return ToolHealth(
            status=ToolStatus.INSTALLED,
            version=version,
            binary_path=str(binary),
            checked_at=datetime.now(UTC).isoformat(),
        )

    @staticmethod
    def _find_binary(executable: str) -> Path | None:
        """
        Look for executable in ~/.xscan/bin first, then PATH.
        Never returns a match for the Python httpx CLI when looking for
        the ProjectDiscovery httpx — callers use tool *names*, not executables.
        """
        # ~/.xscan/bin takes priority
        xscan_bin = _XSCAN_BIN / executable
        if xscan_bin.exists():
            return xscan_bin
        xscan_bin_exe = _XSCAN_BIN / (executable + ".exe")
        if xscan_bin_exe.exists():
            return xscan_bin_exe
        # System PATH
        found = shutil.which(executable)
        if found:
            return Path(found)
        return None

    @staticmethod
    def _get_version(binary: Path) -> str:
        import subprocess
        for flag in ["--version", "version", "-v"]:
            try:
                out = subprocess.run(
                    [str(binary), flag],
                    capture_output=True, text=True, timeout=5,
                )
                line = (out.stdout or out.stderr or "").strip().splitlines()
                if line:
                    return line[0][:60]
            except Exception:
                continue
        return ""


# Module-level singleton
tool_registry = ToolRegistry()
