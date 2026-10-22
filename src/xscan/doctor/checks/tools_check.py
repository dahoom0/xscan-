"""
Security tools health check.
Verifies which Go/binary tools are installed in ~/.xscan/bin or on PATH.
Reports missing tools and offers auto-install via GoInstaller.
"""
from __future__ import annotations

import platform
import shutil
from xscan.doctor.checks.base import BaseCheck
from xscan.services.doctor import HealthResult

# Minimum useful set — must be installed for a complete scan
_CORE_TOOLS = ["katana", "httpx", "dalfox", "subfinder", "ffuf"]
# Nice-to-have but not blocking
_OPTIONAL_TOOLS = ["dnsx", "nuclei", "waybackurls", "gau", "amass"]


class ToolsCheck(BaseCheck):
    name = "tools"

    def run(self) -> HealthResult:
        from xscan.tools.installers.go_installer import GoInstaller, INSTALL_RECIPES
        installer = GoInstaller()

        installed_core    = [t for t in _CORE_TOOLS    if installer.is_installed(t)]
        missing_core      = [t for t in _CORE_TOOLS    if not installer.is_installed(t)]
        installed_opt     = [t for t in _OPTIONAL_TOOLS if installer.is_installed(t)]

        all_installed = installed_core + installed_opt
        detail_parts: list[str] = []
        if all_installed:
            detail_parts.append(f"{len(all_installed)} installed: {', '.join(all_installed)}")
        if missing_core:
            detail_parts.append(f"missing core: {', '.join(missing_core)}")

        if missing_core:
            return HealthResult(
                name=self.name,
                ok=False,
                detail="  ".join(detail_parts) or "No tools installed",
                fix_available=True,
                fix_description=f"xscan install {' '.join(missing_core)}",
            )

        return HealthResult(
            name=self.name,
            ok=True,
            detail="  ".join(detail_parts),
        )

    def fix(self) -> None:
        """Auto-install missing core tools."""
        from xscan.tools.installers.go_installer import GoInstaller
        installer = GoInstaller()
        missing = [t for t in _CORE_TOOLS if not installer.is_installed(t)]
        for tool in missing:
            result = installer.install(tool)
            if not result.success:
                # Try binary download fallback (works without WSL/Go)
                from xscan.tools.installers.binary_installer import download_binary
                download_binary(tool)


class WslCheck(BaseCheck):
    """Check WSL2 availability on Windows — needed to run Go security tools."""
    name = "wsl"

    def run(self) -> HealthResult:
        if platform.system() != "Windows":
            return HealthResult(
                name=self.name, ok=True,
                detail="Not Windows — WSL not required",
            )

        if not shutil.which("wsl.exe"):
            return HealthResult(
                name=self.name, ok=False,
                detail="wsl.exe not found — WSL2 not installed",
                fix_available=True,
                fix_description="Enable WSL2: https://learn.microsoft.com/en-us/windows/wsl/install",
            )

        try:
            import subprocess
            r = subprocess.run(
                ["wsl.exe", "-l", "--running"],
                capture_output=True, timeout=5,
            )
            # WSL outputs UTF-16LE on Windows — decode explicitly
            try:
                output = r.stdout.decode("utf-16-le", errors="replace").strip()
            except Exception:
                output = r.stdout.decode("utf-8", errors="replace").strip()

            if not output or "no distributions" in output.lower():
                return HealthResult(
                    name=self.name, ok=False,
                    detail="WSL2 installed but no distro is running",
                    fix_available=True,
                    fix_description="Start a distro: wsl -d Ubuntu  (or install one from the Microsoft Store)",
                )
            # Parse running distros — skip header line and empty lines
            lines = [l.strip() for l in output.splitlines() if l.strip()]
            running = [l for l in lines[1:] if l and "windows" not in l.lower()]
            names = ", ".join(running[:4]) if running else lines[0][:60]
            return HealthResult(
                name=self.name, ok=True,
                detail=f"WSL2 running  distros: {names}",
            )
        except Exception as exc:
            return HealthResult(
                name=self.name, ok=False,
                detail=f"WSL2 check error: {exc}",
                fix_available=True,
                fix_description="Ensure WSL2 is installed and a Linux distro is running",
            )
