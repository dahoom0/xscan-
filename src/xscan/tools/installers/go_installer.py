"""
Go-based tool installer.
Installs ProjectDiscovery and other Go security tools.

Installation strategy (Windows with WSL2):
  wsl -- go install <package>@latest
  then copies binary to ~/.xscan/bin/

Installation strategy (Linux/macOS):
  go install <package>@latest
  binary appears in ~/go/bin/ → copied to ~/.xscan/bin/

Does NOT execute LLM-generated commands.
All install recipes are hardcoded and reviewed.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from xscan.config.defaults import XSCAN_HOME

_XSCAN_BIN = XSCAN_HOME / "bin"

# Hardcoded, reviewed install recipes — never from LLM output
INSTALL_RECIPES: dict[str, dict] = {
    "katana": {
        "go_pkg": "github.com/projectdiscovery/katana/cmd/katana@latest",
        "binary": "katana",
        "description": "Fast web crawler (ProjectDiscovery)",
    },
    "httpx": {
        "go_pkg": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "binary": "httpx",
        "description": "HTTP probe (ProjectDiscovery)",
    },
    "dnsx": {
        "go_pkg": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "binary": "dnsx",
        "description": "DNS resolver (ProjectDiscovery)",
    },
    "subfinder": {
        "go_pkg": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "binary": "subfinder",
        "description": "Subdomain enumeration (ProjectDiscovery)",
    },
    "nuclei": {
        "go_pkg": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "binary": "nuclei",
        "description": "Vulnerability scanner (ProjectDiscovery)",
    },
    "ffuf": {
        "go_pkg": "github.com/ffuf/ffuf/v2@latest",
        "binary": "ffuf",
        "description": "Web fuzzer",
    },
    "dalfox": {
        "go_pkg": "github.com/hahwul/dalfox/v2@latest",
        "binary": "dalfox",
        "description": "XSS scanner",
    },
    "waybackurls": {
        "go_pkg": "github.com/tomnomnom/waybackurls@latest",
        "binary": "waybackurls",
        "description": "URL discovery from Wayback Machine",
    },
    "gau": {
        "go_pkg": "github.com/lc/gau/v2/cmd/gau@latest",
        "binary": "gau",
        "description": "URL discovery from multiple sources",
    },
}


@dataclass
class InstallResult:
    tool_name: str
    success: bool
    binary_path: str = ""
    error: str = ""
    method: str = ""


class GoInstaller:
    """
    Installs Go-based security tools.
    Uses WSL2 on Windows, native Go on Linux/macOS.
    """

    def __init__(self) -> None:
        self._bin_dir = _XSCAN_BIN
        self._bin_dir.mkdir(parents=True, exist_ok=True)

    def install(self, tool_name: str, progress_cb=None) -> InstallResult:
        recipe = INSTALL_RECIPES.get(tool_name)
        if not recipe:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                error=f"No install recipe for '{tool_name}'. "
                      f"Available: {', '.join(INSTALL_RECIPES)}",
            )

        if progress_cb:
            progress_cb(f"Installing {tool_name}...")

        # Determine execution method
        import platform
        use_wsl = platform.system() == "Windows" and shutil.which("wsl.exe")

        if use_wsl:
            return self._install_via_wsl(tool_name, recipe, progress_cb)
        else:
            return self._install_native(tool_name, recipe, progress_cb)

    def available_recipes(self) -> list[str]:
        return list(INSTALL_RECIPES.keys())

    def is_installed(self, tool_name: str) -> bool:
        recipe = INSTALL_RECIPES.get(tool_name)
        if not recipe:
            return False
        binary = recipe["binary"]
        return (
            (self._bin_dir / binary).exists() or
            (self._bin_dir / (binary + ".exe")).exists() or
            bool(shutil.which(binary))
        )

    # ------------------------------------------------------------------

    def _install_via_wsl(self, tool_name: str, recipe: dict, progress_cb=None) -> InstallResult:
        """Install inside WSL2, then copy binary to ~/.xscan/bin/."""
        go_pkg = recipe["go_pkg"]
        binary = recipe["binary"]

        if progress_cb:
            progress_cb(f"  go install {go_pkg} (via WSL2)")

        try:
            result = subprocess.run(
                ["wsl.exe", "--", "go", "install", go_pkg],
                capture_output=True, text=True, timeout=180,
            )
            if result.returncode != 0:
                return InstallResult(
                    tool_name=tool_name, success=False,
                    error=result.stderr.strip() or "go install failed",
                    method="wsl",
                )
        except Exception as exc:
            return InstallResult(tool_name=tool_name, success=False, error=str(exc), method="wsl")

        # Copy binary from WSL ~/go/bin/ to ~/.xscan/bin/
        if progress_cb:
            progress_cb(f"  Copying {binary} to ~/.xscan/bin/")

        try:
            # Find the binary inside WSL
            find_result = subprocess.run(
                ["wsl.exe", "--", "sh", "-c", f"which {binary} 2>/dev/null || echo ~/go/bin/{binary}"],
                capture_output=True, text=True, timeout=10,
            )
            wsl_path = find_result.stdout.strip()

            # Convert Windows XSCAN_HOME path to WSL mount path
            # e.g. C:\Users\foo\.xscan\bin  →  /mnt/c/Users/foo/.xscan/bin
            win_path = str(self._bin_dir).replace("\\", "/")
            # Handle drive letter: C:/... → /mnt/c/...
            import re as _re
            wsl_dest = _re.sub(r'^([A-Za-z]):(.*)', lambda m: f"/mnt/{m.group(1).lower()}{m.group(2)}", win_path)

            copy_result = subprocess.run(
                ["wsl.exe", "--", "sh", "-c", f"mkdir -p {wsl_dest!r} && cp {wsl_path!r} {wsl_dest!r}/{binary!r}"],
                capture_output=True, text=True, timeout=30,
            )
            dest_win = self._bin_dir / binary
            if copy_result.returncode == 0 and dest_win.exists():
                return InstallResult(
                    tool_name=tool_name, success=True,
                    binary_path=str(dest_win), method="wsl",
                )
            # Binary stays in WSL — still usable via WSLRuntime
            return InstallResult(
                tool_name=tool_name, success=True,
                binary_path=f"wsl:{wsl_path}", method="wsl",
            )
        except Exception:
            return InstallResult(tool_name=tool_name, success=True,
                                 binary_path="wsl:~/go/bin/" + binary,
                                 method="wsl")

    def _install_native(self, tool_name: str, recipe: dict, progress_cb=None) -> InstallResult:
        """Install natively on Linux/macOS."""
        go_pkg = recipe["go_pkg"]
        binary = recipe["binary"]

        if not shutil.which("go"):
            return InstallResult(
                tool_name=tool_name, success=False,
                error="Go is not installed. Install from https://go.dev/dl/",
                method="native",
            )

        if progress_cb:
            progress_cb(f"  go install {go_pkg}")

        try:
            result = subprocess.run(
                ["go", "install", go_pkg],
                capture_output=True, text=True, timeout=180,
            )
            if result.returncode != 0:
                return InstallResult(
                    tool_name=tool_name, success=False,
                    error=result.stderr.strip(), method="native",
                )
        except Exception as exc:
            return InstallResult(tool_name=tool_name, success=False, error=str(exc), method="native")

        # Copy from GOPATH/bin to ~/.xscan/bin/
        go_bin = Path.home() / "go" / "bin" / binary
        dest = self._bin_dir / binary
        if go_bin.exists():
            shutil.copy2(go_bin, dest)
            return InstallResult(
                tool_name=tool_name, success=True,
                binary_path=str(dest), method="native",
            )

        found = shutil.which(binary)
        return InstallResult(
            tool_name=tool_name,
            success=bool(found),
            binary_path=found or "",
            error="" if found else f"Binary not found after install",
            method="native",
        )
