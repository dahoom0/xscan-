"""
Binary installer — downloads pre-built binaries directly from GitHub releases.
Works on Windows without Go or WSL2.
"""
from __future__ import annotations

import io
import json as _json
import platform
import shutil
import urllib.request
import zipfile
import tarfile
from dataclasses import dataclass
from pathlib import Path

from xscan.config.defaults import XSCAN_HOME

_BIN = XSCAN_HOME / "bin"

# GitHub repos for each tool — used to query the releases API
_GITHUB_REPOS: dict[str, str] = {
    "dalfox":    "hahwul/dalfox",
    "katana":    "projectdiscovery/katana",
    "httpx":     "projectdiscovery/httpx",
    "nuclei":    "projectdiscovery/nuclei",
    "dnsx":      "projectdiscovery/dnsx",
    "subfinder": "projectdiscovery/subfinder",
    "ffuf":      "ffuf/ffuf",
}

# Platform → filename fragment patterns (checked against asset names in the release)
_OS_PATTERNS: dict[str, list[str]] = {
    "windows_amd64": ["windows_amd64", "windows_x86_64"],
    "windows_arm64": ["windows_arm64"],
    "linux_amd64":   ["linux_amd64", "linux_x86_64"],
    "linux_arm64":   ["linux_arm64"],
    "darwin_amd64":  ["darwin_amd64", "macos_amd64", "macos_x86_64"],
    "darwin_arm64":  ["darwin_arm64", "macos_arm64"],
}


@dataclass
class BinaryInstallResult:
    tool_name: str
    success: bool
    binary_path: str = ""
    error: str = ""
    method: str = "binary-download"


def _os_arch() -> str:
    os_name = platform.system().lower()
    arch    = platform.machine().lower()
    if os_name == "windows":
        os_name = "windows"
    elif os_name == "darwin":
        os_name = "darwin"
    else:
        os_name = "linux"
    if arch in ("x86_64", "amd64"):
        arch = "amd64"
    elif arch in ("arm64", "aarch64"):
        arch = "arm64"
    return f"{os_name}_{arch}"


def _resolve_url(tool_name: str, os_arch: str) -> str:
    """
    Query the GitHub releases API to find the correct download URL.
    Matches against os/arch patterns in the asset filename.
    Falls back to empty string if not found.
    """
    repo = _GITHUB_REPOS.get(tool_name)
    if not repo:
        return ""

    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{repo}/releases/latest",
            headers={"User-Agent": "xscan-installer/1.0",
                     "Accept": "application/vnd.github+json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = _json.loads(resp.read())
    except Exception:
        return ""

    patterns = _OS_PATTERNS.get(os_arch, [os_arch])
    assets = data.get("assets", [])

    for asset in assets:
        name = asset.get("name", "").lower()
        if not name.endswith((".zip", ".tar.gz")):
            continue
        for pat in patterns:
            if pat in name:
                return asset.get("browser_download_url", "")

    return ""


def download_binary(tool_name: str, progress_cb=None) -> BinaryInstallResult:
    """Download a pre-built binary from GitHub releases."""
    _BIN.mkdir(parents=True, exist_ok=True)

    key = _os_arch()

    if progress_cb:
        progress_cb(f"Resolving latest {tool_name} release...")

    url = _resolve_url(tool_name, key)
    if not url:
        return BinaryInstallResult(
            tool_name=tool_name, success=False,
            error=f"No binary release found for {tool_name} on {key}"
        )

    if progress_cb:
        progress_cb(f"Downloading {tool_name} from {url.split('/')[2]}...")

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "xscan-installer/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = resp.read()
    except Exception as exc:
        return BinaryInstallResult(tool_name=tool_name, success=False, error=str(exc))

    # Determine binary name
    exe_suffix = ".exe" if platform.system() == "Windows" else ""
    binary_name = tool_name + exe_suffix
    dest = _BIN / binary_name

    # Extract
    try:
        if url.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                # Find the binary inside the zip
                for name in zf.namelist():
                    stem = Path(name).stem
                    if stem == tool_name or stem == tool_name + ".exe":
                        with zf.open(name) as src, open(dest, "wb") as dst:
                            dst.write(src.read())
                        break
                else:
                    # Fallback: extract first file that looks like a binary
                    for name in zf.namelist():
                        if not name.endswith("/") and "." not in Path(name).name:
                            with zf.open(name) as src, open(dest, "wb") as dst:
                                dst.write(src.read())
                            break

        elif url.endswith(".tar.gz"):
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
                for member in tf.getmembers():
                    stem = Path(member.name).stem
                    if stem == tool_name:
                        f = tf.extractfile(member)
                        if f:
                            dest.write_bytes(f.read())
                        break

        # Make executable on Unix
        if platform.system() != "Windows":
            dest.chmod(0o755)

        if dest.exists() and dest.stat().st_size > 1000:
            if progress_cb:
                progress_cb(f"  Installed to {dest}")
            return BinaryInstallResult(
                tool_name=tool_name, success=True,
                binary_path=str(dest),
            )
        else:
            return BinaryInstallResult(
                tool_name=tool_name, success=False,
                error=f"Extracted file too small or missing: {dest}"
            )

    except Exception as exc:
        return BinaryInstallResult(tool_name=tool_name, success=False, error=str(exc))
