"""
Universal tool installer.

Detects the install method from the argument:
  https://github.com/*/XSStrike.git   → git clone + pip install
  https://github.com/*/tool            → git clone + auto-detect (setup.py / go / node / binary)
  github.com/*                         → same as https://github.com/...
  katana / httpx / dalfox / ...        → Go recipe (existing GoInstaller)
  xsstrike / XSStrike                  → known Python tool recipe
  dompurify / DOMPurify                → known Node recipe (npm install + build)

Runs on Windows via WSL2 when available, natively otherwise.
Node/JS tools install natively through npm — they never need WSL2.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from xscan.config.defaults import XSCAN_HOME

_XSCAN_BIN  = XSCAN_HOME / "bin"
_XSCAN_TOOLS = XSCAN_HOME / "tools"

# Known Python tools with their recipes
_PYTHON_RECIPES: dict[str, dict] = {
    "xsstrike": {
        "git_url":    "https://github.com/s0md3v/XSStrike.git",
        "entry":      "xsstrike.py",
        "pip_deps":   ["requests", "fuzzywuzzy", "prettytable"],
        "description": "Advanced XSS scanner with blind XSS, DOM analysis and fuzzing",
    },
    "dalfox": {
        # Override: dalfox has a Go recipe but also a direct binary release
        "go_pkg": "github.com/hahwul/dalfox/v2@latest",
        "binary": "dalfox",
        "description": "Fast XSS scanner with blind XSS support",
    },
    "kxss": {
        "git_url":   "https://github.com/Emoe/kxss.git",
        "go_pkg":    "github.com/Emoe/kxss@latest",
        "binary":    "kxss",
        "description": "Find reflected XSS parameters",
    },
    "freq": {
        "go_pkg":    "github.com/takshal/freq@latest",
        "binary":    "freq",
        "description": "Fast URL frequency analyser",
    },
}


# Known Node/JavaScript tools — installed with npm, never with pip or Go.
# Every entry is hardcoded and reviewed, like the Go and Python recipes.
_NODE_RECIPES: dict[str, dict] = {
    "dompurify": {
        "git_url":   "https://github.com/cure53/DOMPurify.git",
        "build":     "build",
        "artifacts": ["dist/purify.js", "dist/purify.min.js", "dist/purify.cjs.js"],
        "description": "XSS sanitizer - powers the dompurify-scan pipeline node",
    },
}


@dataclass
class InstallResult:
    tool_name: str
    success: bool
    binary_path: str = ""
    install_dir: str = ""
    error: str = ""
    method: str = ""
    note: str = ""


class UniversalInstaller:
    """
    Detect what is being installed and use the right method.

    Priority:
      1. GitHub URL → clone + detect (Python / Go / binary)
      2. Known Python recipe name
      3. Known Go recipe name (delegate to GoInstaller)
      4. Unknown → error with suggestions
    """

    def __init__(self) -> None:
        _XSCAN_BIN.mkdir(parents=True, exist_ok=True)
        _XSCAN_TOOLS.mkdir(parents=True, exist_ok=True)

    def install(self, arg: str, progress_cb=None) -> InstallResult:
        arg = arg.strip()
        normalised = arg.lower()

        # ── GitHub URL ─────────────────────────────────────────────────
        if "github.com" in normalised:
            return self._install_from_github(arg, progress_cb)

        # ── Normalise name ─────────────────────────────────────────────
        name = normalised.replace("-", "").replace("_", "").replace(".git", "")

        # ── Known Python recipe ────────────────────────────────────────
        for recipe_name, recipe in _PYTHON_RECIPES.items():
            if recipe_name in name or name in recipe_name:
                if "go_pkg" in recipe:
                    return self._install_go_recipe(recipe_name, recipe, progress_cb)
                return self._install_python_recipe(recipe_name, recipe, progress_cb)

        # ── Known Node/JS recipe ───────────────────────────────────────
        for recipe_name, recipe in _NODE_RECIPES.items():
            if recipe_name in name or name in recipe_name:
                return self._install_node_recipe(recipe_name, recipe, progress_cb=progress_cb)

        # ── Go installer ───────────────────────────────────────────────
        from xscan.tools.installers.go_installer import GoInstaller, INSTALL_RECIPES
        for recipe_key in INSTALL_RECIPES:
            if recipe_key.replace("-", "") in name or name in recipe_key.replace("-", ""):
                return self._wrap_go(recipe_key, progress_cb)

        # ── Unknown ────────────────────────────────────────────────────
        from xscan.tools.installers.go_installer import INSTALL_RECIPES as GO_R
        available = (
            list(GO_R.keys())
            + [k for k in _PYTHON_RECIPES if "git_url" in _PYTHON_RECIPES[k]]
            + list(_NODE_RECIPES.keys())
        )
        return InstallResult(
            tool_name=arg, success=False,
            error=f"Unknown tool '{arg}'.\n"
                  f"  Pass a full GitHub URL:  xscan install https://github.com/s0md3v/XSStrike.git\n"
                  f"  Known tools: {', '.join(sorted(available))}",
        )

    # ------------------------------------------------------------------
    # GitHub URL installation
    # ------------------------------------------------------------------

    def _install_from_github(self, url: str, progress_cb) -> InstallResult:
        if not url.startswith("http"):
            url = "https://" + url.lstrip("/")

        parsed = urlparse(url)
        path_parts = parsed.path.strip("/").split("/")
        if len(path_parts) < 2:
            return InstallResult(tool_name=url, success=False,
                                 error="Cannot parse GitHub URL.")

        repo_name = path_parts[1].replace(".git", "")
        clone_dir = _XSCAN_TOOLS / repo_name
        name_lower = repo_name.lower().replace("-", "").replace("_", "")

        # Check known recipes first
        for recipe_name, recipe in _PYTHON_RECIPES.items():
            if recipe_name in name_lower or name_lower in recipe_name:
                recipe = dict(recipe)
                recipe["git_url"] = url  # use provided URL
                return self._install_python_recipe(recipe_name, recipe, progress_cb)

        # Known Node/JS recipe (e.g. DOMPurify)
        for recipe_name, recipe in _NODE_RECIPES.items():
            if recipe_name in name_lower or name_lower in recipe_name:
                recipe = dict(recipe)
                recipe["git_url"] = url  # use provided URL
                # Reuse the clone directory derived from the URL so a URL
                # install does not create a second, lowercase copy.
                return self._install_node_recipe(
                    recipe_name, recipe, clone_dir=clone_dir, progress_cb=progress_cb,
                )

        if progress_cb:
            progress_cb(f"Cloning {url}")

        # Clone
        clone_ok = self._git_clone(url, clone_dir, progress_cb)
        if not clone_ok:
            return InstallResult(
                tool_name=repo_name, success=False,
                error=f"git clone failed for {url}",
            )

        # Auto-detect project type
        if (clone_dir / "setup.py").exists() or (clone_dir / "pyproject.toml").exists():
            return self._pip_install_cloned(repo_name, clone_dir, progress_cb)
        if (clone_dir / "go.mod").exists():
            return self._go_build_cloned(repo_name, clone_dir, progress_cb)
        if (clone_dir / "package.json").exists():
            # Node/JS project — install dependencies and build (no recipe known)
            return self._install_node_recipe(
                repo_name, {}, clone_dir=clone_dir, progress_cb=progress_cb,
            )
        if any(clone_dir.glob("*.py")):
            return self._create_python_launcher(repo_name, clone_dir, progress_cb)

        return InstallResult(
            tool_name=repo_name, success=True,
            install_dir=str(clone_dir),
            note=f"Cloned to {clone_dir}. Run manually: cd {clone_dir}",
            method="git-clone",
        )

    # ------------------------------------------------------------------
    # Python recipe
    # ------------------------------------------------------------------

    def _install_python_recipe(self, name: str, recipe: dict, progress_cb) -> InstallResult:
        clone_dir = _XSCAN_TOOLS / name

        # Clone if needed
        git_url = recipe.get("git_url", "")
        if git_url and not clone_dir.exists():
            if progress_cb:
                progress_cb(f"Cloning {git_url}")
            if not self._git_clone(git_url, clone_dir, progress_cb):
                return InstallResult(tool_name=name, success=False,
                                     error="git clone failed", method="python")

        # Install pip dependencies
        deps = recipe.get("pip_deps", [])
        if deps:
            if progress_cb:
                progress_cb(f"Installing Python dependencies: {', '.join(deps)}")
            try:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install"] + deps,
                    capture_output=True, text=True, timeout=120,
                )
            except Exception as exc:
                if progress_cb:
                    progress_cb(f"  Warning: pip install failed: {exc}")

        # Install the package itself if setup.py exists
        if clone_dir.exists() and (clone_dir / "setup.py").exists():
            return self._pip_install_cloned(name, clone_dir, progress_cb)

        # Create launcher script
        entry = recipe.get("entry", f"{name}.py")
        if clone_dir.exists() and (clone_dir / entry).exists():
            return self._create_python_launcher(name, clone_dir, progress_cb, entry)

        return InstallResult(
            tool_name=name, success=bool(clone_dir.exists()),
            install_dir=str(clone_dir),
            method="python",
            note=f"Installed to {clone_dir}",
        )

    # ------------------------------------------------------------------
    # Go recipe
    # ------------------------------------------------------------------

    def _install_go_recipe(self, name: str, recipe: dict, progress_cb) -> InstallResult:
        from xscan.tools.installers.go_installer import GoInstaller, InstallResult as GR
        result = GoInstaller().install(name, progress_cb)
        return InstallResult(
            tool_name=result.tool_name,
            success=result.success,
            binary_path=result.binary_path,
            error=result.error,
            method=result.method,
        )

    def _wrap_go(self, name: str, progress_cb) -> InstallResult:
        """Try binary download first, then Go install."""
        from xscan.tools.installers.binary_installer import download_binary, _GITHUB_REPOS
        if name in _GITHUB_REPOS:
            if progress_cb:
                progress_cb(f"Trying binary download for {name}...")
            r = download_binary(name, progress_cb)
            if r.success:
                return InstallResult(
                    tool_name=r.tool_name, success=True,
                    binary_path=r.binary_path, method=r.method,
                )
            if progress_cb:
                progress_cb(f"  Binary download failed ({r.error}) — trying Go install...")
        return self._install_go_recipe(name, {}, progress_cb)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _git_clone(self, url: str, dest: Path, progress_cb) -> bool:
        if dest.exists():
            if progress_cb:
                progress_cb(f"  Already cloned at {dest} — pulling latest")
            try:
                subprocess.run(["git", "pull"], cwd=str(dest),
                               capture_output=True, timeout=60)
                return True
            except Exception:
                return True  # already there, ok

        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", url, str(dest)],
                capture_output=True, text=True, timeout=120,
            )
            return result.returncode == 0
        except Exception:
            # Try via WSL2
            try:
                import platform
                if platform.system() == "Windows" and shutil.which("wsl.exe"):
                    wsl_dest = "/root/.xscan/tools/" + dest.name
                    result = subprocess.run(
                        ["wsl.exe", "--", "git", "clone", "--depth", "1", url, wsl_dest],
                        capture_output=True, text=True, timeout=120,
                    )
                    return result.returncode == 0
            except Exception:
                pass
            return False

    def _pip_install_cloned(self, name: str, clone_dir: Path, progress_cb) -> InstallResult:
        if progress_cb:
            progress_cb(f"  pip install -e {clone_dir}")
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "-e", str(clone_dir)],
                capture_output=True, text=True, timeout=180,
            )
            success = result.returncode == 0
            return InstallResult(
                tool_name=name, success=success,
                install_dir=str(clone_dir),
                error=result.stderr[:200] if not success else "",
                method="pip-editable",
                note=f"Installed as editable package from {clone_dir}",
            )
        except Exception as exc:
            return InstallResult(tool_name=name, success=False, error=str(exc), method="pip")

    def _go_build_cloned(self, name: str, clone_dir: Path, progress_cb) -> InstallResult:
        if progress_cb:
            progress_cb(f"  go build in {clone_dir}")
        try:
            result = subprocess.run(
                ["go", "build", "-o", str(_XSCAN_BIN / name), "./..."],
                cwd=str(clone_dir), capture_output=True, text=True, timeout=180,
            )
            success = result.returncode == 0
            return InstallResult(
                tool_name=name, success=success,
                binary_path=str(_XSCAN_BIN / name) if success else "",
                error=result.stderr[:200] if not success else "",
                method="go-build",
            )
        except Exception as exc:
            return InstallResult(tool_name=name, success=False, error=str(exc), method="go-build")

    # ------------------------------------------------------------------
    # Node / JavaScript recipe
    # ------------------------------------------------------------------

    def _install_node_recipe(
        self,
        name: str,
        recipe: dict[str, Any],
        clone_dir: Path | None = None,
        progress_cb: Callable[[str], None] | None = None,
    ) -> InstallResult:
        """
        Install a Node/JS tool: git clone → npm install → npm run build.

        Tools such as DOMPurify ship a pre-built ``dist/`` inside the repo, so
        the npm steps are skipped whenever the expected artifacts already exist.
        """
        if clone_dir is None:
            clone_dir = _XSCAN_TOOLS / name

        git_url = recipe.get("git_url", "")
        if git_url and not clone_dir.exists():
            if progress_cb:
                progress_cb(f"Cloning {git_url}")
            if not self._git_clone(git_url, clone_dir, progress_cb):
                return InstallResult(
                    tool_name=name, success=False, method="node",
                    error=f"git clone failed for {git_url}",
                )

        if not (clone_dir / "package.json").exists():
            return InstallResult(
                tool_name=name, success=False, method="node",
                error=f"No package.json in {clone_dir} — not a Node project",
            )

        pkg = self._read_package_json(clone_dir)
        version = str(pkg.get("version", "")).strip()
        label = f"v{version}" if version else str(pkg.get("name", name))
        artifacts: list[str] = recipe.get("artifacts", [])
        shipped = [a for a in artifacts if (clone_dir / a).exists()]

        # ── Fast path: the repo already ships its build output ──────────
        if shipped:
            if progress_cb:
                progress_cb(f"  Pre-built artifacts present: {', '.join(shipped)}")
            return InstallResult(
                tool_name=name, success=True, method="node",
                install_dir=str(clone_dir), binary_path=str(clone_dir / shipped[0]),
                note=f"{label} ready at {clone_dir} (build shipped in repository)",
            )

        npm = self._npm_cmd()
        if not npm:
            return InstallResult(
                tool_name=name, success=False, method="node",
                error="npm not found. Install Node.js from https://nodejs.org/",
            )

        if not (clone_dir / "node_modules").exists():
            if progress_cb:
                progress_cb("  npm install …")
            code, output = self._run_npm([npm, "install", "--no-audit", "--no-fund"], clone_dir)
            if code != 0:
                return InstallResult(
                    tool_name=name, success=False, method="node",
                    error=f"npm install failed: {output[:300]}",
                )

        build = recipe.get("build", "")
        if build:
            if progress_cb:
                progress_cb(f"  npm run {build} …")
            code, output = self._run_npm([npm, "run", build], clone_dir)
            if code != 0:
                return InstallResult(
                    tool_name=name, success=False, method="node",
                    error=f"npm run {build} failed: {output[:300]}",
                )

        built = [a for a in artifacts if (clone_dir / a).exists()]
        if artifacts and not built:
            return InstallResult(
                tool_name=name, success=False, method="node",
                error=f"build finished but none of {artifacts} were produced",
            )

        return InstallResult(
            tool_name=name, success=True, method="node",
            install_dir=str(clone_dir),
            binary_path=str(clone_dir / built[0]) if built else str(clone_dir),
            note=f"{label} ready at {clone_dir} (built from source)",
        )

    @staticmethod
    def _read_package_json(clone_dir: Path) -> dict[str, Any]:
        try:
            data = json.loads((clone_dir / "package.json").read_text(encoding="utf-8"))
        except Exception:
            return {}
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _npm_cmd() -> str | None:
        """Resolve the npm executable (npm.cmd on Windows)."""
        for candidate in ("npm", "npm.cmd"):
            found = shutil.which(candidate)
            if found:
                return found
        return None

    @staticmethod
    def _run_npm(args: list[str], cwd: Path) -> tuple[int, str]:
        try:
            result = subprocess.run(
                args, cwd=str(cwd), capture_output=True, text=True, timeout=600,
            )
        except Exception as exc:
            return 1, str(exc)
        return result.returncode, (result.stderr or result.stdout or "")

    def _create_python_launcher(
        self, name: str, clone_dir: Path, progress_cb,
        entry: str = "",
    ) -> InstallResult:
        """Create a small launcher script in ~/.xscan/bin/."""
        if not entry:
            # Find main python file
            candidates = list(clone_dir.glob("*.py"))
            entry_path = next(
                (f for f in candidates if f.stem.lower() in (name, name.replace("-", ""), "main")),
                candidates[0] if candidates else None,
            )
            if entry_path:
                entry = entry_path.name

        if not entry:
            return InstallResult(tool_name=name, success=True,
                                 install_dir=str(clone_dir), method="git-clone",
                                 note=f"Cloned to {clone_dir}. No launcher created.")

        launcher = _XSCAN_BIN / name
        launcher_content = f"""#!/usr/bin/env python3
import sys, os
sys.path.insert(0, r"{clone_dir}")
os.chdir(r"{clone_dir}")
exec(open(r"{clone_dir / entry}").read())
"""
        launcher.write_text(launcher_content, encoding="utf-8")
        try:
            launcher.chmod(0o755)
        except Exception:
            pass

        if progress_cb:
            progress_cb(f"  Launcher created: {launcher}")

        return InstallResult(
            tool_name=name,
            success=True,
            binary_path=str(launcher),
            install_dir=str(clone_dir),
            method="python-launcher",
            note=f"Run with: python {clone_dir / entry}",
        )
