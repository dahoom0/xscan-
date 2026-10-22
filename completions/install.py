#!/usr/bin/env python3
"""
XScan completion installer.

Usage:
    python completions/install.py
    python completions/install.py --shell bash
    python completions/install.py --shell zsh
    python completions/install.py --shell fish
    python completions/install.py --shell powershell
    python completions/install.py --print          # Print instructions only
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def detect_shell() -> str:
    shell_env = os.environ.get("SHELL", "")
    if "zsh" in shell_env:
        return "zsh"
    if "fish" in shell_env:
        return "fish"
    if "bash" in shell_env:
        return "bash"
    if platform.system() == "Windows":
        return "powershell"
    return "bash"


def install_bash() -> None:
    dest = Path.home() / ".bash_completion.d" / "xscan"
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(HERE / "xscan.bash", dest)
    print(f"[bash] Installed to {dest}")
    print("Add the following to ~/.bashrc if not already present:")
    print("  for f in ~/.bash_completion.d/*; do source \"$f\"; done")


def install_zsh() -> None:
    # Try common fpath locations
    zsh_completions = Path.home() / ".zsh" / "completions"
    zsh_completions.mkdir(parents=True, exist_ok=True)
    dest = zsh_completions / "_xscan"
    shutil.copy(HERE / "xscan.zsh", dest)
    print(f"[zsh] Installed to {dest}")
    print("Ensure your ~/.zshrc contains:")
    print("  fpath=(~/.zsh/completions $fpath)")
    print("  autoload -Uz compinit && compinit")


def install_fish() -> None:
    fish_comp = Path.home() / ".config" / "fish" / "completions"
    fish_comp.mkdir(parents=True, exist_ok=True)
    dest = fish_comp / "xscan.fish"
    shutil.copy(HERE / "xscan.fish", dest)
    print(f"[fish] Installed to {dest}")
    print("Completions are active immediately in new fish sessions.")


def install_powershell() -> None:
    profile_path = os.environ.get("PROFILE", "")
    if not profile_path:
        # Fallback default
        profile_path = str(
            Path.home() / "Documents" / "PowerShell" / "Microsoft.PowerShell_profile.ps1"
        )
    dest = HERE / "xscan.ps1"
    line = f'\n. "{dest}"\n'

    profile = Path(profile_path)
    profile.parent.mkdir(parents=True, exist_ok=True)

    existing = profile.read_text(encoding="utf-8") if profile.exists() else ""
    if str(dest) not in existing:
        with open(profile, "a", encoding="utf-8") as f:
            f.write(line)
        print(f"[powershell] Added to {profile_path}")
    else:
        print(f"[powershell] Already present in {profile_path}")
    print("Restart PowerShell or run: . $PROFILE")


def print_instructions() -> None:
    print(
        """
XScan Shell Completion Installation
=====================================

Bash
----
  source completions/xscan.bash
  # Or install permanently:
  python completions/install.py --shell bash

Zsh
---
  cp completions/xscan.zsh ~/.zsh/completions/_xscan
  # Ensure in ~/.zshrc:
  #   fpath=(~/.zsh/completions $fpath)
  #   autoload -Uz compinit && compinit

Fish
----
  cp completions/xscan.fish ~/.config/fish/completions/xscan.fish

PowerShell
----------
  # Add to $PROFILE:
  . "path\\to\\completions\\xscan.ps1"
  # Or run:
  python completions/install.py --shell powershell

Auto-detect
-----------
  python completions/install.py
"""
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Install XScan shell completions")
    parser.add_argument(
        "--shell",
        choices=["bash", "zsh", "fish", "powershell"],
        default=None,
        help="Target shell (auto-detected if omitted)",
    )
    parser.add_argument(
        "--print",
        action="store_true",
        dest="print_only",
        help="Print installation instructions without installing",
    )
    args = parser.parse_args()

    if args.print_only:
        print_instructions()
        return

    shell = args.shell or detect_shell()
    print(f"Installing completions for: {shell}")

    dispatch = {
        "bash": install_bash,
        "zsh": install_zsh,
        "fish": install_fish,
        "powershell": install_powershell,
    }

    installer = dispatch.get(shell)
    if installer is None:
        print(f"Unsupported shell: {shell}", file=sys.stderr)
        sys.exit(1)

    installer()
    print("Done.")


if __name__ == "__main__":
    main()
