"""
WSLRuntime — proxies tool execution into a WSL2 distro.

Architecture:
  Windows Python process
        ↓
  WSLRuntime.run(["katana", ...])
        ↓
  wsl.exe -d Ubuntu -- katana ...
        ↓
  WSL2 Ubuntu
        ↓
  security tool

Rules:
  - Never constructed from LLM output.
  - distro is read from config, not from arbitrary user input.
  - Commands are passed as a list, never shell=True.
"""
from __future__ import annotations
import shutil
import subprocess
from xscan.errors import WSLError
from xscan.runtime.base import ExecutionRuntime, ProcessResult


class WSLRuntime(ExecutionRuntime):
    """Executes commands inside WSL2."""

    def __init__(self, distro: str = "Ubuntu") -> None:
        self._distro = distro

    def run(
        self,
        command: list[str],
        timeout: int = 120,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
    ) -> ProcessResult:
        if not self.available():
            raise WSLError("WSL2 is not available on this machine.")

        wsl_cmd = ["wsl.exe", "-d", self._distro, "--"]
        if cwd:
            import shlex
            # Use shlex.quote so paths with spaces/special chars don't break the shell
            quoted_cwd = shlex.quote(cwd)
            wsl_cmd += ["sh", "-c", f"cd {quoted_cwd} && " + " ".join(shlex.quote(c) for c in command)]
        else:
            wsl_cmd += command

        try:
            result = subprocess.run(
                wsl_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                # Do NOT pass env — would override the WSL environment
            )
            return ProcessResult(
                command=command,
                exit_code=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
            )
        except subprocess.TimeoutExpired as exc:
            return ProcessResult(
                command=command,
                exit_code=-1,
                stdout="",
                stderr=str(exc),
                timed_out=True,
            )
        except Exception as exc:
            return ProcessResult(
                command=command,
                exit_code=-1,
                stdout="",
                stderr=str(exc),
            )

    def which(self, executable: str) -> str | None:
        """Check if executable exists inside WSL."""
        if not self.available():
            return None
        result = subprocess.run(
            ["wsl.exe", "-d", self._distro, "--", "which", executable],
            capture_output=True, text=True, timeout=5,
        )
        path = result.stdout.strip()
        return path if path else None

    def available(self) -> bool:
        """Return True if wsl.exe exists and the configured distro is running."""
        if not shutil.which("wsl.exe"):
            return False
        try:
            result = subprocess.run(
                ["wsl.exe", "-l", "--running"],
                capture_output=True, text=True, timeout=5,
            )
            return self._distro.lower() in result.stdout.lower()
        except Exception:
            return False
