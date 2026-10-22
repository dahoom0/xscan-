"""Local (same-process) runtime — Linux/macOS native execution."""
from __future__ import annotations
import shutil
import subprocess
from xscan.runtime.base import ExecutionRuntime, ProcessResult


class LocalRuntime(ExecutionRuntime):
    """Executes commands directly on the local OS (Linux/macOS)."""

    def run(
        self,
        command: list[str],
        timeout: int = 120,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
    ) -> ProcessResult:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                cwd=cwd,
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
        return shutil.which(executable)

    def available(self) -> bool:
        import platform
        return platform.system() in ("Linux", "Darwin")
