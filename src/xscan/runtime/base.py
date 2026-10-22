"""
ExecutionRuntime base contract.

All tool execution flows through this interface.
Nodes never call subprocess directly.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ProcessResult:
    command: list[str]
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


class ExecutionRuntime(ABC):
    """Abstract execution environment."""

    @abstractmethod
    def run(
        self,
        command: list[str],
        timeout: int = 120,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
    ) -> ProcessResult: ...

    @abstractmethod
    def which(self, executable: str) -> str | None:
        """Return full path to executable, or None."""
        ...

    @abstractmethod
    def available(self) -> bool:
        """Return True if this runtime is usable on the current machine."""
        ...
