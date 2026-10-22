"""
ToolAdapter base — contract for all tool adapters.

Every adapter:
  1. Receives a Runtime (never calls subprocess directly)
  2. Checks scope before execution
  3. Returns a typed ReconToolObservation
  4. Distinguishes all failure states explicitly
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from datetime import datetime, UTC

from xscan.runtime.base import ExecutionRuntime
from xscan.schemas.recon import ReconToolObservation, ReconToolStatus


class ToolAdapterBase(ABC):
    """
    Abstract base for tool adapters.
    Subclasses implement `_build_command` and `_parse_output`.
    """

    tool_name:    str = "unknown"
    capability:   str = ""
    default_timeout: int = 120

    def __init__(self, runtime: ExecutionRuntime) -> None:
        self._runtime = runtime

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self, target: str, **kwargs) -> ReconToolObservation:
        """
        Execute the tool against `target`.
        Returns a typed observation with explicit status.
        """
        obs = ReconToolObservation(
            tool=self.tool_name,
            capability=self.capability,
            target=target,
        )
        t0 = datetime.now(UTC)

        # Check the binary is available
        binary = self._runtime.which(self._executable())
        if not binary:
            obs.status = ReconToolStatus.TOOL_UNAVAILABLE
            obs.observation = f"{self.tool_name} binary not found in runtime"
            obs.finished_at = datetime.now(UTC)
            return obs

        obs.version = self._get_version()

        # Build and execute
        cmd = self._build_command(target, **kwargs)
        timeout = kwargs.get("timeout", self.default_timeout)

        result = self._runtime.run(cmd, timeout=timeout)
        obs.duration_ms = (datetime.now(UTC) - t0).total_seconds() * 1000
        obs.finished_at = datetime.now(UTC)
        obs.raw_output  = ((result.stdout or "") + (result.stderr or ""))[:2000]

        # Map result to status
        if result.timed_out:
            obs.status      = ReconToolStatus.TIMEOUT
            obs.observation = f"{self.tool_name} timed out after {timeout}s"
            return obs

        if result.exit_code != 0 and not result.stdout.strip():
            obs.status      = ReconToolStatus.EXECUTION_FAILED
            obs.observation = f"exit_code={result.exit_code}  stderr={result.stderr[:200]}"
            return obs

        # Parse results
        results = self._parse_output(result.stdout, target)
        obs.results = results

        if results:
            obs.status      = ReconToolStatus.COMPLETED_WITH_RESULTS
            obs.observation = f"{self.tool_name}: {len(results)} result(s)"
        else:
            obs.status      = ReconToolStatus.COMPLETED_NO_RESULTS
            obs.observation = f"{self.tool_name}: no results"

        return obs

    # ------------------------------------------------------------------
    # Subclass contract
    # ------------------------------------------------------------------

    @abstractmethod
    def _executable(self) -> str:
        """Return the binary name (not full path)."""
        ...

    @abstractmethod
    def _build_command(self, target: str, **kwargs) -> list[str]:
        """Return the full command list to pass to runtime.run()."""
        ...

    @abstractmethod
    def _parse_output(self, stdout: str, target: str) -> list[str]:
        """Parse stdout → list of discovered hostnames/URLs/paths."""
        ...

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_version(self) -> str:
        for flag in ["--version", "version", "-version", "-v"]:
            result = self._runtime.run([self._executable(), flag], timeout=5)
            if result.exit_code == 0 and result.stdout.strip():
                return result.stdout.strip().splitlines()[0][:60]
        return ""
