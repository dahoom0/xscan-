"""XScan execution runtime abstraction."""
from xscan.runtime.base import ExecutionRuntime, ProcessResult
from xscan.runtime.local import LocalRuntime
from xscan.runtime.wsl import WSLRuntime
from xscan.runtime.resolver import get_runtime

__all__ = ["ExecutionRuntime", "ProcessResult", "LocalRuntime", "WSLRuntime", "get_runtime"]
