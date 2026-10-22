"""Auto-detect the best available runtime for this machine."""
from __future__ import annotations
import platform
from xscan.runtime.base import ExecutionRuntime


def get_runtime() -> ExecutionRuntime:
    """
    Return the appropriate runtime for the current environment.

      Windows → try WSLRuntime first, fall back to LocalRuntime
      Linux/macOS → LocalRuntime
    """
    from xscan.config import get_settings
    settings = get_settings()

    explicit = settings.runtime.execution_env
    if explicit == "wsl":
        from xscan.runtime.wsl import WSLRuntime
        return WSLRuntime(distro=settings.runtime.wsl_distro)
    if explicit == "local":
        from xscan.runtime.local import LocalRuntime
        return LocalRuntime()

    # Auto-detect
    if platform.system() == "Windows":
        from xscan.runtime.wsl import WSLRuntime
        rt = WSLRuntime(distro=settings.runtime.wsl_distro)
        if rt.available():
            return rt
        # Windows without WSL — limited tool support
        from xscan.runtime.local import LocalRuntime
        return LocalRuntime()

    from xscan.runtime.local import LocalRuntime
    return LocalRuntime()
