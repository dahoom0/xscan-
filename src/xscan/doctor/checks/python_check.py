"""Python version and required package check."""
from __future__ import annotations
import sys
from xscan.doctor.checks.base import BaseCheck
from xscan.services.doctor import HealthResult

MIN_PYTHON = (3, 11)
REQUIRED_PACKAGES = ["pydantic", "httpx", "rich", "typer", "bs4"]


class PythonCheck(BaseCheck):
    name = "python"

    def run(self) -> HealthResult:
        version = sys.version_info[:2]
        if version < MIN_PYTHON:
            return HealthResult(
                name=self.name,
                ok=False,
                detail=f"Python {version[0]}.{version[1]} found, need >= {MIN_PYTHON[0]}.{MIN_PYTHON[1]}",
            )

        missing = []
        for pkg in REQUIRED_PACKAGES:
            try:
                __import__(pkg)
            except ImportError:
                missing.append(pkg)

        if missing:
            return HealthResult(
                name=self.name,
                ok=False,
                detail=f"Missing packages: {', '.join(missing)}",
                fix_available=True,
                fix_description=f"pip install {' '.join(missing)}",
            )

        return HealthResult(
            name=self.name,
            ok=True,
            detail=f"Python {sys.version.split()[0]}  all required packages present",
        )
