"""DoctorService — runs environment health checks and optionally repairs."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class HealthResult:
    name: str
    ok: bool
    detail: str = ""
    fix_available: bool = False
    fix_description: str = ""


@dataclass
class DoctorReport:
    results: list[HealthResult] = field(default_factory=list)

    @property
    def all_ok(self) -> bool:
        return all(r.ok for r in self.results)

    @property
    def failed(self) -> list[HealthResult]:
        return [r for r in self.results if not r.ok]

    def to_dict(self) -> dict[str, Any]:
        return {
            "all_ok": self.all_ok,
            "results": [
                {"name": r.name, "ok": r.ok, "detail": r.detail}
                for r in self.results
            ],
        }


class DoctorService:
    def run(self, fix: bool = False, json_output: bool = False) -> DoctorReport:
        from xscan.doctor.checks.python_check import PythonCheck
        from xscan.doctor.checks.ollama_check import OllamaCheck
        from xscan.doctor.checks.database_check import DatabaseCheck
        from xscan.doctor.checks.config_check import ConfigCheck
        from xscan.doctor.checks.tools_check import ToolsCheck, WslCheck

        checks = [PythonCheck(), OllamaCheck(), DatabaseCheck(), ConfigCheck(), WslCheck(), ToolsCheck()]
        report = DoctorReport()

        for check in checks:
            result = check.run()
            report.results.append(result)
            if not result.ok and fix and result.fix_available:
                logger.info("Attempting fix for: %s", result.name)
                check.fix()

        return report
