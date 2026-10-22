"""Configuration validity check."""
from __future__ import annotations
from xscan.doctor.checks.base import BaseCheck
from xscan.services.doctor import HealthResult


class ConfigCheck(BaseCheck):
    name = "config"

    def run(self) -> HealthResult:
        try:
            from xscan.config import get_settings
            settings = get_settings()
            return HealthResult(
                name=self.name,
                ok=True,
                detail=f"Config OK  model={settings.llm.model}  db={settings.storage.db_path}",
            )
        except Exception as exc:
            return HealthResult(
                name=self.name,
                ok=False,
                detail=str(exc),
            )
