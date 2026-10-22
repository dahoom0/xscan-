"""Database connectivity and schema check."""
from __future__ import annotations
from xscan.doctor.checks.base import BaseCheck
from xscan.services.doctor import HealthResult


class DatabaseCheck(BaseCheck):
    name = "database"

    def run(self) -> HealthResult:
        try:
            from xscan.storage.database import get_db
            db = get_db()
            row = db.fetchone("SELECT MAX(version) as v FROM schema_version")
            version = row["v"] if row else 0
            return HealthResult(
                name=self.name,
                ok=True,
                detail=f"SQLite schema version {version}",
            )
        except Exception as exc:
            return HealthResult(
                name=self.name,
                ok=False,
                detail=str(exc),
                fix_available=True,
                fix_description="xscan fix 'database migration'",
            )
