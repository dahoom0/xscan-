"""Repair: re-run database migrations."""
from __future__ import annotations
from xscan.doctor.repairs.base import RepairBase, RepairResult


class MigrateDatabaseRepair(RepairBase):
    name = "migrate_database"
    description = "Re-run database schema migrations"
    permission_required = False

    def check_preconditions(self) -> bool:
        return True

    def execute(self) -> RepairResult:
        try:
            from xscan.storage.database import get_db
            db = get_db()
            db.migrate()
            return RepairResult(
                name=self.name,
                success=True,
                detail="Migrations applied successfully",
                steps_completed=["run_migrations"],
            )
        except Exception as exc:
            return RepairResult(name=self.name, success=False, detail=str(exc))
