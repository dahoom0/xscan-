"""ScanRepository â€” persistence for Scan domain objects."""
from __future__ import annotations

from datetime import datetime

from xscan.schemas.scan import Scan, ScanProfile, ScanStatus, Target
from xscan.storage.database import Database
from xscan.storage.repositories._util import row_to_dict


class ScanRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def save(self, scan: Scan) -> None:
        self._db.execute(
            """
            INSERT OR REPLACE INTO scans
              (id, target_url, target_host, profile, workflow_name,
               status, no_llm, research_on, auth_session, project,
               error, created_at, started_at, finished_at)
            VALUES
              (:id, :target_url, :target_host, :profile, :workflow_name,
               :status, :no_llm, :research_on, :auth_session, :project,
               :error, :created_at, :started_at, :finished_at)
            """,
            {
                "id":            scan.id,
                "target_url":    scan.target.url,
                "target_host":   scan.target.host,
                "profile":       scan.profile if isinstance(scan.profile, str) else scan.profile.value,
                "workflow_name": scan.workflow_name,
                "status":        scan.status if isinstance(scan.status, str) else scan.status.value,
                "no_llm":        int(scan.no_llm),
                "research_on":   int(scan.research_enabled),
                "auth_session":  scan.auth_session,
                "project":       scan.project,
                "error":         scan.error,
                "created_at":    scan.created_at.isoformat(),
                "started_at":    scan.started_at.isoformat() if scan.started_at else None,
                "finished_at":   scan.finished_at.isoformat() if scan.finished_at else None,
            },
        )

    def get(self, scan_id: str) -> Scan | None:
        row = self._db.fetchone(
            "SELECT * FROM scans WHERE id = :id", {"id": scan_id}
        )
        return self._row_to_scan(row) if row else None

    def list_recent(self, limit: int = 20) -> list[Scan]:
        rows = self._db.fetchall(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT :limit",
            {"limit": limit},
        )
        return [self._row_to_scan(r) for r in rows if r]

    def update_status(self, scan_id: str, status: ScanStatus, error: str = "") -> None:
        self._db.execute(
            "UPDATE scans SET status = :status, error = :error WHERE id = :id",
            {"status": status.value, "error": error or None, "id": scan_id},
        )

    @staticmethod
    def _row_to_scan(row: object) -> Scan:
        r = row_to_dict(row)
        target = Target.from_url(r["target_url"])
        return Scan(
            id=r["id"],
            target=target,
            profile=ScanProfile(r["profile"]),
            workflow_name=r["workflow_name"],
            status=ScanStatus(r["status"]),
            no_llm=bool(r["no_llm"]),
            research_enabled=bool(r["research_on"]),
            auth_session=r.get("auth_session"),
            project=r.get("project"),
            error=r.get("error"),
            created_at=datetime.fromisoformat(r["created_at"]),
            started_at=datetime.fromisoformat(r["started_at"]) if r.get("started_at") else None,
            finished_at=datetime.fromisoformat(r["finished_at"]) if r.get("finished_at") else None,
        )


