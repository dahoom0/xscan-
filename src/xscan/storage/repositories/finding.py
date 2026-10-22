"""FindingRepository â€” persistence for Finding domain objects."""
from __future__ import annotations

import json
from datetime import datetime

from xscan.schemas.finding import Finding, FindingStatus, FindingType, Severity
from xscan.storage.database import Database
from xscan.storage.repositories._util import row_to_dict


class FindingRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def save(self, finding: Finding) -> None:
        self._db.execute(
            """
            INSERT OR REPLACE INTO findings
              (id, scan_id, type, severity, status, url, parameter, payload,
               description, remediation, llm_reasoning, evidence_ids,
               created_at, confirmed_at)
            VALUES
              (:id, :scan_id, :type, :severity, :status, :url, :parameter,
               :payload, :description, :remediation, :llm_reasoning,
               :evidence_ids, :created_at, :confirmed_at)
            """,
            {
                "id":           finding.id,
                "scan_id":      finding.scan_id,
                "type":         finding.type.value,
                "severity":     finding.severity.value,
                "status":       finding.status.value,
                "url":          finding.url,
                "parameter":    finding.parameter,
                "payload":      finding.payload,
                "description":  finding.description,
                "remediation":  finding.remediation,
                "llm_reasoning": finding.llm_reasoning,
                "evidence_ids": json.dumps(finding.evidence_ids),
                "created_at":   finding.created_at.isoformat(),
                "confirmed_at": finding.confirmed_at.isoformat() if finding.confirmed_at else None,
            },
        )

    def get(self, finding_id: str) -> Finding | None:
        row = self._db.fetchone(
            "SELECT * FROM findings WHERE id = :id", {"id": finding_id}
        )
        return self._row_to_finding(row) if row else None

    def list_for_scan(self, scan_id: str) -> list[Finding]:
        rows = self._db.fetchall(
            "SELECT * FROM findings WHERE scan_id = :sid ORDER BY created_at",
            {"sid": scan_id},
        )
        return [self._row_to_finding(r) for r in rows]

    @staticmethod
    def _row_to_finding(row: object) -> Finding:
        r = row_to_dict(row)
        return Finding(
            id=r["id"],
            scan_id=r["scan_id"],
            type=FindingType(r["type"]),
            severity=Severity(r["severity"]),
            status=FindingStatus(r["status"]),
            url=r["url"],
            parameter=r.get("parameter", ""),
            payload=r.get("payload", ""),
            description=r.get("description", ""),
            remediation=r.get("remediation", ""),
            llm_reasoning=r.get("llm_reasoning", ""),
            evidence_ids=json.loads(r.get("evidence_ids", "[]")),
            created_at=datetime.fromisoformat(r["created_at"]),
            confirmed_at=datetime.fromisoformat(r["confirmed_at"]) if r.get("confirmed_at") else None,
        )


