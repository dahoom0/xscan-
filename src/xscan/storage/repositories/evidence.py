"""EvidenceRepository â€” persistence for EvidenceNode, EvidenceEdge, Artifact."""
from __future__ import annotations

import json
from datetime import datetime

from xscan.schemas.evidence import Artifact, EvidenceEdge, EvidenceNode, EvidenceType
from xscan.storage.database import Database
from xscan.storage.repositories._util import row_to_dict


class EvidenceRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    # â”€â”€ EvidenceNode â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def save_node(self, node: EvidenceNode) -> None:
        self._db.execute(
            """
            INSERT OR REPLACE INTO evidence_nodes
              (id, scan_id, dag_node_id, type, url, summary, data_json,
               parent_ids, created_at)
            VALUES
              (:id, :scan_id, :dag_node_id, :type, :url, :summary, :data_json,
               :parent_ids, :created_at)
            """,
            {
                "id":          node.id,
                "scan_id":     node.scan_id,
                "dag_node_id": node.node_id,
                "type":        node.type.value,
                "url":         node.url,
                "summary":     node.summary,
                "data_json":   json.dumps(node.data),
                "parent_ids":  json.dumps(node.parent_ids),
                "created_at":  node.created_at.isoformat(),
            },
        )

    def get_node(self, evidence_id: str) -> EvidenceNode | None:
        row = self._db.fetchone(
            "SELECT * FROM evidence_nodes WHERE id = :id", {"id": evidence_id}
        )
        return self._row_to_node(row) if row else None

    def list_for_scan(self, scan_id: str) -> list[EvidenceNode]:
        rows = self._db.fetchall(
            "SELECT * FROM evidence_nodes WHERE scan_id = :sid ORDER BY created_at",
            {"sid": scan_id},
        )
        return [self._row_to_node(r) for r in rows]

    # â”€â”€ EvidenceEdge â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def save_edge(self, edge: EvidenceEdge) -> None:
        self._db.execute(
            """
            INSERT OR IGNORE INTO evidence_edges (id, from_id, to_id, label)
            VALUES (:id, :from_id, :to_id, :label)
            """,
            {"id": edge.id, "from_id": edge.from_id,
             "to_id": edge.to_id, "label": edge.label},
        )

    # â”€â”€ Artifact â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def save_artifact(self, artifact: Artifact) -> None:
        self._db.execute(
            """
            INSERT OR REPLACE INTO artifacts
              (id, evidence_id, filename, mime_type, size_bytes, storage_path, created_at)
            VALUES
              (:id, :evidence_id, :filename, :mime_type, :size_bytes, :storage_path, :created_at)
            """,
            {
                "id":           artifact.id,
                "evidence_id":  artifact.evidence_id,
                "filename":     artifact.filename,
                "mime_type":    artifact.mime_type,
                "size_bytes":   artifact.size_bytes,
                "storage_path": artifact.storage_path,
                "created_at":   artifact.created_at.isoformat(),
            },
        )

    @staticmethod
    def _row_to_node(row: object) -> EvidenceNode:
        r = row_to_dict(row)
        return EvidenceNode(
            id=r["id"],
            scan_id=r["scan_id"],
            node_id=r.get("dag_node_id", ""),
            type=EvidenceType(r["type"]),
            url=r.get("url", ""),
            summary=r.get("summary", ""),
            data=json.loads(r.get("data_json", "{}")),
            parent_ids=json.loads(r.get("parent_ids", "[]")),
            created_at=datetime.fromisoformat(r["created_at"]),
        )


