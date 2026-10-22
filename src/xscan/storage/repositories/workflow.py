"""WorkflowRepository â€” persistence for WorkflowRun and NodeResult."""
from __future__ import annotations

import json
from datetime import datetime

from xscan.schemas.workflow import NodeResult, NodeStatus, WorkflowRun
from xscan.storage.database import Database


class WorkflowRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    # â”€â”€ WorkflowRun â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def save_run(self, run: WorkflowRun) -> None:
        # Use INSERT OR IGNORE for the scan FK — the engine may not have
        # persisted the scan record yet in all call paths.
        self._db.execute(
            """
            INSERT OR IGNORE INTO scans
              (id, target_url, target_host, profile, workflow_name, status, created_at)
            VALUES (:id, '', '', 'balanced', :wf, 'running', datetime('now'))
            """,
            {"id": run.scan_id, "wf": run.workflow_name},
        )
        self._db.execute(
            """
            INSERT OR REPLACE INTO workflow_runs
              (id, scan_id, workflow_name, workflow_version, status,
               started_at, finished_at)
            VALUES
              (:id, :scan_id, :workflow_name, :workflow_version, :status,
               :started_at, :finished_at)
            """,
            {
                "id":               run.id,
                "scan_id":          run.scan_id,
                "workflow_name":    run.workflow_name,
                "workflow_version": run.workflow_version,
                "status":           run.status.value if hasattr(run.status, "value") else run.status,
                "started_at":       run.started_at.isoformat() if run.started_at else None,
                "finished_at":      run.finished_at.isoformat() if run.finished_at else None,
            },
        )
        # Persist each node result
        for nr in run.node_results.values():
            self.save_node_result(run.id, nr)

    def get_run(self, run_id: str) -> WorkflowRun | None:
        row = self._db.fetchone(
            "SELECT * FROM workflow_runs WHERE id = :id", {"id": run_id}
        )
        if not row:
            return None
        r = dict(row)
        run = WorkflowRun(
            id=r["id"],
            scan_id=r["scan_id"],
            workflow_name=r["workflow_name"],
            workflow_version=r["workflow_version"],
            status=NodeStatus(r["status"]),
            started_at=datetime.fromisoformat(r["started_at"]) if r.get("started_at") else None,
            finished_at=datetime.fromisoformat(r["finished_at"]) if r.get("finished_at") else None,
        )
        # Load node results
        nrs = self._load_node_results(run_id)
        run.node_results = {nr.node_id: nr for nr in nrs}
        return run

    def get_latest_run_for_scan(self, scan_id: str) -> WorkflowRun | None:
        row = self._db.fetchone(
            "SELECT id FROM workflow_runs WHERE scan_id = :sid ORDER BY started_at DESC LIMIT 1",
            {"sid": scan_id},
        )
        return self.get_run(row["id"]) if row else None

    # â”€â”€ NodeResult â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def save_node_result(self, run_id: str, nr: NodeResult) -> None:
        node_pk = f"{run_id}:{nr.node_id}"
        self._db.execute(
            """
            INSERT OR REPLACE INTO node_results
              (id, run_id, node_id, status, output_json, error,
               metrics_json, started_at, finished_at)
            VALUES
              (:id, :run_id, :node_id, :status, :output_json, :error,
               :metrics_json, :started_at, :finished_at)
            """,
            {
                "id":           node_pk,
                "run_id":       run_id,
                "node_id":      nr.node_id,
                "status":       nr.status.value if hasattr(nr.status, "value") else nr.status,
                "output_json":  json.dumps(nr.output),
                "error":        nr.error,
                "metrics_json": json.dumps(nr.metrics),
                "started_at":   nr.started_at.isoformat() if nr.started_at else None,
                "finished_at":  nr.finished_at.isoformat() if nr.finished_at else None,
            },
        )

    def _load_node_results(self, run_id: str) -> list[NodeResult]:
        rows = self._db.fetchall(
            "SELECT * FROM node_results WHERE run_id = :rid", {"rid": run_id}
        )
        results = []
        for row in rows:
            r = dict(row)
            results.append(NodeResult(
                node_id=r["node_id"],
                status=NodeStatus(r["status"]),
                output=json.loads(r.get("output_json", "{}")),
                error=r.get("error"),
                metrics=json.loads(r.get("metrics_json", "{}")),
                started_at=datetime.fromisoformat(r["started_at"]) if r.get("started_at") else None,
                finished_at=datetime.fromisoformat(r["finished_at"]) if r.get("finished_at") else None,
            ))
        return results


