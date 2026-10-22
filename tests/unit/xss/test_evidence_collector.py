"""
Tests for evidence-collector finding creation.

Regressions this pins down (found running the deep profile against a DOM XSS
lab, after the FK crash that used to hide them):

  (a) evidence_nodes / findings are foreign-keyed to scans(id), but the CLI
      runs the DAG without ever registering the scan -> the node died with
      "FOREIGN KEY constraint failed" and took the whole scan down
  (b) the status gate compared the *iteration* status vocabulary against
      ValidationStatus.UNVALIDATED (never equal), and a bare HTTP_REQUEST
      counts as deterministic evidence — so every candidate with a test URL
      became a "finding" (6 findings for a scan with 1 confirmed flow)
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from xscan.core.scope.engine import ScopeEngine
from xscan.evidence.graph import EvidenceGraph
from xscan.nodes.xss.evidence_collector import (
    _PROOF_STATUSES,
    EvidenceCollectorNode,
    _has_reflection,
)
from xscan.schemas.evidence import EvidenceType
from xscan.storage.database import Database

_TARGET = "http://127.0.0.1:8000/feedback"


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Database:
    """A throwaway database, injected where the node looks for one."""
    database = Database(tmp_path / "evidence.db")
    database.connect()
    database.migrate()
    monkeypatch.setattr("xscan.storage.database.get_db", lambda: database)
    yield database
    database.close()


def _ctx(**inputs) -> MagicMock:
    ctx = MagicMock()
    ctx.scan_id = "TEST1234"
    ctx.node_id = "evidence-collect"
    ctx.run_id = "RUN"
    ctx.config = {}
    ctx.inputs = {"target_url": _TARGET, "profile": "deep", **inputs}
    ctx.get = lambda key, default=None: ctx.inputs.get(key, default)
    ctx.scope = ScopeEngine.allow_all("TEST1234")
    ctx.policy = MagicMock()
    ctx.logger = MagicMock()
    ctx.no_llm = True
    return ctx


def _candidate(**overrides) -> dict:
    raw = {
        "xss_type":       "dom",
        "url":            _TARGET,
        "parameter":      "returnPath",
        "method":         "GET",
        "best_payload":   "javascript:alert(document.cookie)",
        "best_test_url":  _TARGET + "?returnPath=javascript%3Aalert%28document.cookie%29",
        "encoding_profile": {"xss_type": "dom", "sink_kind": "url_attribute"},
    }
    raw.update(overrides)
    return raw


class TestFindingProofGate:
    def test_confirmed_candidate_becomes_a_finding(self, db: Database):
        raw = _candidate(confirmed=True, validated=True, validation_status="confirmed")

        result = EvidenceCollectorNode().execute(_ctx(validated_candidates=[raw]))

        assert result["finding_count"] == 1
        assert db.fetchall("SELECT id FROM findings")

    def test_inconclusive_dom_candidate_is_not_a_finding(self, db: Database):
        """Reaching a sink is evidence, not exploitability."""
        raw = _candidate(confirmed=False, validated=False,
                         validation_status="inconclusive")

        result = EvidenceCollectorNode().execute(_ctx(validated_candidates=[raw]))

        assert result["finding_count"] == 0, "no proof of execution -> no finding"

    def test_iteration_status_labels_are_not_treated_as_proof(self, db: Database):
        """The validators emit IterationStatus values such as budget_exhausted."""
        raw = _candidate(confirmed=False, validated=False,
                         validation_status="budget_exhausted")

        result = EvidenceCollectorNode().execute(_ctx(validated_candidates=[raw]))

        assert result["finding_count"] == 0
        assert "budget_exhausted" not in _PROOF_STATUSES


class TestScanRowRegistration:
    def test_scan_row_is_created_for_dag_only_runs(self, db: Database):
        EvidenceCollectorNode().execute(_ctx(
            validated_candidates=[
                _candidate(confirmed=True, validation_status="confirmed")
            ],
        ))

        row = db.fetchone("SELECT target_url FROM scans WHERE id = 'TEST1234'")
        assert row is not None, "evidence rows need a parent scan row"
        assert row["target_url"] == _TARGET

    def test_existing_scan_row_is_not_clobbered(self, db: Database):
        db.execute(
            "INSERT INTO scans (id, target_url, target_host, profile, workflow_name,"
            " status, no_llm, research_on, created_at)"
            " VALUES ('TEST1234', :u, '127.0.0.1', 'deep', 'xss-deep', 'running',"
            " 0, 0, '2026-01-01T00:00:00+00:00')",
            {"u": _TARGET},
        )

        EvidenceCollectorNode().execute(_ctx(validated_candidates=[]))

        row = db.fetchone("SELECT workflow_name FROM scans WHERE id = 'TEST1234'")
        assert row is not None
        assert row["workflow_name"] == "xss-deep"


class TestReflectionDetection:
    def test_graph_without_reflection_has_no_proof(self):
        graph = EvidenceGraph(scan_id="TEST1234", db=None)
        graph.add_http_request(url=_TARGET, method="GET", node_id="evidence-collect")

        assert _has_reflection(graph) is False

    def test_reflection_node_counts_as_proof(self):
        graph = EvidenceGraph(scan_id="TEST1234", db=None)
        graph.add_reflection(url=_TARGET, parameter="q", payload="<img src=x>",
                             snippet="<img src=x>", node_id="evidence-collect")

        assert _has_reflection(graph) is True
        assert EvidenceType.REFLECTION in {n.type for n in graph.all_nodes()}
