"""Tests for Database, migrations, and repositories."""
import json
from pathlib import Path

import pytest

from xscan.storage.database import Database
from xscan.storage.repositories.scan import ScanRepository
from xscan.storage.repositories.evidence import EvidenceRepository
from xscan.storage.repositories.finding import FindingRepository
from xscan.schemas.scan import Scan, Target, ScanProfile, ScanStatus
from xscan.schemas.evidence import EvidenceNode, EvidenceType
from xscan.schemas.finding import Finding, FindingType, Severity


@pytest.fixture
def db(tmp_path: Path) -> Database:
    d = Database(tmp_path / "test.db")
    d.connect()
    d.migrate()
    return d


class TestDatabase:
    def test_connect_and_migrate(self, db: Database):
        rows = db.fetchall("SELECT version FROM schema_version")
        assert len(rows) >= 1
        assert rows[0]["version"] == 1

    def test_idempotent_migration(self, db: Database):
        """Running migrate twice should not error."""
        db.migrate()
        rows = db.fetchall("SELECT version FROM schema_version")
        assert len(rows) == 1   # still just one version row

    def test_execute_and_fetchone(self, db: Database):
        db.execute(
            "INSERT INTO audit_log (id, event_type) VALUES (:id, :t)",
            {"id": "test-1", "t": "test.event"},
        )
        row = db.fetchone("SELECT event_type FROM audit_log WHERE id = 'test-1'")
        assert row is not None
        assert row["event_type"] == "test.event"


class TestScanRepository:
    def test_save_and_get(self, db: Database):
        repo = ScanRepository(db)
        scan = Scan(target=Target.from_url("https://example.com"))
        repo.save(scan)
        loaded = repo.get(scan.id)
        assert loaded is not None
        assert loaded.id == scan.id
        assert loaded.target.host == "example.com"

    def test_get_nonexistent_returns_none(self, db: Database):
        repo = ScanRepository(db)
        assert repo.get("NONEXISTENT") is None

    def test_update_status(self, db: Database):
        repo = ScanRepository(db)
        scan = Scan(target=Target.from_url("https://example.com"))
        repo.save(scan)
        repo.update_status(scan.id, ScanStatus.RUNNING)
        loaded = repo.get(scan.id)
        assert loaded is not None
        assert loaded.status == ScanStatus.RUNNING

    def test_list_recent(self, db: Database):
        repo = ScanRepository(db)
        for i in range(3):
            repo.save(Scan(target=Target.from_url(f"https://site{i}.com")))
        results = repo.list_recent(limit=10)
        assert len(results) == 3


class TestEvidenceRepository:
    def test_save_and_get_node(self, db: Database):
        scan_repo = ScanRepository(db)
        scan = Scan(target=Target.from_url("https://example.com"))
        scan_repo.save(scan)

        ev_repo = EvidenceRepository(db)
        node = EvidenceNode(
            scan_id=scan.id,
            type=EvidenceType.HTTP_RESPONSE,
            url="https://example.com/search",
            summary="HTTP 200 response",
            data={"status_code": 200, "body_length": 1234},
        )
        ev_repo.save_node(node)
        loaded = ev_repo.get_node(node.id)
        assert loaded is not None
        assert loaded.type == EvidenceType.HTTP_RESPONSE
        assert loaded.data["status_code"] == 200

    def test_list_for_scan(self, db: Database):
        scan_repo = ScanRepository(db)
        scan = Scan(target=Target.from_url("https://example.com"))
        scan_repo.save(scan)

        ev_repo = EvidenceRepository(db)
        for _ in range(3):
            ev_repo.save_node(EvidenceNode(
                scan_id=scan.id,
                type=EvidenceType.HTTP_REQUEST,
                url="https://example.com",
            ))
        results = ev_repo.list_for_scan(scan.id)
        assert len(results) == 3


class TestFindingRepository:
    def _setup_scan_with_evidence(self, db: Database):
        """Helper: create a scan + evidence node and return (scan_id, evidence_id)."""
        scan_repo = ScanRepository(db)
        scan = Scan(target=Target.from_url("https://example.com"))
        scan_repo.save(scan)

        ev_repo = EvidenceRepository(db)
        node = EvidenceNode(
            scan_id=scan.id,
            type=EvidenceType.REFLECTION,
            url="https://example.com/search",
        )
        ev_repo.save_node(node)
        return scan.id, node.id

    def test_save_and_get(self, db: Database):
        scan_id, ev_id = self._setup_scan_with_evidence(db)
        repo = FindingRepository(db)
        finding = Finding(
            scan_id=scan_id,
            type=FindingType.XSS_REFLECTED,
            severity=Severity.HIGH,
            url="https://example.com/search",
            parameter="q",
            evidence_ids=[ev_id],
        )
        repo.save(finding)
        loaded = repo.get(finding.id)
        assert loaded is not None
        assert loaded.severity == Severity.HIGH
        assert ev_id in loaded.evidence_ids

    def test_list_for_scan(self, db: Database):
        scan_id, ev_id = self._setup_scan_with_evidence(db)
        repo = FindingRepository(db)
        for _ in range(2):
            repo.save(Finding(
                scan_id=scan_id,
                type=FindingType.XSS_REFLECTED,
                severity=Severity.MEDIUM,
                url="https://example.com",
                evidence_ids=[ev_id],
            ))
        results = repo.list_for_scan(scan_id)
        assert len(results) == 2
