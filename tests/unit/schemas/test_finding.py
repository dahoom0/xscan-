"""Tests for finding schemas — including evidence invariant."""
import pytest
from xscan.schemas.finding import Finding, FindingType, Severity, FindingStatus
from xscan.errors import MissingEvidenceError


class TestFinding:
    def test_requires_evidence_ids(self):
        with pytest.raises(MissingEvidenceError):
            Finding(
                scan_id="s1",
                type=FindingType.XSS_REFLECTED,
                severity=Severity.HIGH,
                url="https://example.com",
                evidence_ids=[],   # ← must be non-empty
            )

    def test_valid_finding_with_evidence(self):
        f = Finding(
            scan_id="s1",
            type=FindingType.XSS_REFLECTED,
            severity=Severity.HIGH,
            url="https://example.com/search",
            parameter="q",
            evidence_ids=["E-abc123"],
        )
        assert f.status == FindingStatus.UNCONFIRMED
        assert f.id.startswith("F-")

    def test_confirm_updates_status(self):
        f = Finding(
            scan_id="s1",
            type=FindingType.XSS_REFLECTED,
            severity=Severity.HIGH,
            url="https://example.com",
            evidence_ids=["E-001"],
        )
        confirmed = f.confirm()
        assert confirmed.status == FindingStatus.CONFIRMED
        assert confirmed.confirmed_at is not None
