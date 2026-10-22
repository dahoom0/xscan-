"""Finding, Severity, and FindingType schemas."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field, model_validator

from xscan.errors import MissingEvidenceError


def _utcnow() -> datetime:
    return datetime.now(UTC)



class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class FindingType(StrEnum):
    XSS_REFLECTED    = "xss-reflected"
    XSS_STORED       = "xss-stored"
    XSS_DOM          = "xss-dom"
    OPEN_REDIRECT    = "open-redirect"
    INFO_DISCLOSURE  = "info-disclosure"
    MISSING_HEADER   = "missing-security-header"
    MISC             = "misc"


class FindingStatus(StrEnum):
    UNCONFIRMED  = "unconfirmed"   # candidate only, no evidence yet
    CONFIRMED    = "confirmed"     # deterministic evidence exists
    FALSE_POSITIVE = "false_positive"
    WONT_FIX     = "wont_fix"


class Finding(BaseModel):
    """
    A security finding.

    INVARIANT: evidence_ids must be non-empty.
    A Finding cannot be created without at least one EvidenceNode.
    """
    id: str = Field(default_factory=lambda: "F-" + uuid.uuid4().hex[:8].upper())
    scan_id: str
    type: FindingType
    severity: Severity
    status: FindingStatus = FindingStatus.UNCONFIRMED
    url: str
    parameter: str = ""
    payload: str = ""
    description: str = ""
    remediation: str = ""
    llm_reasoning: str = ""         # LLM opinion â€” NOT proof
    evidence_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)
    confirmed_at: datetime | None = None

    @model_validator(mode="after")
    def require_evidence(self) -> Finding:
        if not self.evidence_ids:
            raise MissingEvidenceError(
                f"Finding {self.id} created without any evidence. "
                "Link at least one EvidenceNode before creating a Finding."
            )
        return self

    def confirm(self) -> Finding:
        """Mark finding as deterministically confirmed."""
        return self.model_copy(update={
            "status": FindingStatus.CONFIRMED,
            "confirmed_at": _utcnow(),
        })
