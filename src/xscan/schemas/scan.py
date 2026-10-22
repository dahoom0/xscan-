"""Scan, Target, and ScanProfile schemas."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _utcnow() -> datetime:
    return datetime.now(UTC)




class ScanProfile(StrEnum):
    FAST     = "fast"
    BALANCED = "balanced"
    DEEP     = "deep"


class ScanStatus(StrEnum):
    PENDING   = "pending"
    RUNNING   = "running"
    PAUSED    = "paused"
    COMPLETED = "completed"
    FAILED    = "failed"
    CANCELLED = "cancelled"


class Target(BaseModel):
    """Resolved, normalised scan target."""
    url: str                           # canonical base URL
    host: str                          # hostname only
    scheme: str = "https"
    port: int | None = None
    path_prefix: str = ""

    @field_validator("url", mode="before")
    @classmethod
    def ensure_scheme(cls, v: str) -> str:
        v = str(v).strip()
        if not v.startswith(("http://", "https://")):
            v = "https://" + v
        return v.rstrip("/")

    @classmethod
    def from_url(cls, raw: str) -> Target:
        from urllib.parse import urlparse
        raw = raw.strip()
        if not raw.startswith(("http://", "https://")):
            raw = "https://" + raw
        p = urlparse(raw)
        return cls(
            url=raw.rstrip("/"),
            host=p.hostname or "",
            scheme=p.scheme,
            port=p.port,
            path_prefix=p.path,
        )


class Scan(BaseModel):
    """Top-level scan record."""
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8].upper())
    target: Target
    profile: ScanProfile = ScanProfile.BALANCED
    workflow_name: str = "xss-balanced"
    status: ScanStatus = ScanStatus.PENDING
    no_llm: bool = False
    research_enabled: bool = False
    auth_session: str | None = None
    project: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None

    model_config = ConfigDict(use_enum_values=True)

