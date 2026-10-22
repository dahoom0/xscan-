"""
Target Domain Models
====================
Typed Pydantic models for target input, normalization, and queue management.

Key principles:
  - Every target has a stable identity (target_id)
  - Original URL is preserved for evidence/audit
  - Normalized URL is used for deduplication and execution
  - Source information is never lost
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, UTC
from enum import StrEnum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# TargetSourceType — where targets come from
# ---------------------------------------------------------------------------

class TargetSourceType(StrEnum):
    """Enumeration of supported target input sources."""
    SINGLE_URL   = "single_url"    # Direct CLI argument
    URL_FILE     = "url_file"      # File containing URLs (one per line)
    STDIN        = "stdin"         # Piped input
    PREVIOUS_SCAN = "previous_scan" # Load from previous scan results
    CRAWL_RESULT  = "crawl_result"  # Generated from crawler output
    API          = "api"           # Future: API endpoint
    GENERATED    = "generated"     # Future: programmatically generated


# ---------------------------------------------------------------------------
# TargetSource — metadata about where targets originated
# ---------------------------------------------------------------------------

class TargetSource(BaseModel):
    """
    Describes the origin of a set of targets.

    Used for audit trails, reproducibility, and future extensibility.
    """
    type: TargetSourceType = TargetSourceType.SINGLE_URL
    location: str = ""              # File path, scan ID, etc.
    description: str = ""           # Human-readable description
    loaded_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def single_url(cls, url: str) -> "TargetSource":
        """Create a source for a single CLI URL argument."""
        return cls(
            type=TargetSourceType.SINGLE_URL,
            location=url,
            description=f"Single URL: {url[:80]}",
        )

    @classmethod
    def url_file(cls, path: str) -> "TargetSource":
        """Create a source for a file containing URLs."""
        return cls(
            type=TargetSourceType.URL_FILE,
            location=path,
            description=f"URL file: {path}",
        )

    @classmethod
    def stdin(cls) -> "TargetSource":
        """Create a source for stdin input."""
        return cls(
            type=TargetSourceType.STDIN,
            location="stdin",
            description="URLs from stdin",
        )

    @classmethod
    def previous_scan(cls, scan_id: str) -> "TargetSource":
        """Create a source from a previous scan."""
        return cls(
            type=TargetSourceType.PREVIOUS_SCAN,
            location=scan_id,
            description=f"Previous scan: {scan_id}",
        )

    @classmethod
    def crawl_result(cls, seed_url: str) -> "TargetSource":
        """Create a source from crawler output."""
        return cls(
            type=TargetSourceType.CRAWL_RESULT,
            location=seed_url,
            description=f"Crawled from: {seed_url[:60]}",
        )


# ---------------------------------------------------------------------------
# TargetStatus — execution state of a target
# ---------------------------------------------------------------------------

class TargetStatus(StrEnum):
    """Execution status of a target within an assessment."""
    PENDING   = "pending"    # Queued, not yet started
    RUNNING   = "running"    # Currently being processed
    COMPLETED = "completed"  # Successfully processed
    FAILED    = "failed"     # Processing failed
    SKIPPED   = "skipped"    # Skipped (e.g., out of scope)
    BLOCKED   = "blocked"    # Blocked by scope or policy
    CANCELLED = "cancelled"  # Cancelled by user


# ---------------------------------------------------------------------------
# NormalizedTarget — a target with stable identity
# ---------------------------------------------------------------------------

class NormalizedTarget(BaseModel):
    """
    A normalized target URL with stable identity.

    Key principles:
      - target_id is deterministic based on normalized URL
      - original_url is preserved for evidence/audit
      - normalized_url is used for deduplication and execution
      - source tracks where this target came from
    """
    target_id: str = Field(default="")
    original_url: str = ""
    normalized_url: str = ""

    # Parsed components (from normalized URL)
    scheme: str = "https"
    hostname: str = ""
    port: int | None = None
    path: str = "/"
    query: str = ""
    fragment: str = ""

    # Source tracking
    source: TargetSource = Field(default_factory=TargetSource)
    source_line: int = 0          # Line number in file (if applicable)

    # Metadata
    metadata: dict[str, Any] = Field(default_factory=dict)

    # Scope/Policy validation results
    scope_valid: bool | None = None
    scope_rejection_reason: str = ""

    # Status
    status: TargetStatus = TargetStatus.PENDING

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        # Generate deterministic target_id if not provided
        if not self.target_id and self.normalized_url:
            self.target_id = self._compute_id()

    def _compute_id(self) -> str:
        """Compute a deterministic ID from normalized URL."""
        # Use SHA-256 of normalized URL, take first 12 hex chars
        h = hashlib.sha256(self.normalized_url.encode("utf-8")).hexdigest()[:12]
        return f"TGT-{h.upper()}"

    @property
    def url(self) -> str:
        """Return the normalized URL for execution."""
        return self.normalized_url

    @property
    def host_port(self) -> str:
        """Return hostname:port or just hostname if default port."""
        if self.port:
            default_ports = {"http": 80, "https": 443}
            if self.port != default_ports.get(self.scheme):
                return f"{self.hostname}:{self.port}"
        return self.hostname

    def to_scan_target(self) -> "ScanTarget":
        """
        Convert to the existing ScanTarget schema for DAG compatibility.

        This bridges the new target system with the existing scan.py schemas.
        """
        from xscan.schemas.scan import Target
        return Target.from_url(self.normalized_url)


# Import at end to avoid circular import
from xscan.schemas.scan import Target as ScanTarget


# ---------------------------------------------------------------------------
# TargetQueueEntry — a target's state in the execution queue
# ---------------------------------------------------------------------------

class TargetQueueEntry(BaseModel):
    """
    A target's entry in the execution queue.

    Tracks execution state, timing, and results.
    """
    target_id: str = ""
    target: NormalizedTarget = Field(default_factory=NormalizedTarget)
    status: TargetStatus = TargetStatus.PENDING

    # Execution tracking
    started_at: datetime | None = None
    finished_at: datetime | None = None
    run_id: str = ""              # Workflow run ID (from checkpoint)
    error: str = ""

    # Results
    candidates_found: int = 0
    findings_count: int = 0

    # Position in queue
    priority: int = 0             # Higher = processed first
    retry_count: int = 0
    max_retries: int = 2


# ---------------------------------------------------------------------------
# TargetQueue — execution queue for targets
# ---------------------------------------------------------------------------

class TargetQueue(BaseModel):
    """
    Queue of targets for execution.

    Supports:
      - State transitions (pending → running → completed/failed/skipped)
      - Priority ordering
      - Retry handling
      - Progress tracking
    """
    assessment_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8].upper())
    entries: list[TargetQueueEntry] = Field(default_factory=list)

    # Statistics
    total_targets: int = 0
    pending_count: int = 0
    running_count: int = 0
    completed_count: int = 0
    failed_count: int = 0
    skipped_count: int = 0
    blocked_count: int = 0

    # Configuration
    max_concurrent: int = 1       # Future: parallel execution
    max_retries: int = 2

    def add(self, target: NormalizedTarget, priority: int = 0) -> TargetQueueEntry:
        """Add a target to the queue."""
        entry = TargetQueueEntry(
            target_id=target.target_id,
            target=target,
            priority=priority,
            max_retries=self.max_retries,
        )
        self.entries.append(entry)
        self.total_targets += 1
        self.pending_count += 1
        return entry

    def get_next(self) -> TargetQueueEntry | None:
        """Get the next pending target (highest priority first)."""
        pending = [
            e for e in self.entries
            if e.status == TargetStatus.PENDING
        ]
        if not pending:
            return None
        # Sort by priority (descending), then by insertion order
        pending.sort(key=lambda e: (-e.priority, self.entries.index(e)))
        return pending[0]

    def mark_running(self, target_id: str) -> None:
        """Mark a target as running."""
        for entry in self.entries:
            if entry.target_id == target_id:
                if entry.status == TargetStatus.PENDING:
                    self.pending_count -= 1
                entry.status = TargetStatus.RUNNING
                entry.started_at = datetime.now(UTC)
                self.running_count += 1
                break

    def mark_completed(self, target_id: str, run_id: str = "") -> None:
        """Mark a target as completed."""
        for entry in self.entries:
            if entry.target_id == target_id:
                if entry.status == TargetStatus.RUNNING:
                    self.running_count -= 1
                entry.status = TargetStatus.COMPLETED
                entry.finished_at = datetime.now(UTC)
                entry.run_id = run_id
                self.completed_count += 1
                break

    def mark_failed(self, target_id: str, error: str = "") -> None:
        """Mark a target as failed."""
        for entry in self.entries:
            if entry.target_id == target_id:
                if entry.status == TargetStatus.RUNNING:
                    self.running_count -= 1
                entry.error = error
                entry.retry_count += 1
                # Check if we should retry
                if entry.retry_count < entry.max_retries:
                    entry.status = TargetStatus.PENDING
                    self.pending_count += 1
                else:
                    entry.status = TargetStatus.FAILED
                    entry.finished_at = datetime.now(UTC)
                    self.failed_count += 1
                break

    def mark_skipped(self, target_id: str, reason: str = "") -> None:
        """Mark a target as skipped."""
        for entry in self.entries:
            if entry.target_id == target_id:
                if entry.status == TargetStatus.PENDING:
                    self.pending_count -= 1
                entry.status = TargetStatus.SKIPPED
                entry.error = reason
                entry.finished_at = datetime.now(UTC)
                self.skipped_count += 1
                break

    def mark_blocked(self, target_id: str, reason: str = "") -> None:
        """Mark a target as blocked by scope/policy."""
        for entry in self.entries:
            if entry.target_id == target_id:
                if entry.status == TargetStatus.PENDING:
                    self.pending_count -= 1
                entry.status = TargetStatus.BLOCKED
                entry.error = reason
                entry.finished_at = datetime.now(UTC)
                self.blocked_count += 1
                # Also update the target's scope_valid field
                entry.target.scope_valid = False
                entry.target.scope_rejection_reason = reason
                break

    def is_complete(self) -> bool:
        """Check if all targets have been processed."""
        return self.pending_count == 0 and self.running_count == 0

    def get_entry(self, target_id: str) -> TargetQueueEntry | None:
        """Get a queue entry by target ID."""
        for entry in self.entries:
            if entry.target_id == target_id:
                return entry
        return None

    def summary(self) -> dict[str, Any]:
        """Return a summary of queue state."""
        return {
            "assessment_id": self.assessment_id,
            "total": self.total_targets,
            "pending": self.pending_count,
            "running": self.running_count,
            "completed": self.completed_count,
            "failed": self.failed_count,
            "skipped": self.skipped_count,
            "blocked": self.blocked_count,
            "progress_pct": round(
                100 * (self.completed_count + self.failed_count + self.skipped_count + self.blocked_count)
                / max(1, self.total_targets), 1
            ),
        }


# ---------------------------------------------------------------------------
# TargetSet — collection of targets for an assessment
# ---------------------------------------------------------------------------

class TargetSet(BaseModel):
    """
    A normalized collection of targets for an assessment.

    Responsibilities:
      - Hold all targets for a single assessment
      - Track source information
      - Provide deduplication
      - Support iteration and querying
    """
    assessment_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8].upper())
    source: TargetSource = Field(default_factory=TargetSource)
    targets: list[NormalizedTarget] = Field(default_factory=list)

    # Index for fast lookup
    _target_index: dict[str, NormalizedTarget] = {}

    def add(self, target: NormalizedTarget) -> bool:
        """
        Add a target if not already present.

        Returns True if added, False if duplicate.
        """
        if target.target_id in self._target_index:
            return False
        self.targets.append(target)
        self._target_index[target.target_id] = target
        return True

    def get(self, target_id: str) -> NormalizedTarget | None:
        """Get a target by ID."""
        return self._target_index.get(target_id)

    def get_by_url(self, normalized_url: str) -> NormalizedTarget | None:
        """Get a target by normalized URL."""
        for target in self.targets:
            if target.normalized_url == normalized_url:
                return target
        return None

    def __iter__(self):
        return iter(self.targets)

    def __len__(self) -> int:
        return len(self.targets)

    def __getitem__(self, index: int) -> NormalizedTarget:
        return self.targets[index]

    @property
    def valid_targets(self) -> list[NormalizedTarget]:
        """Return targets that passed scope validation."""
        return [t for t in self.targets if t.scope_valid is True or t.scope_valid is None]

    @property
    def blocked_targets(self) -> list[NormalizedTarget]:
        """Return targets blocked by scope/policy."""
        return [t for t in self.targets if t.scope_valid is False]

    def summary(self) -> dict[str, Any]:
        """Return a summary of the target set."""
        return {
            "assessment_id": self.assessment_id,
            "source": self.source.type.value,
            "source_location": self.source.location,
            "total_targets": len(self.targets),
            "valid_targets": len(self.valid_targets),
            "blocked_targets": len(self.blocked_targets),
        }

    def model_post_init(self, __context: Any) -> None:
        """Rebuild index after deserialization."""
        self._target_index = {t.target_id: t for t in self.targets}
