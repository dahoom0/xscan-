"""
Recon Domain Schemas
====================
Typed models for the reconnaissance pipeline.

Models:
  ReconToolStatus   — explicit tool execution states (never conflated)
  ReconAsset        — canonical deduplicated hostname/asset
  HttpProbeResult   — result of probing one hostname over HTTP
  DiscoveredPath    — one path found by FFUF or crawling
  Endpoint          — canonical URL endpoint (merged from all sources)
  ReconSummary      — final recon output passed to XSS pipeline
"""
from __future__ import annotations

import uuid
from datetime import datetime, UTC
from enum import StrEnum
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Tool execution states — spec §23
# CRITICAL: these must never be conflated
# ---------------------------------------------------------------------------

class ReconToolStatus(StrEnum):
    COMPLETED_WITH_RESULTS = "completed_with_results"
    COMPLETED_NO_RESULTS   = "completed_no_results"
    NO_CANDIDATES          = "no_candidates"      # tool ran, found nothing
    NO_PARAMETERS          = "no_parameters"      # tool found no input params
    CONNECTION_FAILED      = "connection_failed"
    EXECUTION_FAILED       = "execution_failed"
    TIMEOUT                = "timeout"
    TOOL_UNAVAILABLE       = "tool_unavailable"   # binary not installed
    UNSUPPORTED            = "unsupported"
    POLICY_BLOCKED         = "policy_blocked"
    OUT_OF_SCOPE           = "out_of_scope"

    @property
    def is_definitive_negative(self) -> bool:
        """True ONLY if tool ran cleanly and produced zero results."""
        return self == ReconToolStatus.COMPLETED_NO_RESULTS

    @property
    def is_failure(self) -> bool:
        return self in (
            ReconToolStatus.CONNECTION_FAILED,
            ReconToolStatus.EXECUTION_FAILED,
            ReconToolStatus.TIMEOUT,
        )


# ---------------------------------------------------------------------------
# ReconToolObservation — replaces raw dicts from recon tools
# ---------------------------------------------------------------------------

class ReconToolObservation(BaseModel):
    """
    Normalised observation from one external recon tool execution.
    Reuses the same pattern as ToolObservation in schemas/xss.py.
    """
    id:           str = Field(default_factory=lambda: "ROBS-" + uuid.uuid4().hex[:8])
    tool:         str
    version:      str = ""
    target:       str = ""
    capability:   str = ""
    status:       ReconToolStatus = ReconToolStatus.COMPLETED_NO_RESULTS
    observation:  str = ""
    raw_output:   str = ""          # capped at 2000 chars
    results:      list[str] = Field(default_factory=list)   # hostnames/URLs/paths
    started_at:   datetime  = Field(default_factory=lambda: datetime.now(UTC))
    finished_at:  Optional[datetime] = None
    duration_ms:  float = 0.0
    evidence_ids: list[str] = Field(default_factory=list)

    @property
    def has_results(self) -> bool:
        return bool(self.results) and self.status == ReconToolStatus.COMPLETED_WITH_RESULTS

    @property
    def is_failure(self) -> bool:
        return self.status.is_failure


# ---------------------------------------------------------------------------
# ReconAsset — canonical deduplicated hostname
# ---------------------------------------------------------------------------

class ReconAsset(BaseModel):
    """
    A canonical, deduplicated discovered asset (hostname/domain).

    Multiple tool observations for the same hostname → ONE ReconAsset.
    Provenance is preserved in `sources` and `evidence_ids`.
    """
    id:                  str = Field(default_factory=lambda: "ASSET-" + uuid.uuid4().hex[:8])
    hostname:            str
    normalized_hostname: str = ""       # lowercase, no trailing dot
    root_domain:         str = ""

    # Provenance — which tools discovered this asset
    sources:             list[str] = Field(default_factory=list)   # e.g. ["subfinder", "amass"]
    evidence_ids:        list[str] = Field(default_factory=list)

    # Scope
    in_scope:            bool = False
    scope_reason:        Optional[str] = None

    # DNS
    dns_resolved:        Optional[bool] = None
    addresses:           list[str] = Field(default_factory=list)   # IP addresses

    # HTTP
    urls:                list[str] = Field(default_factory=list)   # confirmed HTTP URLs
    live:                Optional[bool] = None
    http_status:         Optional[int] = None
    https_available:     Optional[bool] = None

    # Technologies
    technologies:        list[str] = Field(default_factory=list)

    # Status
    status:              str = "discovered"  # discovered | probed | live | dead

    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def add_source(self, source: str, evidence_id: str = "") -> None:
        if source not in self.sources:
            self.sources.append(source)
        if evidence_id and evidence_id not in self.evidence_ids:
            self.evidence_ids.append(evidence_id)

    @classmethod
    def normalise_hostname(cls, raw: str) -> str:
        return raw.strip().lower().rstrip(".")


# ---------------------------------------------------------------------------
# HttpProbeResult — one live HTTP service observation
# ---------------------------------------------------------------------------

class HttpProbeStatus(StrEnum):
    LIVE              = "live"
    REDIRECT          = "redirect"
    FORBIDDEN         = "forbidden"
    NOT_FOUND         = "not_found"
    SERVER_ERROR      = "server_error"
    CONNECTION_FAILED = "connection_failed"
    TIMEOUT           = "timeout"
    UNKNOWN           = "unknown"


class HttpProbeResult(BaseModel):
    """Result of probing one hostname/URL over HTTP/S."""
    id:               str = Field(default_factory=lambda: "PROBE-" + uuid.uuid4().hex[:8])
    url:              str
    hostname:         str = ""
    status:           HttpProbeStatus = HttpProbeStatus.UNKNOWN
    http_status_code: Optional[int] = None
    title:            str = ""
    server:           str = ""
    content_type:     str = ""
    content_length:   Optional[int] = None
    redirect_location:Optional[str] = None
    response_time_ms: float = 0.0
    technologies:     list[str] = Field(default_factory=list)
    headers:          dict[str, str] = Field(default_factory=dict)
    live:             bool = False
    https_available:  Optional[bool] = None
    evidence_ids:     list[str] = Field(default_factory=list)
    probed_at:        datetime = Field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# DiscoveredPath — one path from FFUF or crawler
# ---------------------------------------------------------------------------

class DiscoveredPathStatus(StrEnum):
    DISCOVERED    = "discovered"
    REACHABLE     = "reachable"
    REDIRECT      = "redirect"
    FORBIDDEN     = "forbidden"
    NOT_FOUND     = "not_found"
    ERROR         = "error"
    INCONCLUSIVE  = "inconclusive"


class DiscoveredPath(BaseModel):
    """A single path discovered by FFUF, crawler, or JS analysis."""
    id:               str = Field(default_factory=lambda: "PATH-" + uuid.uuid4().hex[:8])
    url:              str
    hostname:         str = ""
    path:             str = ""
    source:           str = ""          # "ffuf" | "crawler" | "js-analysis" | "probe"
    status:           DiscoveredPathStatus = DiscoveredPathStatus.DISCOVERED
    http_status_code: Optional[int] = None
    content_length:   Optional[int] = None
    content_type:     str = ""
    redirect_location:Optional[str] = None
    in_scope:         bool = True
    evidence_ids:     list[str] = Field(default_factory=list)
    discovered_at:    datetime = Field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# Endpoint — canonical merged URL endpoint
# ---------------------------------------------------------------------------

class Endpoint(BaseModel):
    """
    A canonical URL endpoint merged from crawler + FFUF + JS + probes.
    Same URL from multiple sources = ONE Endpoint.
    """
    id:           str = Field(default_factory=lambda: "EP-" + uuid.uuid4().hex[:8])
    url:          str
    method:       Optional[str] = None
    hostname:     str = ""
    path:         str = ""
    parameters:   list[str] = Field(default_factory=list)
    sources:      list[str] = Field(default_factory=list)   # ["crawler", "ffuf", "js-analysis"]
    technologies: list[str] = Field(default_factory=list)
    in_scope:     bool = True
    evidence_ids: list[str] = Field(default_factory=list)
    discovered_at:datetime = Field(default_factory=lambda: datetime.now(UTC))

    def add_source(self, source: str) -> None:
        if source not in self.sources:
            self.sources.append(source)


# ---------------------------------------------------------------------------
# ReconSummary — final recon output → XSS pipeline
# ---------------------------------------------------------------------------

class ReconSummary(BaseModel):
    """
    The output of the full recon pipeline.
    Consumed by crawler, XSS analysis, and reporting.
    """
    scan_id:       str

    # Asset inventory
    assets_discovered:  int = 0
    assets_in_scope:    int = 0
    assets_out_of_scope:int = 0
    assets_live:        int = 0
    assets_dead:        int = 0

    # Canonical collections
    assets:     list[ReconAsset]      = Field(default_factory=list)
    probes:     list[HttpProbeResult] = Field(default_factory=list)
    paths:      list[DiscoveredPath]  = Field(default_factory=list)
    endpoints:  list[Endpoint]        = Field(default_factory=list)

    # Tool observations
    tool_observations: list[ReconToolObservation] = Field(default_factory=list)

    # Tool run states (explicit, not conflated)
    tool_states: dict[str, str] = Field(default_factory=dict)  # tool_name -> ReconToolStatus

    # Technologies observed
    technologies: dict[str, list[str]] = Field(default_factory=dict)  # hostname -> [techs]

    completed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def live_urls(self) -> list[str]:
        """All confirmed live HTTP/S URLs — input to XSS crawler."""
        return [p.url for p in self.probes if p.live]

    @property
    def endpoint_urls(self) -> list[str]:
        return [e.url for e in self.endpoints if e.in_scope]
