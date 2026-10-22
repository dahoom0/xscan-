"""
Shared data models used across the scan pipeline.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import datetime


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class FindingType(str, Enum):
    XSS_REFLECTED  = "xss-reflected"
    XSS_STORED     = "xss-stored"
    XSS_DOM        = "xss-dom"
    OPEN_REDIRECT  = "open-redirect"
    INFO_DISCLOSURE = "info-disclosure"
    MISC           = "misc"


@dataclass
class HttpRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None


@dataclass
class HttpResponse:
    status_code: int
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed_ms: float = 0.0


@dataclass
class Form:
    action: str          # resolved URL
    method: str          # GET | POST
    inputs: list[dict]   # [{"name": "q", "type": "text", "value": ""}]
    source_url: str = ""


@dataclass
class XssCandidate:
    url: str
    parameter: str
    method: str          # GET | POST
    payload: str
    evidence: str        # snippet of response that contains the payload
    reflected: bool = False
    form: Optional[Form] = None
    request: Optional[HttpRequest] = None
    response: Optional[HttpResponse] = None


@dataclass
class Finding:
    id: str
    type: FindingType
    severity: Severity
    url: str
    parameter: str
    payload: str
    evidence: str
    description: str = ""
    remediation: str = ""
    llm_analysis: str = ""
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    request: Optional[HttpRequest] = None
    response: Optional[HttpResponse] = None


@dataclass
class ScanResult:
    target: str
    scan_id: str
    start_time: str
    end_time: str = ""
    profile: str = "balanced"
    # stage outputs
    urls_discovered: list[str] = field(default_factory=list)
    forms_discovered: list[Form] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    candidates: list[XssCandidate] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # stage counts
    requests_sent: int = 0
