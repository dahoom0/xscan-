"""XScan typed domain schemas (Pydantic v2)."""
from xscan.schemas.events import DomainEvent, EventType
from xscan.schemas.evidence import (
    Artifact,
    EvidenceEdge,
    EvidenceNode,
    EvidenceType,
)
from xscan.schemas.finding import Finding, FindingStatus, FindingType, Severity
from xscan.schemas.llm import (
    LLMRequest,
    LLMResponse,
    SpecialistInput,
    SpecialistOutput,
)
from xscan.schemas.scan import Scan, ScanProfile, ScanStatus, Target
from xscan.schemas.scope import Scope, ScopeRule, ScopeRuleType
from xscan.schemas.tool import Capability, Tool, ToolHealth, ToolStatus
from xscan.schemas.workflow import (
    NodeResult,
    NodeStatus,
    Workflow,
    WorkflowNode,
    WorkflowRun,
)
from xscan.schemas.xss import (
    XSSCandidate,
    XSSType,
    ValidationStatus,
    ContextObservation,
    DOMSourceObservation,
    DOMSinkObservation,
    DOMEventObservation,
    TaintNode,
    TaintEdge,
    TaintPath,
    ToolObservation,
    DOMSourceType,
    DOMSinkCategory,
    TaintNodeType,
    ToolStatus as XSSToolStatus,
)

__all__ = [
    # scan
    "Scan", "Target", "ScanStatus", "ScanProfile",
    # scope
    "Scope", "ScopeRule", "ScopeRuleType",
    # workflow
    "Workflow", "WorkflowNode", "NodeResult", "NodeStatus", "WorkflowRun",
    # finding
    "Finding", "Severity", "FindingType", "FindingStatus",
    # evidence
    "EvidenceNode", "EvidenceEdge", "EvidenceType", "Artifact",
    # tool
    "Tool", "Capability", "ToolHealth", "ToolStatus",
    # llm
    "LLMRequest", "LLMResponse", "SpecialistInput", "SpecialistOutput",
    # events
    "DomainEvent", "EventType",
    # xss domain
    "XSSCandidate", "XSSType", "ValidationStatus",
    "ContextObservation",
    "DOMSourceObservation", "DOMSinkObservation", "DOMEventObservation",
    "TaintNode", "TaintEdge", "TaintPath",
    "ToolObservation",
    "DOMSourceType", "DOMSinkCategory", "TaintNodeType",
    "XSSToolStatus",
]
