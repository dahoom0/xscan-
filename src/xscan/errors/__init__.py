"""
XScan Exception Hierarchy
==========================

All XScan exceptions inherit from XScanError so callers can catch
the entire family with a single except clause.

Hierarchy:
  XScanError
  ├── ConfigError
  ├── StorageError
  │   └── MigrationError
  ├── ScopeError
  │   └── PolicyViolation          ← blocked by scope/policy
  ├── DAGError
  │   ├── WorkflowValidationError
  │   ├── NodeExecutionError
  │   └── CheckpointError
  ├── ToolError
  │   ├── ToolNotFoundError
  │   ├── CapabilityNotAvailableError
  │   └── ToolExecutionError
  ├── LLMError
  │   ├── LLMProviderError
  │   ├── LLMTimeoutError
  │   └── SpecialistOutputError     ← structured output did not validate
  ├── EvidenceError
  ├── FindingError
  │   └── MissingEvidenceError      ← finding created without evidence
  └── RuntimeError_                 ← avoid shadowing builtin RuntimeError
      └── WSLError
"""

from __future__ import annotations


class XScanError(Exception):
    """Base class for all XScan exceptions."""
    def __init__(self, message: str, *, context: dict[str, object] | None = None) -> None:
        super().__init__(message)
        self.context: dict[str, object] = context or {}


# ── Configuration ─────────────────────────────────────────────────────────────

class ConfigError(XScanError):
    """Invalid or missing configuration."""


# ── Storage ───────────────────────────────────────────────────────────────────

class StorageError(XScanError):
    """Database or persistence failure."""


class MigrationError(StorageError):
    """Schema migration failed."""


# ── Scope / Policy ────────────────────────────────────────────────────────────

class ScopeError(XScanError):
    """Scope configuration error."""


class PolicyViolation(ScopeError):
    """An operation was rejected by the policy engine."""
    def __init__(self, message: str, *, url: str = "", operation: str = "") -> None:
        super().__init__(message, context={"url": url, "operation": operation})
        self.url = url
        self.operation = operation


# ── DAG ───────────────────────────────────────────────────────────────────────

class DAGError(XScanError):
    """DAG engine error."""


class WorkflowValidationError(DAGError):
    """Workflow YAML failed validation."""


class NodeExecutionError(DAGError):
    """A DAG node raised an unhandled error."""
    def __init__(self, message: str, *, node_id: str = "") -> None:
        super().__init__(message, context={"node_id": node_id})
        self.node_id = node_id


class CheckpointError(DAGError):
    """DAG checkpoint save/load failed."""


# ── Tools ─────────────────────────────────────────────────────────────────────

class ToolError(XScanError):
    """Tool management error."""


class ToolNotFoundError(ToolError):
    """No tool registered for the requested name or capability."""
    def __init__(self, message: str, *, capability: str = "", name: str = "") -> None:
        super().__init__(message, context={"capability": capability, "name": name})


class CapabilityNotAvailableError(ToolError):
    """Capability required by a workflow node is not available."""


class ToolExecutionError(ToolError):
    """Tool subprocess exited with an error."""
    def __init__(self, message: str, *, exit_code: int = -1, stderr: str = "") -> None:
        super().__init__(message, context={"exit_code": exit_code, "stderr": stderr})
        self.exit_code = exit_code
        self.stderr = stderr


# ── LLM ───────────────────────────────────────────────────────────────────────

class LLMError(XScanError):
    """LLM gateway or provider error."""


class LLMProviderError(LLMError):
    """Provider (e.g. Ollama) returned an error."""


class LLMTimeoutError(LLMError):
    """LLM request timed out."""


class SpecialistOutputError(LLMError):
    """Specialist returned output that failed Pydantic validation."""
    def __init__(self, message: str, *, raw: str = "", specialist: str = "") -> None:
        super().__init__(message, context={"raw": raw[:500], "specialist": specialist})


# ── Evidence / Findings ───────────────────────────────────────────────────────

class EvidenceError(XScanError):
    """Evidence capture or storage error."""


class FindingError(XScanError):
    """Finding creation error."""


class MissingEvidenceError(FindingError):
    """Attempted to create a Finding without any linked EvidenceNode."""


# ── Target Loading ─────────────────────────────────────────────────────────────

class TargetLoadError(XScanError):
    """Target loading error (file not found, invalid URL, etc.)."""


# ── Runtime ───────────────────────────────────────────────────────────────────

class RuntimeError_(XScanError):
    """Execution runtime error (named with trailing _ to avoid shadowing builtin)."""


class WSLError(RuntimeError_):
    """WSL2 execution or communication error."""
