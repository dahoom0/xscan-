"""LLMRequest, LLMResponse, SpecialistInput, and SpecialistOutput schemas."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(UTC)




class LLMRequest(BaseModel):
    """A single request to an LLM provider."""
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    model: str
    system_prompt: str = ""
    user_prompt: str
    temperature: float = 0.1
    max_tokens: int = 2048
    timeout: int = 120
    specialist: str = ""            # which specialist issued this request
    scan_id: str = ""
    node_id: str = ""
    # Ask the provider for constrained JSON output (Ollama `format: "json"`)
    # when the caller is going to parse the reply as JSON anyway.
    json_mode: bool = False


class LLMResponse(BaseModel):
    """Raw response from an LLM provider."""
    request_id: str
    model: str
    raw_text: str
    input_tokens: int = 0
    output_tokens: int = 0
    duration_ms: float = 0.0
    created_at: datetime = Field(default_factory=_utcnow)
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.error is None and bool(self.raw_text)


class SpecialistInput(BaseModel):
    """
    Typed input passed to every LLM specialist.
    Subclassed by each specialist with additional fields.
    """
    scan_id: str
    node_id: str = ""
    context: dict[str, Any] = Field(default_factory=dict)


class SpecialistOutput(BaseModel):
    """
    Typed output returned by every LLM specialist.
    Subclassed by each specialist with additional fields.

    IMPORTANT: LLM output is analysis/opinion, never direct proof.
    Findings require deterministic evidence, not just SpecialistOutput.
    """
    specialist: str
    confidence: float = 0.0         # 0.0 â€“ 1.0
    reasoning: str = ""
    raw_response: str = ""
    llm_request_id: str = ""

