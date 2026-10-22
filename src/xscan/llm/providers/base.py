"""Base class for all LLM provider adapters."""
from __future__ import annotations
from abc import ABC, abstractmethod
from xscan.schemas.llm import LLMRequest, LLMResponse


class LLMProvider(ABC):
    @abstractmethod
    def complete(self, request: LLMRequest) -> LLMResponse: ...

    @abstractmethod
    def ping(self) -> bool: ...

    @abstractmethod
    def list_models(self) -> list[str]: ...
