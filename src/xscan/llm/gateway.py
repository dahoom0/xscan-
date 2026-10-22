"""
LLMGateway
==========
Single entry point for all LLM calls in XScan.

Architecture:
  Specialist
      ↓
  LLMGateway.complete(request)
      ↓
  Provider (Ollama / future OpenAI-compatible)
      ↓
  Model (Qwen3, DeepSeek, Mistral, …)

Rules enforced here:
  - All requests are logged (scan_id, node_id, specialist, token counts)
  - Timeout is always bounded
  - Providers are pluggable — specialists never know about Ollama URLs
  - Structured output validation is the caller's responsibility (specialists)
"""
from __future__ import annotations

import functools
import logging
from typing import TYPE_CHECKING

from xscan.config import get_settings
from xscan.errors import LLMError, LLMProviderError, LLMTimeoutError
from xscan.schemas.llm import LLMRequest, LLMResponse

if TYPE_CHECKING:
    from xscan.llm.providers.base import LLMProvider

logger = logging.getLogger(__name__)


class LLMGateway:
    """
    Routes LLM requests to the configured provider.

    Usage::

        gateway = LLMGateway()
        response = gateway.complete(LLMRequest(
            model="qwen3:14b",
            user_prompt="Analyse this JavaScript ...",
            specialist="sink",
            scan_id="A1B2C3",
        ))
    """

    def __init__(self, provider: "LLMProvider | None" = None) -> None:
        self._provider = provider or self._default_provider()

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def complete(self, request: LLMRequest) -> LLMResponse:
        """Send a single request and return the response."""
        logger.debug(
            "LLM request  model=%s  specialist=%s  scan=%s  node=%s",
            request.model, request.specialist, request.scan_id, request.node_id,
        )
        try:
            response = self._provider.complete(request)
        except LLMError:
            raise
        except Exception as exc:
            raise LLMProviderError(f"Provider error: {exc}") from exc

        logger.debug(
            "LLM response  model=%s  tokens_in=%d  tokens_out=%d  ok=%s",
            response.model, response.input_tokens, response.output_tokens, response.success,
        )
        return response

    def active_model(self) -> str:
        """Return the name of the currently configured model."""
        return get_settings().llm.model

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _default_provider() -> "LLMProvider":
        settings = get_settings()
        if settings.llm.provider == "ollama":
            from xscan.llm.providers.ollama import OllamaProvider
            return OllamaProvider(
                base_url=settings.llm.base_url,
                timeout=settings.llm.timeout,
            )
        raise LLMProviderError(f"Unknown LLM provider: {settings.llm.provider!r}")


@functools.lru_cache(maxsize=1)
def get_gateway() -> LLMGateway:
    """Return the process-wide LLMGateway singleton."""
    return LLMGateway()
