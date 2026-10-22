"""ModelService — delegates to LLM providers via the gateway."""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class ModelService:
    """Thin service wrapping the Ollama provider for CLI use."""

    def list(self) -> dict[str, Any]:
        from xscan.llm.providers.ollama import OllamaProvider
        provider = OllamaProvider()
        return provider.status_dict()

    def use(self, model: str) -> None:
        from xscan.config.defaults import CONFIG_FILE
        import re
        config = CONFIG_FILE
        config.parent.mkdir(parents=True, exist_ok=True)
        text = config.read_text(encoding="utf-8") if config.exists() else ""
        if re.search(r"^\s*model\s*=", text, re.MULTILINE):
            text = re.sub(r'(?m)^(\s*model\s*=\s*).*$', f'\\1"{model}"', text)
        else:
            text += f'\n[llm]\nmodel = "{model}"\n'
        config.write_text(text, encoding="utf-8")
        logger.info("Active model set to %s", model)

    def test(self, model: str | None = None) -> tuple[bool, str]:
        from xscan.llm.providers.ollama import OllamaProvider
        provider = OllamaProvider()
        target_model = model or provider.active_model()
        return provider.test_generate(target_model)

    def info(self, model: str) -> dict[str, Any] | None:
        from xscan.llm.providers.ollama import OllamaProvider
        provider = OllamaProvider()
        return provider.model_info(model)
