"""Ollama connectivity and model availability check."""
from __future__ import annotations
from xscan.doctor.checks.base import BaseCheck
from xscan.services.doctor import HealthResult


class OllamaCheck(BaseCheck):
    name = "ollama"

    def run(self) -> HealthResult:
        from xscan.llm.providers.ollama import OllamaProvider
        provider = OllamaProvider()

        if not provider.ping():
            return HealthResult(
                name=self.name,
                ok=False,
                detail="Ollama is not reachable at localhost:11434",
                fix_available=True,
                fix_description="Start Ollama: ollama serve",
            )

        status = provider.status_dict()
        models = status.get("models", [])
        if not models:
            return HealthResult(
                name=self.name,
                ok=False,
                detail="Ollama is running but no models are pulled",
                fix_available=True,
                fix_description="ollama pull qwen3",
            )

        names = [m["name"] for m in models]
        return HealthResult(
            name=self.name,
            ok=True,
            detail=f"Ollama v{status.get('version', '?')}  models: {', '.join(names[:5])}",
        )
