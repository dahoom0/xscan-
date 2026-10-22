"""
OllamaProvider
==============
Adapter for the Ollama local LLM server.
Migrated from the prototype llm/ollama.py and wired behind LLMGateway.

Specialists never import this directly — they use LLMGateway.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from datetime import datetime, UTC
from typing import Any

from xscan.config.defaults import DEFAULT_LLM_MODEL, OLLAMA_BASE_URL
from xscan.errors import LLMProviderError, LLMTimeoutError
from xscan.llm.providers.base import LLMProvider
from xscan.schemas.llm import LLMRequest, LLMResponse

_DEFAULT_TIMEOUT = 5


def _http_get(url: str, timeout: int = _DEFAULT_TIMEOUT) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())  # type: ignore[no-any-return]


def _http_post(url: str, body: dict[str, Any], timeout: int = 120) -> dict[str, Any]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())  # type: ignore[no-any-return]


class OllamaProvider(LLMProvider):
    """
    Adapter for Ollama's REST API.

    Endpoints used:
      GET  /api/version  — server version
      GET  /api/tags     — list pulled models
      GET  /api/ps       — models loaded in memory
      POST /api/generate — single-turn generation
    """

    def __init__(
        self,
        base_url: str = OLLAMA_BASE_URL,
        timeout: int = 120,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout

    # ------------------------------------------------------------------
    # LLMProvider interface
    # ------------------------------------------------------------------

    def complete(self, request: LLMRequest) -> LLMResponse:
        prompt = f"{request.system_prompt}\n\n{request.user_prompt}".strip()
        t0 = time.monotonic()
        body: dict[str, Any] = {
            "model":   request.model,
            "prompt":  prompt,
            "stream":  False,
            "options": {
                "temperature": request.temperature,
                "num_predict": request.max_tokens,
            },
        }
        if request.json_mode:
            # Constrain decoding to valid JSON (Ollama structured outputs;
            # `format` accepts the string "json" or a JSON schema object).
            body["format"] = "json"
        try:
            data = _http_post(f"{self._base}/api/generate", body, timeout=request.timeout or self._timeout)
        except urllib.error.HTTPError as exc:
            raise LLMProviderError(f"Ollama HTTP {exc.code}: {exc.reason}") from exc
        except TimeoutError as exc:
            raise LLMTimeoutError(f"Ollama timed out after {request.timeout}s") from exc
        except Exception as exc:
            raise LLMProviderError(f"Ollama request failed: {exc}") from exc

        elapsed_ms = (time.monotonic() - t0) * 1000
        return LLMResponse(
            request_id=request.id,
            model=data.get("model", request.model),
            raw_text=data.get("response", "").strip(),
            input_tokens=data.get("prompt_eval_count", 0),
            output_tokens=data.get("eval_count", 0),
            duration_ms=round(elapsed_ms, 1),
            created_at=datetime.now(UTC),
        )

    def ping(self) -> bool:
        try:
            _http_get(f"{self._base}/api/tags", timeout=3)
            return True
        except Exception:
            return False

    def list_models(self) -> list[str]:
        try:
            data = _http_get(f"{self._base}/api/tags")
            return [m.get("name", "") for m in data.get("models", [])]
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Extended helpers (used by ModelService + doctor)
    # ------------------------------------------------------------------

    def active_model(self) -> str:
        from xscan.config import get_settings
        return get_settings().llm.model

    def status_dict(self) -> dict[str, Any]:
        """Full status including running models — used by CLI `models list`."""
        try:
            tags = _http_get(f"{self._base}/api/tags")
        except Exception:
            return {"reachable": False, "models": [], "running": [], "version": ""}

        version = ""
        try:
            v = _http_get(f"{self._base}/api/version")
            version = v.get("version", "")
        except Exception:
            pass

        running: list[str] = []
        try:
            ps = _http_get(f"{self._base}/api/ps")
            running = [m.get("name", "") for m in ps.get("models", [])]
        except Exception:
            pass

        models = []
        for m in tags.get("models", []):
            sz = m.get("size", 0)
            gb = sz / (1024 ** 3)
            size_str = f"{gb:.1f} GB" if gb >= 1 else f"{sz / (1024**2):.0f} MB"
            models.append({
                "name":        m.get("name", ""),
                "family":      m.get("details", {}).get("family", ""),
                "size_human":  size_str,
                "size_bytes":  sz,
                "digest":      (m.get("digest", "") or "")[:12],
                "modified_at": (m.get("modified_at", "") or "")[:10],
                "running":     m.get("name", "") in running,
            })

        return {
            "reachable": True,
            "version":   version,
            "base_url":  self._base,
            "models":    sorted(models, key=lambda x: x["name"]),
            "running":   running,
        }

    def model_info(self, model: str) -> dict[str, Any] | None:
        status = self.status_dict()
        for m in status.get("models", []):
            if m["name"] == model or m["name"].split(":")[0] == model:
                return m
        return None

    def test_generate(self, model: str, prompt: str = "Reply with OK only.") -> tuple[bool, str]:
        try:
            req = LLMRequest(
                model=model,
                user_prompt=prompt,
                specialist="doctor",
                timeout=120,
            )
            resp = self.complete(req)
            return True, resp.raw_text[:120]
        except Exception as exc:
            return False, str(exc)
