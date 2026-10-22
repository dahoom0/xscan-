"""
XScan Ollama Client
===================
Thin wrapper around the Ollama REST API.

Endpoints used:
  GET  /api/tags   – list all pulled models
  GET  /api/ps     – list models currently loaded in memory (running)
  POST /api/generate  – single-turn generation (for test ping)
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

# Default Ollama base URL — overridden by ~/.xscan/config.toml
DEFAULT_BASE_URL = "http://localhost:11434"
DEFAULT_TIMEOUT = 5  # seconds for status queries


@dataclass
class OllamaModel:
    """One model entry returned by /api/tags."""
    name: str                     # e.g. "qwen3:14b"
    family: str = ""              # e.g. "qwen3"
    size_bytes: int = 0
    modified_at: str = ""
    digest: str = ""
    running: bool = False         # True if currently loaded in VRAM via /api/ps

    @property
    def size_human(self) -> str:
        """Human-readable size string."""
        gb = self.size_bytes / (1024 ** 3)
        if gb >= 1:
            return f"{gb:.1f} GB"
        mb = self.size_bytes / (1024 ** 2)
        return f"{mb:.0f} MB"

    @property
    def short_name(self) -> str:
        """Name without the tag, e.g. 'qwen3:14b' → 'qwen3'."""
        return self.name.split(":")[0]


@dataclass
class OllamaStatus:
    reachable: bool
    base_url: str
    version: str = ""
    error: str = ""
    models: list[OllamaModel] = field(default_factory=list)
    running_models: list[str] = field(default_factory=list)


def _get(url: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """HTTP GET → parsed JSON dict. Raises on error."""
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _post(url: str, body: dict, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """HTTP POST JSON → parsed JSON dict. Raises on error."""
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


class OllamaClient:
    """
    Interact with a local Ollama instance.

    Usage::

        client = OllamaClient()
        status = client.status()
        models = client.list_models()
        running = client.running_models()
    """

    def __init__(self, base_url: str = DEFAULT_BASE_URL) -> None:
        self.base_url = base_url.rstrip("/")

    # ------------------------------------------------------------------
    # High-level status
    # ------------------------------------------------------------------

    def status(self) -> OllamaStatus:
        """
        Return a full OllamaStatus: reachable, version, pulled models,
        and which models are currently loaded in memory.
        """
        try:
            # Get Ollama version
            version = ""
            try:
                v = _get(f"{self.base_url}/api/version")
                version = v.get("version", "")
            except Exception:
                pass

            models = self.list_models()
            running = self.running_models()

            # Mark running flag on each model
            running_names = {r.split(":")[0] for r in running} | set(running)
            for m in models:
                m.running = m.name in running or m.short_name in running_names

            return OllamaStatus(
                reachable=True,
                base_url=self.base_url,
                version=version,
                models=models,
                running_models=running,
            )
        except (urllib.error.URLError, ConnectionRefusedError, OSError) as exc:
            return OllamaStatus(
                reachable=False,
                base_url=self.base_url,
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # Model listing
    # ------------------------------------------------------------------

    def list_models(self) -> list[OllamaModel]:
        """Return all models pulled locally via /api/tags."""
        data = _get(f"{self.base_url}/api/tags")
        results = []
        for m in data.get("models", []):
            details = m.get("details", {})
            results.append(OllamaModel(
                name=m.get("name", ""),
                family=details.get("family", m.get("name", "").split(":")[0]),
                size_bytes=m.get("size", 0),
                modified_at=m.get("modified_at", ""),
                digest=m.get("digest", "")[:12] if m.get("digest") else "",
            ))
        return sorted(results, key=lambda x: x.name)

    def running_models(self) -> list[str]:
        """
        Return names of models currently loaded in memory via /api/ps.
        Falls back to empty list if the endpoint is unavailable (older Ollama).
        """
        try:
            data = _get(f"{self.base_url}/api/ps")
            return [m.get("name", "") for m in data.get("models", [])]
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Connectivity test
    # ------------------------------------------------------------------

    def ping(self) -> bool:
        """Return True if Ollama is reachable."""
        try:
            _get(f"{self.base_url}/api/tags", timeout=3)
            return True
        except Exception:
            return False

    def test_model(self, model: str, prompt: str = "Reply with OK only.") -> tuple[bool, str]:
        """
        Send a minimal generation request to verify a model responds.
        Returns (success, response_text_or_error).
        """
        try:
            data = _post(
                f"{self.base_url}/api/generate",
                {"model": model, "prompt": prompt, "stream": False},
                timeout=120,
            )
            return True, data.get("response", "").strip()
        except urllib.error.HTTPError as exc:
            return False, f"HTTP {exc.code}: {exc.reason}"
        except Exception as exc:
            return False, str(exc)
