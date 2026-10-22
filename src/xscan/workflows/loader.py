"""
WorkflowLoader
==============
Loads Workflow definitions from YAML files.

Search order:
  1. Built-in definitions shipped with the package
     (src/xscan/workflows/definitions/*.yaml)
  2. User-defined workflows in ~/.xscan/workflows/

YAML format::

    name: xss-balanced
    version: "1.0"
    description: "Balanced XSS analysis workflow"

    inputs:
      target_url:
        type: str
        required: true

    nodes:
      - id: scope-validation
        type: scope-check
        depends_on: []

      - id: recon
        type: technology-detect
        depends_on: [scope-validation]
        timeout: 60

      - id: crawl
        type: crawler
        depends_on: [recon]
        config:
          max_pages: 60
          max_depth: 3

    # ... etc.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from xscan.errors import WorkflowValidationError
from xscan.schemas.workflow import Workflow, WorkflowNode

logger = logging.getLogger(__name__)

# Built-in definitions live next to this file
_BUILTIN_DIR = Path(__file__).parent / "definitions"


class WorkflowLoader:
    """
    Load and cache Workflow objects from YAML.

    Usage::

        loader = WorkflowLoader()
        workflow = loader.load("xss-balanced")
        all_workflows = loader.list_available()
    """

    def __init__(self, user_dir: Path | None = None) -> None:
        self._user_dir = user_dir or (Path.home() / ".xscan" / "workflows")
        self._cache: dict[str, Workflow] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load(self, name: str) -> Workflow:
        """
        Load a workflow by name.  Searches built-in then user dir.
        Results are cached for the lifetime of this loader instance.
        """
        if name in self._cache:
            return self._cache[name]

        path = self._find(name)
        if path is None:
            available = self.list_available()
            raise WorkflowValidationError(
                f"Workflow '{name}' not found. Available: {available}"
            )

        workflow = self._parse(path)
        self._cache[name] = workflow
        return workflow

    def load_file(self, path: Path) -> Workflow:
        """Load directly from a file path."""
        return self._parse(path)

    def list_available(self) -> list[str]:
        """Return names of all available workflows (built-in + user)."""
        names: set[str] = set()
        for d in [_BUILTIN_DIR, self._user_dir]:
            if d.exists():
                for p in d.glob("*.yaml"):
                    names.add(p.stem)
                for p in d.glob("*.yml"):
                    names.add(p.stem)
        return sorted(names)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _find(self, name: str) -> Path | None:
        for d in [_BUILTIN_DIR, self._user_dir]:
            for ext in (".yaml", ".yml"):
                p = d / (name + ext)
                if p.exists():
                    return p
        return None

    @staticmethod
    def _parse(path: Path) -> Workflow:
        try:
            import yaml  # type: ignore[import]
        except ImportError as e:
            raise WorkflowValidationError(
                "PyYAML is required to load workflow files. "
                "Install with: pip install pyyaml"
            ) from e

        try:
            with open(path, encoding="utf-8") as f:
                data: dict[str, Any] = yaml.safe_load(f)
        except Exception as exc:
            raise WorkflowValidationError(f"Cannot parse workflow file {path}: {exc}") from exc

        if not isinstance(data, dict):
            raise WorkflowValidationError(f"Workflow file {path} must be a YAML mapping")

        nodes_raw = data.get("nodes", [])
        nodes = []
        for n in nodes_raw:
            if not isinstance(n, dict):
                raise WorkflowValidationError(f"Each node must be a YAML mapping in {path}")
            nodes.append(WorkflowNode(
                id=n.get("id", ""),
                type=n.get("type", ""),
                depends_on=n.get("depends_on", []),
                config=n.get("config", {}),
                capability=n.get("capability"),
                timeout=int(n.get("timeout", 300)),
                retry=int(n.get("retry", 0)),
            ))

        return Workflow(
            name=data.get("name", path.stem),
            version=str(data.get("version", "1.0")),
            description=data.get("description", ""),
            inputs=data.get("inputs", {}),
            nodes=nodes,
        )
