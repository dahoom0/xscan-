"""
XScan Help Engine
=================
Central dispatcher for all help and documentation requests.

Responsibilities:
  - Resolve a topic name to a Markdown document path
  - Delegate to DocIndex for filesystem-backed docs
  - Delegate to HelpSearch for free-text queries
  - Provide environment-aware context (installed tools, models, workflows)
  - Expose the guided interactive menu
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Optional

from .index import DocIndex
from .search import HelpSearch
from .renderer import HelpRenderer
from .topics import TOPICS, GUIDED_MENU, TOPIC_ALIASES


# Locate the docs/ directory relative to this file's package root.
# Layout:  src/xscan/help/engine.py  →  project_root/docs/
_PKG_ROOT = Path(__file__).resolve().parent.parent.parent.parent  # project root
DOCS_ROOT = _PKG_ROOT / "docs"


class HelpEngine:
    """
    Central help broker.

    Usage::

        engine = HelpEngine()
        engine.show_topic("getting-started")
        engine.show_search("how do I add a crawler")
        engine.show_guided_menu()
    """

    def __init__(self, docs_root: Optional[Path] = None) -> None:
        self.docs_root = docs_root or DOCS_ROOT
        self._index = DocIndex(self.docs_root)
        self._search = HelpSearch(self._index)
        self._renderer = HelpRenderer()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def show_topic(self, topic: str) -> int:
        """
        Render documentation for *topic*.

        Accepts:
          - canonical topic names   ("getting-started")
          - aliases                 ("start" → "getting-started")
          - path-style names        ("concepts/dag")
          - command names           ("scan", "workflow")

        Returns exit code (0 = ok, 1 = not found).
        """
        resolved = self._resolve_topic(topic)
        if resolved is None:
            self._renderer.not_found(topic, list(TOPICS.keys()))
            return 1

        doc_path = self._index.find(resolved)
        if doc_path and doc_path.exists():
            self._renderer.render_file(doc_path)
        elif resolved in TOPICS:
            # Built-in inline topic (no Markdown file required)
            self._renderer.render_inline(TOPICS[resolved])
        else:
            self._renderer.not_found(topic, list(TOPICS.keys()))
            return 1
        return 0

    def show_search(self, query: str) -> int:
        """Full-text search across indexed documentation."""
        results = self._search.search(query)
        if not results:
            self._renderer.no_search_results(query)
            return 1
        self._renderer.render_search_results(query, results)
        return 0

    def show_guided_menu(self) -> int:
        """Render the interactive 'What are you trying to do?' menu."""
        self._renderer.render_guided_menu(GUIDED_MENU)
        return 0

    def show_topic_list(self) -> int:
        """Print every available help topic."""
        all_topics = sorted(
            set(list(TOPICS.keys()) + self._index.all_topics())
        )
        self._renderer.render_topic_list(all_topics)
        return 0

    # ------------------------------------------------------------------
    # Environment-aware helpers (used by specialised help sub-topics)
    # ------------------------------------------------------------------

    def installed_tools(self) -> dict[str, bool]:
        """
        Return a mapping of known tool names → installed (bool).
        Checks PATH and ~/.xscan/bin.
        """
        known = [
            "katana", "httpx", "dnsx", "amass", "subfinder",
            "nuclei", "ffuf", "waybackurls", "gau", "hakrawler",
            "gospider", "dalfox", "kxss", "cariddi", "playwright",
        ]
        xscan_bin = Path.home() / ".xscan" / "bin"
        result: dict[str, bool] = {}
        for tool in known:
            in_path = shutil.which(tool) is not None
            in_xscan = (xscan_bin / tool).exists() or (xscan_bin / (tool + ".exe")).exists()
            result[tool] = in_path or in_xscan
        return result

    def available_models(self) -> dict[str, bool]:
        """
        Return known local LLM names → available (bool).
        Queries Ollama's REST API if reachable; falls back to config.
        """
        known = ["qwen3", "deepseek-coder", "mistral", "llama3", "codellama", "phi3"]
        available: dict[str, bool] = {}
        try:
            import urllib.request, json as _json
            with urllib.request.urlopen("http://localhost:11434/api/tags", timeout=2) as r:
                data = _json.loads(r.read())
            pulled = {m["name"].split(":")[0] for m in data.get("models", [])}
            for m in known:
                available[m] = m in pulled
        except Exception:
            for m in known:
                available[m] = False
        return available

    def registered_workflows(self) -> list[str]:
        """Return workflow names discovered from the workflows/ package."""
        wf_dir = self.docs_root.parent / "src" / "xscan" / "workflows"
        names: list[str] = []
        if wf_dir.exists():
            for p in wf_dir.glob("*.py"):
                if not p.name.startswith("_"):
                    names.append(p.stem.replace("_", "-"))
        # Also pick up workflow docs
        wf_docs = self.docs_root / "workflows"
        if wf_docs.exists():
            for p in wf_docs.glob("*.md"):
                name = p.stem
                if name not in names:
                    names.append(name)
        return sorted(names)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_topic(self, raw: str) -> Optional[str]:
        """Normalise and alias-expand a raw topic string."""
        normalised = raw.lower().strip().replace(" ", "-")
        if normalised in TOPICS:
            return normalised
        if normalised in TOPIC_ALIASES:
            return TOPIC_ALIASES[normalised]
        # Allow path-style: concepts/dag → concepts-dag for lookup
        path_key = normalised.replace("/", "-")
        if path_key in TOPICS:
            return path_key
        if path_key in TOPIC_ALIASES:
            return TOPIC_ALIASES[path_key]
        # Check if it resolves to a doc file directly
        if self._index.find(normalised):
            return normalised
        return None
