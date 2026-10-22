"""
XScan Doc Index
===============
Walks the docs/ directory tree and builds an in-memory index that maps
normalised topic keys to absolute Markdown file paths.

Index key rules
---------------
  docs/getting-started/index.md   → "getting-started"
  docs/getting-started/install.md → "getting-started-install"
  docs/concepts/dag.md            → "concepts-dag"  (also: "dag")
  docs/commands/scan.md           → "commands-scan"  (also: "scan")

The short alias (filename stem without the directory prefix) is registered
only when it is unique. If two files share the same stem, both get only their
fully-qualified key.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional


class DocIndex:
    """
    Lazy-loading index of Markdown documentation files.

    Build once, query many times.
    """

    def __init__(self, docs_root: Path) -> None:
        self.docs_root = docs_root
        self._index: dict[str, Path] = {}
        self._content_cache: dict[str, str] = {}
        self._built = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def find(self, topic_key: str) -> Optional[Path]:
        """Return the Path for *topic_key*, or None if not indexed."""
        self._ensure_built()
        return self._index.get(topic_key.lower().strip())

    def all_topics(self) -> list[str]:
        """Return every indexed topic key."""
        self._ensure_built()
        return list(self._index.keys())

    def all_docs(self) -> list[tuple[str, Path]]:
        """Return (topic_key, path) pairs for every indexed document."""
        self._ensure_built()
        return list(self._index.items())

    def content(self, topic_key: str) -> Optional[str]:
        """Return raw Markdown content for *topic_key*."""
        path = self.find(topic_key)
        if path is None:
            return None
        if topic_key not in self._content_cache:
            self._content_cache[topic_key] = path.read_text(encoding="utf-8")
        return self._content_cache[topic_key]

    def rebuild(self) -> None:
        """Force a full re-scan of the docs directory."""
        self._index.clear()
        self._content_cache.clear()
        self._built = False
        self._build()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _ensure_built(self) -> None:
        if not self._built:
            self._build()

    def _build(self) -> None:
        if not self.docs_root.exists():
            self._built = True
            return

        # stem → list of full keys (to detect collisions for short aliases)
        stem_map: dict[str, list[str]] = {}

        for md_file in sorted(self.docs_root.rglob("*.md")):
            rel = md_file.relative_to(self.docs_root)
            parts = list(rel.parts)
            stem = parts[-1].replace(".md", "")

            # Build fully-qualified key: join directory parts + stem
            dir_parts = parts[:-1]
            if stem == "index":
                # docs/getting-started/index.md → "getting-started"
                fq_key = "-".join(dir_parts) if dir_parts else "index"
            else:
                fq_key = "-".join(dir_parts + [stem]) if dir_parts else stem

            fq_key = self._normalise_key(fq_key)
            self._index[fq_key] = md_file

            # Track short alias candidates
            short = self._normalise_key(stem) if stem != "index" else fq_key
            stem_map.setdefault(short, []).append(fq_key)

        # Register short aliases only where they are unambiguous
        for short, fq_keys in stem_map.items():
            if len(fq_keys) == 1 and short not in self._index:
                self._index[short] = self._index[fq_keys[0]]

        self._built = True

    @staticmethod
    def _normalise_key(key: str) -> str:
        """Lower-case, replace spaces and underscores with hyphens."""
        return re.sub(r"[\s_]+", "-", key.lower().strip())
