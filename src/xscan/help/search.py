"""
XScan Help Search
=================
Keyword-based full-text search over indexed Markdown documentation.

Algorithm
---------
1. Tokenise the query into individual keywords (lower-cased).
2. For every indexed document, score it:
     - Each keyword found in the document title/heading  → +3
     - Each keyword found in the document body           → +1
3. Return results sorted descending by score, capped at MAX_RESULTS.

No external dependencies required — pure stdlib.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .index import DocIndex

MAX_RESULTS = 10
_STOP_WORDS = {
    "a", "an", "the", "and", "or", "in", "on", "at", "to", "for",
    "of", "is", "it", "i", "do", "how", "what", "where", "when",
    "can", "my", "me", "with", "from", "that", "this", "be",
}


@dataclass
class SearchResult:
    topic_key: str
    path: Path
    score: int
    title: str = ""
    snippet: str = ""
    matched_terms: list[str] = field(default_factory=list)

    def __lt__(self, other: "SearchResult") -> bool:
        return self.score > other.score  # reverse sort: higher score first


class HelpSearch:
    """Full-text search over the DocIndex."""

    def __init__(self, index: DocIndex) -> None:
        self._index = index

    def search(self, query: str, max_results: int = MAX_RESULTS) -> list[SearchResult]:
        """
        Search documentation for *query*.

        Returns a list of :class:`SearchResult` objects sorted by relevance.
        """
        keywords = self._tokenise(query)
        if not keywords:
            return []

        results: list[SearchResult] = []

        for topic_key, path in self._index.all_docs():
            content = self._index.content(topic_key) or ""
            score, matched, title, snippet = self._score(content, topic_key, keywords)
            if score > 0:
                results.append(SearchResult(
                    topic_key=topic_key,
                    path=path,
                    score=score,
                    title=title or topic_key,
                    snippet=snippet,
                    matched_terms=matched,
                ))

        results.sort()
        return results[:max_results]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _tokenise(query: str) -> list[str]:
        tokens = re.findall(r"[a-zA-Z0-9_\-]+", query.lower())
        return [t for t in tokens if t not in _STOP_WORDS and len(t) > 1]

    @staticmethod
    def _score(
        content: str,
        topic_key: str,
        keywords: list[str],
    ) -> tuple[int, list[str], str, str]:
        """
        Return (score, matched_terms, title, snippet).
        """
        content_lower = content.lower()
        lines = content.splitlines()

        # Extract title from first H1/H2
        title = topic_key
        for line in lines:
            if line.startswith("#"):
                title = line.lstrip("#").strip()
                break

        score = 0
        matched: list[str] = []
        snippet_line: Optional[str] = None

        # Heading lines (first 5) get bonus weight
        heading_text = " ".join(
            l.lstrip("#").lower() for l in lines[:5] if l.startswith("#")
        )
        # Also weight the topic key itself
        key_text = topic_key.replace("-", " ")

        for kw in keywords:
            # Title / heading match
            if kw in heading_text or kw in key_text:
                score += 3
                if kw not in matched:
                    matched.append(kw)
            # Body match
            if kw in content_lower:
                score += 1
                if kw not in matched:
                    matched.append(kw)
                # Grab first line containing this keyword as snippet
                if snippet_line is None:
                    for line in lines:
                        if kw in line.lower() and not line.startswith("#"):
                            snippet_line = line.strip()
                            break

        snippet = snippet_line or ""
        # Truncate long snippets
        if len(snippet) > 120:
            snippet = snippet[:117] + "..."

        return score, matched, title, snippet
