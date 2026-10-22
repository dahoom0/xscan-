"""
XSSKnowledgeRegistry — loads and exposes all XSS knowledge YAML files.

This is the single authoritative source for:
  - Source patterns (what browser APIs carry attacker data)
  - Sink patterns (what browser APIs execute attacker data)
  - Context definitions (how injection context affects exploitability)
  - Test strategies (which payloads to try for each context)

Rules:
  - All data is loaded from YAML — no hardcoded lists in scanner nodes.
  - The registry is read-only after load — nodes never write to it.
  - LLM specialists receive excerpts from this registry, not the raw source.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, ClassVar

import yaml

_HERE = Path(__file__).parent


@dataclass
class SourceEntry:
    id: str
    label: str
    pattern: str
    input_type: str
    confidence: str = "medium"
    framework: str = ""
    notes: str = ""
    _compiled: Any = field(default=None, repr=False)

    @property
    def regex(self) -> re.Pattern:
        if self._compiled is None:
            self._compiled = re.compile(self.pattern, re.I)
        return self._compiled

    def matches(self, code: str) -> bool:
        return bool(self.regex.search(code))


@dataclass
class SinkEntry:
    id: str
    label: str
    pattern: str
    severity: str
    category: str
    requires_browser: bool = True
    framework: str = ""
    notes: str = ""
    # What the sink does with its input, and how a browser must trigger it.
    # Empty values fall back to the category defaults below.
    kind: str = ""
    interaction: str = ""
    _compiled: Any = field(default=None, repr=False)

    # category → (kind, interaction)
    _CATEGORY_DEFAULTS: ClassVar[dict[str, tuple[str, str]]] = {
        "html_injection":  ("html_text",     "none"),
        "js_execution":    ("js_execution",  "none"),
        "url_sink":        ("url_attribute", "click"),
        "dom_property":    ("html_text",     "none"),
        "framework":       ("html_text",     "none"),
        "framework_bypass": ("html_text",    "none"),
    }

    @property
    def resolved_kind(self) -> str:
        if self.kind:
            return self.kind
        return self._CATEGORY_DEFAULTS.get(self.category, ("html_text", "none"))[0]

    @property
    def resolved_interaction(self) -> str:
        if self.interaction:
            return self.interaction
        return self._CATEGORY_DEFAULTS.get(self.category, ("html_text", "none"))[1]

    @property
    def regex(self) -> re.Pattern:
        if self._compiled is None:
            self._compiled = re.compile(self.pattern, re.I)
        return self._compiled

    def matches(self, code: str) -> bool:
        return bool(self.regex.search(code))


@dataclass
class ContextEntry:
    id: str
    label: str
    description: str
    breakout_chars: list[str]
    test_strategy: str
    xss_possible: bool
    requires_browser: bool = True
    notes: str = ""
    example: str = ""


@dataclass
class StrategyPayload:
    category: str
    examples: list[str]
    source_type: str = ""
    note: str = ""


@dataclass
class StrategyEntry:
    id: str
    label: str
    context_ids: list[str]
    max_http_attempts: int
    payloads: list[StrategyPayload] = field(default_factory=list)
    notes: str = ""

    def all_payloads(self, source_type: str = "") -> list[str]:
        """Return all example payloads, optionally filtered by source_type."""
        result = []
        for p in self.payloads:
            if source_type and p.source_type and p.source_type != source_type:
                continue
            result.extend(p.examples)
        return result


class XSSKnowledgeRegistry:
    """
    Singleton registry loaded from YAML files.
    All scanner nodes access XSS knowledge through this registry.
    """

    def __init__(self) -> None:
        self._sources:   list[SourceEntry]   = []
        self._sinks:     list[SinkEntry]     = []
        self._contexts:  list[ContextEntry]  = []
        self._strategies:list[StrategyEntry] = []
        self._loaded = False

    # ------------------------------------------------------------------
    # Load
    # ------------------------------------------------------------------

    def load(self) -> None:
        if self._loaded:
            return
        self._sources   = self._load_sources()
        self._sinks     = self._load_sinks()
        self._contexts  = self._load_contexts()
        self._strategies= self._load_strategies()
        self._loaded = True

    def _read(self, filename: str) -> list[dict]:
        path = _HERE / filename
        if not path.exists():
            return []
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, list) else (data.get(list(data.keys())[0], []) if data else [])

    def _load_sources(self) -> list[SourceEntry]:
        raw = self._read_key("sources.yaml", "sources")
        return [SourceEntry(**{k: v for k, v in r.items() if k != "compiled"})
                for r in raw]

    def _load_sinks(self) -> list[SinkEntry]:
        raw = self._read_key("sinks.yaml", "sinks")
        return [SinkEntry(**{k: v for k, v in r.items() if k != "compiled"})
                for r in raw]

    def _load_contexts(self) -> list[ContextEntry]:
        raw = self._read_key("contexts.yaml", "contexts")
        return [ContextEntry(**r) for r in raw]

    def _load_strategies(self) -> list[StrategyEntry]:
        raw = self._read_key("test_strategies.yaml", "strategies")
        entries = []
        for r in raw:
            payloads = [
                StrategyPayload(
                    category=p.get("category", ""),
                    examples=p.get("examples", []),
                    source_type=p.get("source_type", ""),
                    note=p.get("note", ""),
                )
                for p in r.get("payloads", [])
            ]
            entries.append(StrategyEntry(
                id=r["id"],
                label=r["label"],
                context_ids=r.get("context_ids", []),
                max_http_attempts=r.get("max_http_attempts", 3),
                payloads=payloads,
                notes=r.get("notes", ""),
            ))
        return entries

    def _read_key(self, filename: str, key: str) -> list[dict]:
        path = _HERE / filename
        if not path.exists():
            return []
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return data.get(key, [])

    # ------------------------------------------------------------------
    # Access
    # ------------------------------------------------------------------

    @property
    def sources(self) -> list[SourceEntry]:
        self.load()
        return self._sources

    @property
    def sinks(self) -> list[SinkEntry]:
        self.load()
        return self._sinks

    @property
    def contexts(self) -> list[ContextEntry]:
        self.load()
        return self._contexts

    @property
    def strategies(self) -> list[StrategyEntry]:
        self.load()
        return self._strategies

    def context(self, context_id: str) -> ContextEntry | None:
        self.load()
        return next((c for c in self._contexts if c.id == context_id), None)

    def sink_by_label(self, label: str) -> SinkEntry | None:
        self.load()
        return next((s for s in self._sinks if s.label == label), None)

    def source_by_id(self, source_id: str) -> SourceEntry | None:
        self.load()
        return next((s for s in self._sources if s.id == source_id), None)

    def strategy_for_context(self, context_id: str) -> StrategyEntry | None:
        """Return the test strategy for a given context id."""
        self.load()
        return next(
            (s for s in self._strategies if context_id in s.context_ids),
            None,
        )

    def payloads_for(
        self,
        context_id: str = "",
        source_type: str = "",
        sink_label: str = "",
        max_count: int = 8,
    ) -> list[str]:
        """
        Return the best payloads for the given context/source/sink combination.

        Priority:
        1. Strategy matching context_id
        2. Filter by source_type if provided
        3. Cap at max_count
        """
        self.load()
        strategy = self.strategy_for_context(context_id) if context_id else None

        if not strategy:
            # No strategy — return empty (caller should generate manual test)
            return []

        payloads = strategy.all_payloads(source_type=source_type)

        # For Angular bypass sinks, force the api_response payloads
        if sink_label and "bypass" in sink_label.lower():
            bypass_strategy = next(
                (s for s in self._strategies if s.id == "dom_specific"), None
            )
            if bypass_strategy:
                payloads = bypass_strategy.all_payloads(source_type="api_response")

        return payloads[:max_count]

    def find_sources_in_code(self, code: str) -> list[SourceEntry]:
        """Return all sources whose pattern matches the given code."""
        self.load()
        return [s for s in self._sources if s.matches(code)]

    def find_sinks_in_code(self, code: str) -> list[SinkEntry]:
        """Return all sinks whose pattern matches the given code."""
        self.load()
        return [s for s in self._sinks if s.matches(code)]

    def context_is_exploitable_http_only(self, context_id: str) -> bool:
        """Return True if this context can be tested without a browser."""
        ctx = self.context(context_id)
        if ctx is None:
            return False
        if not ctx.xss_possible:
            return False
        strategy = self.strategy_for_context(context_id)
        if strategy and strategy.max_http_attempts == 0:
            return False
        return True

    def summary_for_llm(self, max_sources: int = 5, max_sinks: int = 5) -> str:
        """Produce a compact summary for inclusion in LLM prompts."""
        self.load()
        lines = ["=== XSS Knowledge ==="]
        lines.append(f"Sources ({len(self._sources)}):")
        for s in self._sources[:max_sources]:
            lines.append(f"  {s.id}: {s.label} ({s.input_type})")
        lines.append(f"\nSinks ({len(self._sinks)}):")
        for s in self._sinks[:max_sinks]:
            lines.append(f"  {s.id}: {s.label} [{s.severity}]")
        return "\n".join(lines)


# Module-level singleton — load once, reuse everywhere
xss_knowledge = XSSKnowledgeRegistry()
