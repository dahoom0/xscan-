"""
ast-parser node — Phase C
==========================
Parses JavaScript source text into structured AstRecord objects.
Uses regex-based heuristic AST (no external JS parser dependency).
Retains file + line + column + snippet for every observation.

For production-quality analysis use esprima-python or node+acorn.
This implementation is safe to run in CI without extra deps.

Inputs:  js_files (list[dict])
Outputs: ast_records (list[dict])  — AstRecord per interesting node
         ast_file_count (int)
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field, asdict
from typing import Any

from xscan.core.dag.node_registry import registry
from xscan.nodes.base import NodeBase, ExecutionContext
from xscan.nodes.emitter import NodeEmitter


@dataclass
class AstRecord:
    """Represents a single interesting construct found in JavaScript."""
    file_url:      str
    line:          int
    column:        int
    node_type:     str      # variable_decl | assignment | function_call | event_listener | string_literal | template_literal
    name:          str      # variable/function name
    value:         str      # RHS / argument snippet
    snippet:       str      # full line
    extra:         dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# Regex patterns for common JS constructs
_PATTERNS: list[tuple[str, str]] = [
    # variable declarations
    (r"\b(?:var|let|const)\s+([\w$]+)\s*=\s*(.{0,120})",  "variable_decl"),
    # assignments
    (r"([\w$\.]+)\s*=\s*(?!={1,2})(.{0,120})",             "assignment"),
    # function calls
    (r"([\w$\.]+)\s*\(([^)]{0,200})\)",                    "function_call"),
    # event listeners
    (r"addEventListener\s*\(\s*['\"](\w+)['\"]",           "event_listener"),
    # jQuery event
    (r"\$\([\s\S]*?\)\.on\s*\(\s*['\"](\w+)['\"]",        "jquery_event"),
    # template literals
    (r"`([^`]{0,200})`",                                    "template_literal"),
]

# Source identifiers to flag
_SOURCE_PATTERNS = [
    "location.search", "location.hash", "location.href",
    "document.URL", "document.referrer", "window.name",
    "URLSearchParams", "decodeURIComponent", "postMessage",
    "document.cookie", "localStorage", "sessionStorage",
]

# Sink identifiers to flag — plain substrings, matched with `in`.
_SINK_SUBSTRINGS = [
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "eval(", "Function(", "setTimeout", "setInterval",
    ".html(", ".append(", ".prepend(", ".after(", ".before(",
    "insertAdjacentHTML", ".href", ".src", ".setAttribute(",
    "location.assign", "location.replace",
]

# Sinks that need a real regex (a bare "(" in the list above must never be
# handed to re.search — that raised re.PatternError and failed the whole node).
_SINK_REGEXES = [re.compile(r"\$\s*\(")]


def _has_sink(line: str) -> bool:
    return any(s in line for s in _SINK_SUBSTRINGS) or any(
        r.search(line) for r in _SINK_REGEXES
    )


def _sink_hits(line: str) -> list[str]:
    hits = [s for s in _SINK_SUBSTRINGS if s in line]
    hits.extend(r.pattern for r in _SINK_REGEXES if r.search(line))
    return hits


@registry.register("ast-parser")
class AstParserNode(NodeBase, NodeEmitter):
    node_type = "ast-parser"

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        t0 = self.emit_started(ctx)

        js_files:    list[dict] = ctx.get("js_files", [])
        ast_records: list[dict] = []

        for js_file in js_files:
            url     = js_file.get("url", "")
            content = js_file.get("content", "")
            records = self._parse(content, url)
            ast_records.extend(r.to_dict() for r in records)

        ms = (time.monotonic() - t0) * 1000
        self.emit_completed(ctx, metrics={
            "js_files_parsed": len(js_files),
            "ast_records":     len(ast_records),
        }, duration_ms=ms)

        return {
            "ast_records":    ast_records,
            "ast_file_count": len(js_files),
        }

    def _parse(self, content: str, url: str) -> list[AstRecord]:
        records: list[AstRecord] = []
        lines = content.splitlines()

        for line_no, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or len(stripped) < 5:
                continue

            # Check if line contains a source or sink — only parse those lines
            has_source = any(s in line for s in _SOURCE_PATTERNS)
            has_sink   = _has_sink(line)

            if not (has_source or has_sink):
                continue

            for pattern, node_type in _PATTERNS:
                for m in re.finditer(pattern, line):
                    name   = m.group(1)[:80] if m.lastindex and m.lastindex >= 1 else ""
                    value  = m.group(2)[:120] if m.lastindex and m.lastindex >= 2 else ""
                    extra: dict[str, Any] = {}

                    if has_source:
                        src_hits = [s for s in _SOURCE_PATTERNS if s in line]
                        extra["sources"] = src_hits
                    if has_sink:
                        extra["sinks"] = _sink_hits(line)

                    records.append(AstRecord(
                        file_url=url,
                        line=line_no,
                        column=m.start(),
                        node_type=node_type,
                        name=name,
                        value=value,
                        snippet=stripped[:200],
                        extra=extra,
                    ))
                    break  # one record per pattern per line is enough

        return records
