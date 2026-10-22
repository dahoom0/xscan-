"""
DOM Event detection.
Critical for event-driven DOM XSS (hashchange, postMessage, popstate, etc.).
"""
from __future__ import annotations
import re
from xscan.schemas.xss import DOMEventObservation, DOMSourceType
from xscan.nodes.dom.sources import SOURCE_REGISTRY
from xscan.nodes.dom.sinks import SINK_REGISTRY

# Events that commonly carry attacker-controlled data
RELEVANT_EVENTS = {
    "hashchange", "popstate", "message", "load", "DOMContentLoaded",
    "click", "input", "change", "submit", "keyup", "keydown",
    "focus", "blur", "resize", "scroll",
}

# Patterns that declare event listeners
_EVENT_LISTENER_PATTERNS: list[tuple[str, str]] = [
    # window.addEventListener('hashchange', fn)
    (r"(?:window|document)\s*\.\s*addEventListener\s*\(\s*['\"](\w+)['\"]", "addEventListener"),
    # $(window).on('hashchange', fn)
    (r"\$\s*\([^)]*\)\s*\.on\s*\(\s*['\"](\w+)['\"]",                      "jquery_on"),
    # $(window).bind('hashchange', fn)
    (r"\$\s*\([^)]*\)\s*\.bind\s*\(\s*['\"](\w+)['\"]",                    "jquery_bind"),
    # window.onhashchange = fn
    (r"(?:window|document)\s*\.\s*on(\w+)\s*=",                             "on_property"),
]


def detect_events(content: str, file_url: str) -> list[DOMEventObservation]:
    """Detect event-driven execution paths in JavaScript."""
    observations: list[DOMEventObservation] = []
    lines = content.splitlines()

    for line_no, line in enumerate(lines, 1):
        for pattern, _kind in _EVENT_LISTENER_PATTERNS:
            m = re.search(pattern, line, re.I)
            if not m:
                continue

            event_type = m.group(1).lower()
            if event_type not in RELEVANT_EVENTS:
                continue

            # Capture callback body — next 20 lines
            ctx_end   = min(len(lines), line_no + 20)
            ctx_block = "\n".join(lines[line_no - 1: ctx_end])

            # Find source refs in callback
            source_refs: list[str] = []
            for src_pattern, label, _, _ in SOURCE_REGISTRY:
                if re.search(src_pattern, ctx_block, re.I):
                    source_refs.append(label)

            # Find sink refs in callback
            sink_refs: list[str] = []
            for snk_pattern, snk_label, _, _ in SINK_REGISTRY:
                if re.search(snk_pattern, ctx_block, re.I):
                    sink_refs.append(snk_label)

            observations.append(DOMEventObservation(
                event_type=event_type,
                file_url=file_url,
                line=line_no,
                column=m.start(),
                callback_snippet=line.strip()[:200],
                source_refs=source_refs,
                sink_refs=sink_refs,
                context=ctx_block[:500],
            ))
            break  # one observation per line

    return observations
