"""
DOM-XSS Detection Diagnostics
==============================
Instrumentation module to trace why zero DOM-XSS candidates are generated.

This module adds comprehensive logging and metrics collection to the DOM analysis
pipeline to identify exact breakpoints in source-to-sink analysis.

Usage:
  - Import and call diagnostic functions during DAG node execution
  - Log detailed decision points
  - Collect and report metrics on what was analyzed and why discarded
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SourceAnalysisMetrics:
    """Metrics for source pattern analysis."""

    total_lines_analysed: int = 0
    lines_with_source_patterns: int = 0
    lines_with_sink_patterns: int = 0
    lines_with_both: int = 0
    source_patterns_matched: dict[str, int] = field(default_factory=dict)
    sink_patterns_matched: dict[str, int] = field(default_factory=dict)
    discard_reasons: dict[str, int] = field(default_factory=dict)

    def record_discard(self, reason: str) -> None:
        """Record why a candidate was discarded at this level."""
        self.discard_reasons[reason] = self.discard_reasons.get(reason, 0) + 1

    def summary(self) -> str:
        """Return human-readable summary."""
        summary = (
            f"Lines: {self.total_lines_analysed} total, "
            f"{self.lines_with_source_patterns} sources, "
            f"{self.lines_with_sink_patterns} sinks, "
            f"{self.lines_with_both} both"
        )
        if self.discard_reasons:
            reasons_str = "; ".join(f"{k}:{v}" for k, v in self.discard_reasons.items())
            summary += f"; discarded: {reasons_str}"
        return summary


@dataclass
class FileAnalysisMetrics:
    """Metrics for per-file DOM analysis."""

    file_url: str
    file_type: str  # inline, external, bundled
    file_size_bytes: int
    lines_count: int
    is_vendor_code: bool = False
    vendor_markers: list[str] = field(default_factory=list)
    extraction_reason: str = ""  # why this file was extracted
    analysis_result: str = ""  # why no candidates (if any)
    sources_found: list[dict[str, Any]] = field(default_factory=list)
    sinks_found: list[dict[str, Any]] = field(default_factory=list)
    source_analysis: SourceAnalysisMetrics = field(
        default_factory=SourceAnalysisMetrics
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return {
            "file_url": self.file_url,
            "file_type": self.file_type,
            "size_bytes": self.file_size_bytes,
            "lines": self.lines_count,
            "is_vendor": self.is_vendor_code,
            "vendor_markers": self.vendor_markers,
            "extraction_reason": self.extraction_reason,
            "analysis_result": self.analysis_result,
            "sources_count": len(self.sources_found),
            "sinks_count": len(self.sinks_found),
            "metrics": {
                "total_lines": self.source_analysis.total_lines_analysed,
                "with_sources": self.source_analysis.lines_with_source_patterns,
                "with_sinks": self.source_analysis.lines_with_sink_patterns,
                "with_both": self.source_analysis.lines_with_both,
            },
        }


@dataclass
class DOMAnalysisMetrics:
    """Overall metrics for DOM analysis pipeline."""

    pages_crawled: int = 0
    js_files_extracted: int = 0
    js_files_vendor_filtered: int = 0
    js_files_analysed: int = 0
    total_lines_analysed: int = 0
    dom_sources_detected: int = 0
    dom_sinks_detected: int = 0
    source_sink_pairs: int = 0
    candidates_generated: int = 0
    candidates_discarded: int = 0
    file_metrics: list[FileAnalysisMetrics] = field(default_factory=list)
    discard_reasons: dict[str, int] = field(default_factory=dict)

    def record_discard(self, reason: str) -> None:
        """Record why a candidate was discarded."""
        self.discard_reasons[reason] = self.discard_reasons.get(reason, 0) + 1
        self.candidates_discarded += 1

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return {
            "pages_crawled": self.pages_crawled,
            "js_files_extracted": self.js_files_extracted,
            "js_files_vendor_filtered": self.js_files_vendor_filtered,
            "js_files_analysed": self.js_files_analysed,
            "total_lines_analysed": self.total_lines_analysed,
            "dom_sources_detected": self.dom_sources_detected,
            "dom_sinks_detected": self.dom_sinks_detected,
            "source_sink_pairs": self.source_sink_pairs,
            "candidates_generated": self.candidates_generated,
            "candidates_discarded": self.candidates_discarded,
            "discard_reasons": self.discard_reasons,
            "file_metrics": [f.to_dict() for f in self.file_metrics],
        }

    def summary(self) -> str:
        """Human-readable summary."""
        lines = [
            "DOM Analysis Summary:",
            f"  Pages crawled: {self.pages_crawled}",
            f"  JS files extracted: {self.js_files_extracted}",
            f"  JS files vendor-filtered: {self.js_files_vendor_filtered}",
            f"  JS files analysed: {self.js_files_analysed}",
            f"  Total lines: {self.total_lines_analysed}",
            f"  DOM sources detected: {self.dom_sources_detected}",
            f"  DOM sinks detected: {self.dom_sinks_detected}",
            f"  Source-sink pairs: {self.source_sink_pairs}",
            f"  Candidates generated: {self.candidates_generated}",
            f"  Candidates discarded: {self.candidates_discarded}",
        ]
        if self.discard_reasons:
            lines.append("  Discard reasons:")
            for reason, count in sorted(
                self.discard_reasons.items(), key=lambda x: -x[1]
            ):
                lines.append(f"    - {reason}: {count}")
        return "\n".join(lines)


def log_file_analysis(metrics: FileAnalysisMetrics) -> None:
    """Log detailed analysis for a single file."""
    logger.info(
        "DOM Analysis: %s (%s, %d bytes, %d lines)",
        metrics.file_url,
        metrics.file_type,
        metrics.file_size_bytes,
        metrics.lines_count,
    )

    if metrics.is_vendor_code:
        logger.warning(
            "  → Skipped: vendor code (markers: %s)",
            ", ".join(metrics.vendor_markers),
        )
        return

    logger.debug("  Sources detected: %d", len(metrics.sources_found))
    for source in metrics.sources_found[:5]:  # Log first 5
        logger.debug(
            "    - %s at line %d: %s",
            source.get("type"),
            source.get("line"),
            source.get("snippet", ""),
        )

    logger.debug("  Sinks detected: %d", len(metrics.sinks_found))
    for sink in metrics.sinks_found[:5]:  # Log first 5
        logger.debug(
            "    - %s at line %d: %s",
            sink.get("type"),
            sink.get("line"),
            sink.get("snippet", ""),
        )

    if metrics.analysis_result:
        logger.info("  Analysis result: %s", metrics.analysis_result)


def log_overall_metrics(metrics: DOMAnalysisMetrics) -> None:
    """Log overall metrics."""
    logger.info(metrics.summary())

    # Log files with no candidates
    if metrics.candidates_generated == 0:
        logger.warning(
            "ZERO candidates generated from %d analysed files",
            metrics.js_files_analysed,
        )

        # Show which files were analysed and why they produced no candidates
        logger.warning("File-by-file breakdown:")
        for file_metric in metrics.file_metrics:
            if not file_metric.is_vendor_code:
                logger.warning(
                    "  - %s: %d sources, %d sinks → %s",
                    file_metric.file_url,
                    len(file_metric.sources_found),
                    len(file_metric.sinks_found),
                    file_metric.analysis_result or "no candidates",
                )


def diagnose_source_discovery(js_content: str) -> dict[str, Any]:
    """
    Diagnose why sources might not be detected.

    Checks for common source patterns and variations.
    """
    diagnosis = {
        "total_lines": len(js_content.split("\n")),
        "detected_patterns": [],
        "possible_undetected_sources": [],
    }

    lines = js_content.split("\n")

    # Known patterns
    known_sources = [
        "location.search",
        "location.hash",
        "location.href",
        "document.URL",
        "document.location",
        "window.location",
        "URLSearchParams",
        "new URL(",
        "new URLSearchParams(",
    ]

    # Variations that might not be detected
    possible_undetected = [
        "location\\[",  # location['search']
        "document\\.location",  # document.location
        "window\\.URL",  # window.URL
        "getParameter",  # custom parameter extraction
        "getQueryParam",  # custom function names
        "getSearch",  # aliased functions
        "\\$_GET",  # PHP-style (shouldn't be in JS)
        "window\\.history",  # history-based navigation
        "document\\.referrer",  # referrer source
        "window\\.parent",  # cross-frame access
    ]

    detected = set()
    undetected = []

    for line in lines:
        for pattern in known_sources:
            if pattern in line:
                detected.add(pattern)

        for pattern in possible_undetected:
            import re

            if re.search(pattern, line):
                undetected.append({"pattern": pattern, "line": line.strip()})

    diagnosis["detected_patterns"] = list(detected)
    diagnosis["possible_undetected_sources"] = undetected[:10]  # First 10

    return diagnosis


def diagnose_sink_discovery(js_content: str) -> dict[str, Any]:
    """
    Diagnose why sinks might not be detected.

    Checks for common sink patterns and variations.
    """
    diagnosis = {
        "total_lines": len(js_content.split("\n")),
        "detected_sinks": [],
        "possible_undetected_sinks": [],
    }

    lines = js_content.split("\n")

    # Known sinks
    known_sinks = [
        "innerHTML",
        "outerHTML",
        "textContent",
        "insertAdjacentHTML",
        "eval",
        "Function",
        "setTimeout",
        "setInterval",
        "document.write",
    ]

    # Variations
    possible_undetected = [
        "\\.html\\(",  # jQuery.html()
        "\\.append\\(",  # jQuery.append()
        "\\.prepend\\(",  # jQuery.prepend()
        "\\.after\\(",  # jQuery methods
        "\\.before\\(",  # jQuery methods
        "\\.replaceWith\\(",  # jQuery methods
        "\\.attr\\(",  # getAttribute/setAttribute
        "\\.prop\\(",  # property assignment
        "DOMParser",  # parseFromString
        "template\\.content",  # template content insertion
        "\\.render\\(",  # React.render, Vue.$mount
        "ReactDOM\\.render",  # React
        "\\$mount",  # Vue
    ]

    detected = set()
    undetected = []

    for line in lines:
        for sink in known_sinks:
            if sink in line:
                detected.add(sink)

        for pattern in possible_undetected:
            import re

            if re.search(pattern, line):
                undetected.append({"pattern": pattern, "line": line.strip()})

    diagnosis["detected_sinks"] = list(detected)
    diagnosis["possible_undetected_sinks"] = undetected[:10]  # First 10

    return diagnosis
