"""
XSS Knowledge Registry
======================
Structured, data-driven knowledge about XSS sources, sinks, contexts,
and test strategies. Loaded once at startup; never modified at runtime.

Usage::

    from xscan.knowledge import xss_knowledge
    sources  = xss_knowledge.sources
    sinks    = xss_knowledge.sinks
    strategy = xss_knowledge.strategy_for_context("html_attribute")
    payloads = xss_knowledge.payloads_for(source_type="hash", sink_label="jQuery $()")
"""
from xscan.knowledge.registry import XSSKnowledgeRegistry, xss_knowledge

__all__ = ["xss_knowledge", "XSSKnowledgeRegistry"]
