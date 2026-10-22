"""
Provenance helpers — verify evidence chains before Finding creation.

Rule: A Finding may only be created when this check passes.
"""
from __future__ import annotations
from xscan.errors import MissingEvidenceError
from xscan.evidence.graph import EvidenceGraph


def assert_finding_evidence(
    graph: EvidenceGraph,
    evidence_ids: list[str],
    url: str = "",
) -> None:
    """
    Assert that evidence_ids contains at least one deterministic
    evidence node before a Finding is constructed.

    Raises:
        MissingEvidenceError — if evidence is empty or only LLM reasoning.
    """
    if not evidence_ids:
        raise MissingEvidenceError(
            f"Cannot create Finding for {url!r}: no evidence IDs provided."
        )
    if not graph.has_deterministic_evidence(evidence_ids):
        raise MissingEvidenceError(
            f"Cannot create Finding for {url!r}: evidence set contains only "
            "LLM reasoning. Deterministic evidence (HTTP response, reflection, "
            "DOM snapshot) is required."
        )
