"""
EvidenceGraph
=============
Captures and links all evidence for a scan.

Architecture:
  EvidenceGraph (in-memory + persisted)
    │
    ├── EvidenceNode  (observation with provenance)
    │     └── Artifact (binary/text files)
    │
    └── EvidenceEdge  (relationship between nodes)
          e.g. "request → response → reflection → dom-sink"

Rules:
  - Every Finding MUST reference at least one EvidenceNode ID.
  - LLM reasoning is stored as an EvidenceNode of type TOOL_OUTPUT —
    it is NOT treated as proof.
  - Confirmed findings require at minimum an HTTP_RESPONSE + REFLECTION node.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from xscan.schemas.evidence import Artifact, EvidenceEdge, EvidenceNode, EvidenceType

if TYPE_CHECKING:
    from xscan.storage.database import Database

logger = logging.getLogger(__name__)


class EvidenceGraph:
    """
    In-memory evidence graph with SQLite persistence.

    Usage::

        graph = EvidenceGraph(scan_id="A1B2", db=db)

        req_node = graph.add_http_request("https://example.com/search?q=<script>",
                                          method="GET", headers={}, body=None)
        resp_node = graph.add_http_response(200, body="...<script>...",
                                            parent_id=req_node.id)
        refl_node = graph.add_reflection(parameter="q", payload="<script>",
                                          snippet="...<script>...",
                                          parent_id=resp_node.id)

        # When creating a Finding, pass [refl_node.id]
    """

    def __init__(self, scan_id: str, db: "Database | None" = None) -> None:
        self.scan_id = scan_id
        self._db = db
        self._nodes: dict[str, EvidenceNode] = {}
        self._edges: list[EvidenceEdge] = []

        if db:
            from xscan.storage.repositories.evidence import EvidenceRepository
            self._repo: "EvidenceRepository | None" = EvidenceRepository(db)
        else:
            self._repo = None

    # ------------------------------------------------------------------
    # Node creation helpers (typed per evidence type)
    # ------------------------------------------------------------------

    def add_http_request(
        self,
        url: str,
        method: str = "GET",
        headers: dict | None = None,
        body: str | None = None,
        node_id: str = "",
        parent_id: str | None = None,
    ) -> EvidenceNode:
        node = EvidenceNode(
            scan_id=self.scan_id,
            node_id=node_id,
            type=EvidenceType.HTTP_REQUEST,
            url=url,
            summary=f"{method} {url[:80]}",
            data={"method": method, "headers": headers or {}, "body": body or ""},
            parent_ids=[parent_id] if parent_id else [],
        )
        return self._add(node)

    def add_http_response(
        self,
        status_code: int,
        url: str,
        headers: dict | None = None,
        body: str = "",
        elapsed_ms: float = 0.0,
        parent_id: str | None = None,
        node_id: str = "",
    ) -> EvidenceNode:
        node = EvidenceNode(
            scan_id=self.scan_id,
            node_id=node_id,
            type=EvidenceType.HTTP_RESPONSE,
            url=url,
            summary=f"HTTP {status_code}  {url[:60]}",
            data={
                "status_code": status_code,
                "headers": headers or {},
                "body_snippet": body[:500],
                "elapsed_ms": elapsed_ms,
            },
            parent_ids=[parent_id] if parent_id else [],
        )
        return self._add(node)

    def add_reflection(
        self,
        url: str,
        parameter: str,
        payload: str,
        snippet: str,
        parent_id: str | None = None,
        node_id: str = "",
    ) -> EvidenceNode:
        node = EvidenceNode(
            scan_id=self.scan_id,
            node_id=node_id,
            type=EvidenceType.REFLECTION,
            url=url,
            summary=f"Reflection of '{payload[:30]}' in param '{parameter}'",
            data={
                "parameter": parameter,
                "payload": payload,
                "snippet": snippet[:400],
            },
            parent_ids=[parent_id] if parent_id else [],
        )
        return self._add(node)

    def add_llm_reasoning(
        self,
        specialist: str,
        summary: str,
        raw_output: str,
        parent_id: str | None = None,
        node_id: str = "",
    ) -> EvidenceNode:
        """
        Store LLM reasoning as evidence.

        NOTE: This is analysis / opinion only.
        It does NOT constitute proof of a vulnerability.
        """
        node = EvidenceNode(
            scan_id=self.scan_id,
            node_id=node_id,
            type=EvidenceType.TOOL_OUTPUT,
            summary=f"LLM[{specialist}]: {summary[:80]}",
            data={
                "specialist": specialist,
                "raw_output": raw_output[:1000],
                "note": "LLM analysis only — not deterministic proof",
            },
            parent_ids=[parent_id] if parent_id else [],
        )
        return self._add(node)

    def add_dom_snapshot(
        self,
        url: str,
        dom_html: str,
        parent_id: str | None = None,
        node_id: str = "",
    ) -> EvidenceNode:
        node = EvidenceNode(
            scan_id=self.scan_id,
            node_id=node_id,
            type=EvidenceType.DOM_SNAPSHOT,
            url=url,
            summary=f"DOM snapshot  {url[:60]}",
            data={"dom_snippet": dom_html[:2000]},
            parent_ids=[parent_id] if parent_id else [],
        )
        return self._add(node)

    # ------------------------------------------------------------------
    # Edge creation
    # ------------------------------------------------------------------

    def link(self, from_id: str, to_id: str, label: str = "") -> EvidenceEdge:
        edge = EvidenceEdge(from_id=from_id, to_id=to_id, label=label)
        self._edges.append(edge)
        if self._repo:
            self._repo.save_edge(edge)
        return edge

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def node(self, evidence_id: str) -> EvidenceNode | None:
        return self._nodes.get(evidence_id)

    def all_nodes(self) -> list[EvidenceNode]:
        return list(self._nodes.values())

    def all_edges(self) -> list[EvidenceEdge]:
        return list(self._edges)

    def chain(self, from_id: str) -> list[EvidenceNode]:
        """Return all nodes reachable from from_id via edges."""
        visited: set[str] = set()
        result: list[EvidenceNode] = []
        stack = [from_id]
        while stack:
            nid = stack.pop()
            if nid in visited:
                continue
            visited.add(nid)
            node = self._nodes.get(nid)
            if node:
                result.append(node)
                stack.extend(node.parent_ids)
        return result

    # ------------------------------------------------------------------
    # Validation helpers (used before Finding creation)
    # ------------------------------------------------------------------

    def has_deterministic_evidence(self, evidence_ids: list[str]) -> bool:
        """
        Return True if the evidence set contains at least one
        deterministic evidence type (HTTP_RESPONSE, REFLECTION, DOM_SNAPSHOT).
        LLM reasoning alone does NOT qualify.
        """
        deterministic = {
            EvidenceType.HTTP_RESPONSE,
            EvidenceType.HTTP_REQUEST,
            EvidenceType.REFLECTION,
            EvidenceType.DOM_SNAPSHOT,
            EvidenceType.SCREENSHOT,
            EvidenceType.CONSOLE_LOG,
            EvidenceType.NETWORK_LOG,
        }
        for eid in evidence_ids:
            node = self._nodes.get(eid)
            if node and node.type in deterministic:
                return True
        return False

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _add(self, node: EvidenceNode) -> EvidenceNode:
        self._nodes[node.id] = node
        if self._repo:
            self._repo.save_node(node)
        logger.debug("Evidence captured  id=%s  type=%s", node.id, node.type)
        return node
