"""
evidence-collector node — Phase N
===================================
Persists validated candidate evidence into the EvidenceGraph.
Connects HTTP request/response, reflection snippets, taint paths,
tool observations, and LLM reasoning to the evidence store.

Creates Finding records only when deterministic evidence exists.

Inputs:  validated_candidates (list[dict]),
         scan_id, target_url
Outputs: evidence_ids (list[str]),
         finding_ids  (list[str]),
         finding_count (int)
"""
from __future__ import annotations

import time
from typing import Any

from xscan.core.dag.node_registry import registry
from xscan.errors import MissingEvidenceError
from xscan.evidence.graph import EvidenceGraph
from xscan.nodes.base import ExecutionContext, NodeBase
from xscan.nodes.emitter import NodeEmitter
from xscan.schemas.evidence import EvidenceType
from xscan.schemas.finding import Finding, FindingStatus, FindingType, Severity
from xscan.schemas.xss import ValidationStatus, XSSCandidate


def _severity_from_context(ctx_name: str) -> Severity:
    high_risk = {"html_attribute", "script_string_double", "script_string_single",
                 "script_expression", "html_text"}
    if ctx_name in high_risk:
        return Severity.HIGH
    return Severity.MEDIUM


# Status labels that mean the validators produced evidence.
_PROOF_STATUSES = {
    str(ValidationStatus.VALIDATED),
    str(ValidationStatus.CONFIRMED),
    "confirmed",
}


def _has_reflection(graph: Any) -> bool:
    """True when this candidate recorded an unencoded reflection."""
    return any(n.type == EvidenceType.REFLECTION for n in graph.all_nodes())


def _ensure_scan_row(db: Any, ctx: ExecutionContext) -> None:
    """
    Register the scan before persisting evidence.

    Evidence and findings are foreign-keyed to ``scans(id)``, but a DAG run can
    happen without a scan row — the CLI runs the workflow without touching the
    database. Without this the node dies with "FOREIGN KEY constraint failed"
    and takes the whole scan down with it.
    """
    from xscan.schemas.scan import Scan, ScanProfile, ScanStatus, Target
    from xscan.storage.repositories.scan import ScanRepository

    repo = ScanRepository(db)
    if repo.get(ctx.scan_id):
        return
    target_url = str(ctx.get("target_url", "") or "")
    if not target_url:
        return
    try:
        target = Target.from_url(target_url)
    except Exception:
        return
    try:
        profile = ScanProfile(str(ctx.inputs.get("profile", "balanced")))
    except ValueError:
        profile = ScanProfile.BALANCED
    repo.save(Scan(
        id=ctx.scan_id,
        target=target,
        profile=profile,
        status=ScanStatus.RUNNING,
        no_llm=bool(ctx.no_llm),
    ))


def _finding_type_from_xss_type(xss_type: str) -> FindingType:
    return {
        "reflected":    FindingType.XSS_REFLECTED,
        "stored":       FindingType.XSS_STORED,
        "dom":          FindingType.XSS_DOM,
        "reflected_dom":FindingType.XSS_DOM,
        "stored_dom":   FindingType.XSS_STORED,
    }.get(xss_type, FindingType.XSS_REFLECTED)


@registry.register("evidence-collector")
class EvidenceCollectorNode(NodeBase, NodeEmitter):
    node_type = "evidence-collector"

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        t0 = self.emit_started(ctx)

        validated_raw: list[dict] = ctx.get("validated_candidates", [])
        scan_id:       str        = ctx.scan_id

        evidence_ids: list[str] = []
        finding_ids:  list[str] = []

        # Get DB connection for persistence
        try:
            from xscan.storage.database import get_db
            from xscan.storage.repositories.evidence import EvidenceRepository
            from xscan.storage.repositories.finding import FindingRepository
            db       = get_db()
            ev_repo  = EvidenceRepository(db)
            fin_repo = FindingRepository(db)
            _ensure_scan_row(db, ctx)
        except Exception:
            ev_repo = fin_repo = None

        for raw in validated_raw:
            try:
                c = XSSCandidate.from_dict(raw)
            except Exception:
                continue

            # Only process candidates whose validation produced proof. The
            # status vocabulary differs per stage (IterationStatus while
            # testing, ValidationStatus afterwards), so compare as strings and
            # fall back to the evidence itself rather than trusting a label.
            status = str(raw.get("validation_status") or "").lower()
            if status == ValidationStatus.UNVALIDATED:
                continue

            # Build evidence graph for this candidate
            graph = EvidenceGraph(scan_id=scan_id, db=db if ev_repo else None)

            # HTTP request evidence
            req_node = None
            best_url = raw.get("best_test_url") or raw.get("request_url") or c.url
            if best_url:
                req_node = graph.add_http_request(
                    url=best_url,
                    method=c.method,
                    node_id=ctx.node_id,
                )
                evidence_ids.append(req_node.id)

            # HTTP response / reflection evidence
            obs_list: list[dict] = raw.get("observations", [])
            refl_node = None
            for obs in obs_list:
                if obs.get("payload_reflected") and not obs.get("payload_encoded"):
                    refl_node = graph.add_reflection(
                        url=obs.get("url_sent", best_url),
                        parameter=c.parameter,
                        payload=obs.get("payload", ""),
                        snippet=obs.get("reflection_snippet", "")[:200],
                        parent_id=req_node.id if req_node else None,
                        node_id=ctx.node_id,
                    )
                    evidence_ids.append(refl_node.id)
                    break

            # Taint path evidence (DOM candidates)
            taint_raw = raw.get("taint_path")
            taint_node = None
            if taint_raw:
                taint_node = graph.add_http_request(   # reuse as taint evidence node
                    url=c.url,
                    method="DOM",
                    headers={"note": "taint-path"},
                    body=str(taint_raw)[:300],
                    node_id=ctx.node_id,
                )
                evidence_ids.append(taint_node.id)

            # LLM reasoning (explicitly NOT proof)
            llm_reasoning = raw.get("llm_explanation") or raw.get("llm_reasoning", "")
            if llm_reasoning:
                llm_node = graph.add_llm_reasoning(
                    specialist="context-analyst",
                    summary=llm_reasoning[:80],
                    raw_output=llm_reasoning[:400],
                    node_id=ctx.node_id,
                )
                evidence_ids.append(llm_node.id)

            # Collect all evidence IDs for this candidate
            cand_evidence_ids = [
                n.id for n in graph.all_nodes()
            ]

            if not cand_evidence_ids:
                continue

            # Check deterministic evidence requirement
            has_determ = graph.has_deterministic_evidence(cand_evidence_ids)
            if not has_determ:
                self.emit_progress(
                    ctx,
                    f"  Skip finding for {c.parameter or 'DOM'} — no deterministic evidence",
                )
                continue

            # Build VulnerabilityModel and WHY explanation for every candidate
            # with evidence — not just confirmed ones.
            try:
                from xscan.schemas.vuln_model import build_model_from_candidate
                model = build_model_from_candidate(raw)
                why_lines = model.explain()
                # Store in candidate dict for report node
                raw["vuln_model"] = model.model_dump(mode="json")
                raw["why"] = why_lines
                # Also add an LLM-free reasoning node to the evidence graph
                if why_lines:
                    why_node = graph.add_llm_reasoning(
                        specialist="vuln-model",
                        summary=why_lines[0] if why_lines else "vulnerability model",
                        raw_output="\n".join(why_lines[:20]),
                        node_id=ctx.node_id,
                    )
                    cand_evidence_ids.append(why_node.id)
            except Exception as exc:
                ctx.logger.debug("VulnerabilityModel build failed: %s", exc)

            # A finding needs proof of exploitability, not just a test URL: a
            # recorded reflection, or an explicit confirmation. A DOM candidate
            # that merely reached a sink without executing is not a finding.
            confirmed = bool(raw.get("confirmed")) or status in _PROOF_STATUSES
            if not (confirmed or _has_reflection(graph)):
                self.emit_progress(
                    ctx,
                    f"  Skip finding for {c.parameter or 'DOM'} — "
                    "no reflection or confirmation",
                )
                continue

            # Create Finding (only with deterministic evidence)
            try:
                ca       = c.context_analysis
                ctx_name = ca.context if ca else "unknown"
                severity = _severity_from_context(ctx_name)
                f_type   = _finding_type_from_xss_type(c.xss_type)

                finding = Finding(
                    scan_id=scan_id,
                    type=f_type,
                    severity=severity,
                    status=FindingStatus.CONFIRMED if raw.get("confirmed")
                           else FindingStatus.UNCONFIRMED,
                    url=c.url,
                    parameter=c.parameter,
                    payload=raw.get("best_payload", ""),
                    description=(
                        raw.get("llm_classification")
                        or f"{f_type.value} in {c.parameter or 'DOM'} ({ctx_name})"
                    ),
                    remediation="Encode all user input before rendering in HTML/JS context. Apply CSP.",
                    llm_reasoning=llm_reasoning[:300],
                    evidence_ids=cand_evidence_ids,
                )
                finding_ids.append(finding.id)
                if fin_repo:
                    fin_repo.save(finding)
                self.emit_progress(ctx, f"  Finding created: {finding.id}  {finding.type}  {finding.severity}")

            except MissingEvidenceError as exc:
                ctx.logger.warning("Finding creation skipped: %s", exc)
            except Exception as exc:
                ctx.logger.warning("Finding error: %s", exc)

        ms = (time.monotonic() - t0) * 1000
        self.emit_completed(ctx, metrics={
            "evidence_nodes": len(evidence_ids),
            "findings":       len(finding_ids),
        }, duration_ms=ms)

        return {
            "evidence_ids": evidence_ids,
            "finding_ids":  finding_ids,
            "finding_count":len(finding_ids),
        }
