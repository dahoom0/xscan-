"""
llm-candidate-triage node
==========================
Passes each reflection candidate through CandidateTriageSpecialist.

Rules enforced here:
  - If ctx.no_llm is True, all candidates are passed through unchanged
    (marked as unconfirmed, not as findings).
  - LLM output is opinion only. No Finding is created here.
  - Evidence must be captured by a later validation node.
  - Specialist calls go through LLMGateway — never direct to Ollama.

Inputs:  candidates (list[dict])
Outputs: triaged_candidates (list[dict])  — enriched with LLM analysis
"""
from __future__ import annotations
from typing import Any
from xscan.nodes.base import NodeBase, ExecutionContext
from xscan.core.dag.node_registry import registry


@registry.register("llm-candidate-triage")
class LLMCandidateTriageNode(NodeBase):
    node_type = "llm-candidate-triage"

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        candidates: list[dict] = ctx.get("candidates", [])

        if not candidates:
            ctx.logger.info("llm-candidate-triage: no candidates to analyse")
            return {"triaged_candidates": []}

        if ctx.no_llm:
            ctx.logger.info("llm-candidate-triage: LLM disabled — passing %d candidates through", len(candidates))
            for c in candidates:
                c["llm_skip"] = True
                c["llm_likely_vulnerable"] = None
            return {"triaged_candidates": candidates}

        from xscan.llm.specialists.triage import CandidateTriageSpecialist, TriageInput
        from xscan.skills import skill_manager

        # Load skills relevant to detected technologies + injection context
        techs = ctx.get("technologies", [])
        all_contexts = list({c.get("context", "") for c in candidates})
        skill_manager.load_all()
        relevant_skills = skill_manager.for_context(
            techs=techs,
            context=" ".join(all_contexts),
            category="xss",
        )
        skill_text = skill_manager.render(relevant_skills)
        if relevant_skills and (ctx.config.get("verbose") or True):
            ctx.logger.info(
                "LLM triage loading skills: %s",
                [s.name for s in relevant_skills],
            )

        specialist = CandidateTriageSpecialist(skill_context=skill_text)
        triaged: list[dict] = []

        for i, candidate in enumerate(candidates):
            ctx.logger.debug(
                "LLM triage [%d/%d]  param=%s  url=%s",
                i + 1, len(candidates),
                candidate.get("parameter", "?"),
                candidate.get("url", "?")[:60],
            )
            try:
                # Build encoding summary string
                encoding = candidate.get("encoding", {})
                enc_parts = []
                for char, is_encoded in encoding.items():
                    enc_parts.append(f"'{char}' {'encoded' if is_encoded else 'NOT encoded'}")
                encoding_str = ", ".join(enc_parts) if enc_parts else "not tested"

                # Best working payload
                working = candidate.get("working_payloads", [])
                best_payload = next((p["payload"] for p in working if not p.get("encoded")), "")
                if not best_payload and working:
                    best_payload = working[0].get("payload", "")

                result = specialist.run(TriageInput(
                    scan_id=ctx.scan_id,
                    node_id=ctx.node_id,
                    url=candidate.get("url", ""),
                    parameter=candidate.get("parameter", ""),
                    method=candidate.get("method", "GET"),
                    payload=best_payload or candidate.get("evidence", ""),
                    evidence=candidate.get("evidence", ""),
                    injection_context=candidate.get("context", "unknown"),
                    encoding_info=encoding_str,
                    payload_count=candidate.get("payload_count", 0),
                    working_payloads=working,
                ))
                candidate["llm_likely_vulnerable"] = result.is_likely_vulnerable
                candidate["llm_confidence"]        = result.confidence
                candidate["llm_severity"]          = result.severity
                candidate["llm_xss_type"]          = result.xss_type
                candidate["llm_context"]           = result.context
                candidate["llm_reasoning"]         = result.reasoning
                candidate["llm_encoding_analysis"] = result.encoding_analysis
                candidate["llm_attack_scenario"]   = result.attack_scenario
                candidate["llm_best_payload"]      = result.best_payload
                candidate["llm_alt_payloads"]      = result.alternative_payloads
                candidate["llm_bypass_notes"]      = result.bypass_notes
                candidate["llm_validation_advice"] = result.recommended_validation
                candidate["llm_skip"]              = False
            except Exception as exc:
                ctx.logger.warning("LLM triage failed for candidate %d: %s", i, exc)
                candidate["llm_skip"] = True
                candidate["llm_likely_vulnerable"] = None

            triaged.append(candidate)

        likely = sum(1 for c in triaged if c.get("llm_likely_vulnerable"))
        ctx.logger.info(
            "llm-candidate-triage done  total=%d  likely_vulnerable=%d",
            len(triaged), likely,
        )
        return {"triaged_candidates": triaged}
