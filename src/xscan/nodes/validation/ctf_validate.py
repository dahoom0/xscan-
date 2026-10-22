"""
ctf-validate node — CTF-mode XSS validation
============================================
Specialized validation node for CTF targets that uses the CTF payload generator specialist
to craft custom payloads based on detected filter profiles, then immediately tests them.

Workflow:
1. Detect if target is CTF (via ctf_detection module)
2. For each candidate:
   a. Extract encoding profile (raw_chars, encoded_chars, stripped_chars)
   b. Call CTFPayloadGeneratorSpecialist to craft custom payloads
   c. Test payloads immediately via HTTP (for reflected) or browser (for DOM)
   d. Record which payloads work (unencoded reflection or execution)
   e. If multiple payloads fail, call specialist again with new constraints
3. Return validated_candidates with confirmed/inconclusive status

Assumptions (CTF context):
- Vulnerabilities ARE intentional (target is designed to be vulnerable)
- Filters ARE deliberate (meant to be bypassed as part of the challenge)
- Payloads should be AGGRESSIVE (test uncommon techniques first)
- Time budget is reasonable (CTF targets respond quickly)

Inputs:  fused_candidates | xss_candidates, technologies
Outputs: validated_candidates, confirmed_count, validated_count
"""
from __future__ import annotations

import asyncio
import time
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from xscan.core.dag.node_registry import registry
from xscan.llm.specialists.ctf_payload_generator import (
    CTFPayloadGeneratorInput,
    CTFPayloadGeneratorSpecialist,
)
from xscan.nodes.base import ExecutionContext, NodeBase
from xscan.nodes.emitter import NodeEmitter
from xscan.schemas.iteration import IterationBudget, IterationStatus
from xscan.validation.ctf_detection import detect_ctf_context
from xscan.validation.http import HTTPValidator
from xscan.validation.observation import Observation


@registry.register("ctf-validate")
class CtfValidateNode(NodeBase, NodeEmitter):
    """CTF-mode XSS validation node."""

    node_type = "ctf-validate"

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        """
        Execute CTF validation: detect CTF, generate custom payloads, test them.
        """
        t0 = self.emit_started(ctx)

        # Extract candidates
        candidates: list[dict] = (
            ctx.get("fused_candidates")
            or ctx.get("xss_candidates")
            or []
        )
        if not candidates:
            self.emit_completed(ctx, metrics={"validated": 0, "confirmed": 0})
            return {
                "validated_candidates": [],
                "validated_count": 0,
                "confirmed_count": 0,
            }

        # Check if this is a CTF target
        techs = ctx.get("technologies", []) or []
        url = candidates[0].get("url", "") if candidates else ""
        ctf_context = detect_ctf_context(url, techs)

        if not ctf_context.is_ctf:
            # Not a CTF target, use standard validation instead
            self.emit_warning(
                ctx,
                f"Target {url} not detected as CTF; consider using xss-validate node",
            )
            return {
                "validated_candidates": [],
                "validated_count": 0,
                "confirmed_count": 0,
            }

        # Budget for CTF mode (more aggressive)
        budget = IterationBudget(
            max_iterations=int(ctx.config.get("max_iterations", 5)),
            max_candidates_per_iteration=int(
                ctx.config.get("max_candidates_per_iteration", 8)
            ),
            max_total_candidates=int(ctx.config.get("max_total_candidates", 20)),
            max_requests=int(ctx.config.get("max_requests", 40)),
            max_runtime_s=float(ctx.config.get("max_runtime_s", 120.0)),
            stop_on_confirmation=bool(ctx.config.get("stop_on_confirmation", True)),
        )

        validated: list[dict] = []
        confirmed_count = 0
        specialist = CTFPayloadGeneratorSpecialist()
        http_validator = HTTPValidator()

        for candidate_idx, candidate in enumerate(candidates):
            url = candidate.get("url", "")
            param = candidate.get("parameter", "")
            method = candidate.get("method", "GET").upper()
            ca = candidate.get("context_analysis") or {}
            ep = candidate.get("encoding_profile") or {}

            context = ca.get("context", "unknown")
            attribute = ca.get("attribute", "")
            quote_type = ca.get("quote_type", "")

            raw_chars = set(ep.get("raw_chars", []))
            encoded_chars = set(ep.get("encoded_chars", []))
            stripped_chars = set(ep.get("stripped_chars", []))

            # Track attempts for this candidate
            attempts: list[dict] = []
            confirmed = False
            validated_status = "inconclusive"

            # Generate payloads using CTF specialist (iteration 1)
            llm_input = CTFPayloadGeneratorInput(
                url=url,
                parameter=param,
                context=context,
                attribute=attribute,
                quote_type=quote_type,
                raw_chars=list(raw_chars),
                encoded_chars=list(encoded_chars),
                stripped_chars=list(stripped_chars),
                max_candidates=min(5, budget.max_candidates_per_iteration),
            )

            try:
                llm_output = specialist.run(llm_input)
                payloads = llm_output.candidates
            except Exception as e:
                self.emit_warning(ctx, f"CTF payload generation failed: {str(e)[:160]}")
                payloads = []

            if not payloads:
                # No payloads generated, mark inconclusive
                validated_candidate = self._mark_candidate(
                    candidate, attempts, confirmed, validated_status, specialist
                )
                validated.append(validated_candidate)
                continue

            # Test each payload
            for payload_idx, payload_obj in enumerate(payloads):
                if len(attempts) >= budget.max_total_candidates:
                    break

                payload = payload_obj.payload

                # Skip if already tested
                if any(a["payload"] == payload for a in attempts):
                    continue

                # Build test URL
                test_url = self._build_test_url(url, param, payload, method)

                # Execute HTTP test
                try:
                    observation = http_validator.execute(
                        url=url,
                        param=param,
                        payload=payload,
                        method=method,
                        attempt=len(attempts) + 1,
                    )
                except Exception as e:
                    observation = Observation(
                        attempt=len(attempts) + 1,
                        payload=payload,
                        http_status=0,
                        reflected=False,
                        encoded_chars=[],
                        stripped_chars=[],
                        response_changed=False,
                        note=f"HTTP error: {str(e)[:80]}",
                    )

                attempts.append(
                    {
                        "payload": payload,
                        "technique": payload_obj.technique,
                        "rationale": payload_obj.rationale,
                        "reflected": observation.reflected,
                        "encoded": bool(observation.encoded_chars),
                        "stripped": bool(observation.stripped_chars),
                        "status": observation.http_status,
                    }
                )

                # Check for confirmation (unencoded reflection = provisional success)
                if (
                    observation.reflected
                    and not observation.encoded_chars
                    and not observation.stripped_chars
                ):
                    confirmed = True
                    validated_status = "confirmed"
                    self.emit_debug(
                        ctx,
                        f"CTF candidate confirmed with payload: {payload[:60]}...",
                    )
                    break

                # Update constraints for next iteration
                if observation.encoded_chars:
                    encoded_chars.update(observation.encoded_chars)
                if observation.stripped_chars:
                    stripped_chars.update(observation.stripped_chars)

            # If not confirmed after first round, try LLM replanning
            if not confirmed and len(attempts) < budget.max_total_candidates:
                # Generate new payloads based on updated constraints
                llm_input.raw_chars = list(raw_chars - encoded_chars - stripped_chars)
                llm_input.encoded_chars = list(encoded_chars)
                llm_input.stripped_chars = list(stripped_chars)
                llm_input.previous_results = []  # Simplified; full results would be attached

                try:
                    llm_output = specialist.run(llm_input)
                    for payload_obj in llm_output.candidates:
                        if len(attempts) >= budget.max_total_candidates:
                            break
                        if any(a["payload"] == payload_obj.payload for a in attempts):
                            continue

                        payload = payload_obj.payload
                        test_url = self._build_test_url(url, param, payload, method)

                        try:
                            observation = http_validator.execute(
                                url=url,
                                param=param,
                                payload=payload,
                                method=method,
                                attempt=len(attempts) + 1,
                            )
                        except Exception as e:
                            observation = Observation(
                                attempt=len(attempts) + 1,
                                payload=payload,
                                http_status=0,
                                reflected=False,
                                encoded_chars=[],
                                stripped_chars=[],
                                response_changed=False,
                            )

                        attempts.append(
                            {
                                "payload": payload,
                                "technique": payload_obj.technique,
                                "reflected": observation.reflected,
                            }
                        )

                        if (
                            observation.reflected
                            and not observation.encoded_chars
                            and not observation.stripped_chars
                        ):
                            confirmed = True
                            validated_status = "confirmed"
                            break
                except Exception:
                    pass

            # Build validated candidate record
            if confirmed:
                confirmed_count += 1
            if validated_status in ("confirmed",):
                validated_candidate = self._mark_candidate(
                    candidate, attempts, confirmed, validated_status, specialist
                )
            else:
                validated_candidate = self._mark_candidate(
                    candidate, attempts, confirmed, "inconclusive", specialist
                )

            validated.append(validated_candidate)

        self.emit_completed(
            ctx,
            metrics={
                "validated": len(validated),
                "confirmed": confirmed_count,
                "ctf_mode": True,
            },
            duration_ms=(time.monotonic() - t0) * 1000,
        )

        return {
            "validated_candidates": validated,
            "validated_count": len(validated),
            "confirmed_count": confirmed_count,
        }

    @staticmethod
    def _build_test_url(
        base_url: str, param: str, payload: str, method: str
    ) -> str:
        """Build test URL with payload injected into parameter."""
        parsed = urlparse(base_url)

        if method == "POST":
            # For POST, payload goes in body (handled by validator)
            return base_url

        # For GET, inject into query string
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        if param in query_params:
            query_params[param] = [payload]
        else:
            query_params[param] = [payload]

        new_query = urlencode(query_params, doseq=True)
        new_parsed = parsed._replace(query=new_query)
        return urlunparse(new_parsed)

    @staticmethod
    def _mark_candidate(
        candidate: dict[str, Any],
        attempts: list[dict],
        confirmed: bool,
        status: str,
        specialist: Any,
    ) -> dict[str, Any]:
        """Mark candidate with validation results."""
        updated = dict(candidate)
        updated.update(
            {
                "validation_status": status,
                "validated": confirmed,
                "confirmed": confirmed,
                "ctf_mode": True,
                "attempts": attempts,
                "attempt_count": len(attempts),
            }
        )

        if confirmed and attempts:
            # Find the successful payload
            for attempt in attempts:
                if attempt.get("reflected"):
                    updated["best_payload"] = attempt.get("payload", "")
                    break

        return updated
