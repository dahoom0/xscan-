"""
CandidateTriageSpecialist
=========================
Analyses an XSS candidate and produces a structured triage result.

Migrated from prototype llm/analyst.py into the specialist framework.

IMPORTANT: Output is analysis + opinion only.
A Finding is NOT created here — evidence must be captured first by the
validation node before any Finding is constructed.
"""
from __future__ import annotations

from typing import Literal

from pydantic import Field

from xscan.llm.specialists.base import SpecialistBase
from xscan.schemas.llm import SpecialistInput, SpecialistOutput

_SYSTEM = """\
You are a web application security expert specialising in XSS vulnerabilities.
Analyse the provided XSS candidate and respond ONLY with a single valid JSON object.
Do not include any text outside the JSON block.
"""

_PROMPT_TEMPLATE = """\
XSS Candidate — Deep Analysis:

URL: {url}
Parameter: {parameter}
Method: {method}
Injection context: {context}
Encoding detected: {encoding}
Working payloads found: {payload_count}
Best working payload: {best_payload}
Best payload snippet (how it appears in response):
{evidence}

Analyse this candidate thoroughly and respond with JSON only:
{{
  "is_likely_vulnerable": true or false,
  "confidence": "high" | "medium" | "low",
  "severity": "critical" | "high" | "medium" | "low",
  "xss_type": "reflected" | "stored" | "dom" | "unknown",
  "context": "precise description of injection context",
  "encoding_analysis": "describe what characters are/aren't encoded and why this matters",
  "attack_scenario": "describe how an attacker would exploit this",
  "best_payload": "the most effective payload to use for this specific context",
  "alternative_payloads": ["list", "of", "2-3", "alternative", "payloads"],
  "bypass_notes": "any filter bypass techniques needed, or empty string",
  "reasoning": "detailed explanation of the vulnerability",
  "remediation": "specific fix for this exact context"
}}
"""


class TriageInput(SpecialistInput):
    url: str
    parameter: str
    method: str = "GET"
    payload: str = ""                       # canary evidence string
    evidence: str = ""
    injection_context: str = "unknown"
    encoding_info: str = ""
    payload_count: int = 0
    working_payloads: list[dict] = Field(default_factory=list)


class TriageOutput(SpecialistOutput):
    is_likely_vulnerable: bool = False
    confidence: Literal["high", "medium", "low"] = "low"
    severity: Literal["critical", "high", "medium", "low"] = "medium"
    xss_type: Literal["reflected", "stored", "dom", "unknown"] = "unknown"
    context: str = ""
    encoding_analysis: str = ""
    attack_scenario: str = ""
    best_payload: str = ""
    alternative_payloads: list[str] = Field(default_factory=list)
    bypass_notes: str = ""
    recommended_validation: str = ""

    specialist: str = "candidate-triage"


class CandidateTriageSpecialist(SpecialistBase[TriageInput, TriageOutput]):
    specialist_name = "candidate-triage"
    system_prompt = _SYSTEM
    default_timeout = 120

    def __init__(self, skill_context: str = "") -> None:
        self._skill_context = skill_context

    def build_prompt(self, input_data: TriageInput) -> str:
        skill_section = f"\n{self._skill_context}\n" if self._skill_context else ""
        # Pick the best working payload (first unencoded one, else first)
        payloads = input_data.context.get("working_payloads", []) if hasattr(input_data, "context") and isinstance(input_data.context, dict) else []
        best_payload = ""
        for p in payloads:
            if not p.get("encoded", True):
                best_payload = p.get("payload", "")
                break
        if not best_payload and payloads:
            best_payload = payloads[0].get("payload", "")
        if not best_payload:
            best_payload = input_data.payload

        encoding_info = input_data.encoding_info or "unknown"

        return skill_section + _PROMPT_TEMPLATE.format(
            url=input_data.url,
            parameter=input_data.parameter,
            method=input_data.method,
            context=input_data.injection_context,
            encoding=encoding_info,
            payload_count=input_data.payload_count,
            best_payload=best_payload,
            evidence=input_data.evidence[:500],
        )

    def parse_output(self, raw_text: str) -> TriageOutput:
        data = self._extract_json(raw_text)
        return TriageOutput(
            scan_id="-",
            is_likely_vulnerable=bool(data.get("is_likely_vulnerable", False)),
            confidence=data.get("confidence", "low"),
            severity=data.get("severity", "medium"),
            xss_type=data.get("xss_type", "unknown"),
            context=data.get("context", ""),
            encoding_analysis=data.get("encoding_analysis", ""),
            attack_scenario=data.get("attack_scenario", ""),
            best_payload=data.get("best_payload", ""),
            alternative_payloads=data.get("alternative_payloads", []),
            bypass_notes=data.get("bypass_notes", ""),
            reasoning=data.get("reasoning", ""),
            recommended_validation=data.get("remediation", data.get("recommended_validation", "")),
        )
