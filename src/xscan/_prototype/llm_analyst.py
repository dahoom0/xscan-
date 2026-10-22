"""
XScan LLM Analyst
=================
Uses the active Ollama model to analyse XSS candidates and produce
structured findings with severity and remediation advice.

Each candidate gets a prompt asking:
  1. Is this a real XSS vulnerability?
  2. What is the severity?
  3. What is the context (HTML body, attribute, script, etc.)?
  4. Recommended remediation.

Output is plain structured text parsed into a dict.
"""
from __future__ import annotations

import json
import re
from typing import Optional

from xscan.core.models import Finding, FindingType, Severity, XssCandidate
from xscan.llm.ollama import OllamaClient, _post, DEFAULT_BASE_URL

_SYSTEM_PROMPT = """\
You are a web application security expert specializing in XSS vulnerabilities.
Analyze the given XSS candidate and respond ONLY with valid JSON.
No explanations outside the JSON block.
"""

_ANALYSIS_PROMPT = """\
XSS Candidate Analysis:

URL: {url}
Parameter: {param}
Method: {method}
Payload: {payload}
Response snippet containing payload:
{evidence}

Analyze this candidate and respond with JSON only:
{{
  "is_vulnerable": true or false,
  "confidence": "high" | "medium" | "low",
  "severity": "critical" | "high" | "medium" | "low",
  "xss_type": "reflected" | "stored" | "dom" | "unknown",
  "context": "e.g. HTML body, attribute value, script block, etc.",
  "description": "one or two sentence description",
  "remediation": "specific fix recommendation"
}}
"""


class LLMAnalyst:
    """
    Analyse XssCandidate objects using the local Ollama model.

    Usage::

        analyst = LLMAnalyst(model="qwen3:14b")
        finding = analyst.analyse(candidate)
    """

    def __init__(
        self,
        model: str = "qwen3:14b",
        base_url: str = DEFAULT_BASE_URL,
        timeout: int = 120,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._id_counter = 0

    def analyse(self, candidate: XssCandidate) -> Optional[Finding]:
        """
        Analyse one candidate. Returns a Finding if the LLM judges it
        vulnerable, or None if it considers it a false positive.
        """
        prompt = _ANALYSIS_PROMPT.format(
            url=candidate.url,
            param=candidate.parameter,
            method=candidate.method,
            payload=candidate.payload,
            evidence=candidate.evidence[:400],
        )
        raw = self._call(prompt)
        if not raw:
            # LLM unavailable — promote candidate to finding automatically
            return self._auto_finding(candidate)

        parsed = self._parse_json(raw)
        if not parsed:
            return self._auto_finding(candidate)

        if not parsed.get("is_vulnerable", True):
            return None  # LLM says false positive

        self._id_counter += 1
        severity_str = parsed.get("severity", "medium").lower()
        severity = Severity(severity_str) if severity_str in Severity._value2member_map_ else Severity.MEDIUM

        xss_type_str = parsed.get("xss_type", "reflected").lower()
        ftype_map = {
            "reflected": FindingType.XSS_REFLECTED,
            "stored":    FindingType.XSS_STORED,
            "dom":       FindingType.XSS_DOM,
        }
        ftype = ftype_map.get(xss_type_str, FindingType.XSS_REFLECTED)

        return Finding(
            id=f"XSS-{self._id_counter:03d}",
            type=ftype,
            severity=severity,
            url=candidate.url,
            parameter=candidate.parameter,
            payload=candidate.payload,
            evidence=candidate.evidence,
            description=parsed.get("description", ""),
            remediation=parsed.get("remediation", ""),
            llm_analysis=(
                f"Confidence: {parsed.get('confidence','?')} | "
                f"Context: {parsed.get('context','?')}"
            ),
            request=candidate.request,
            response=candidate.response,
        )

    def analyse_batch(
        self,
        candidates: list[XssCandidate],
        progress_cb=None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for i, candidate in enumerate(candidates, 1):
            if progress_cb:
                progress_cb(
                    f"  LLM analysing [{i}/{len(candidates)}] "
                    f"{candidate.parameter} @ {candidate.url[:50]}"
                )
            finding = self.analyse(candidate)
            if finding:
                findings.append(finding)
        return findings

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _call(self, prompt: str) -> str:
        """Call Ollama generate endpoint. Returns raw text or ''."""
        try:
            data = _post(
                f"{self.base_url}/api/generate",
                {
                    "model":  self.model,
                    "prompt": f"{_SYSTEM_PROMPT}\n\n{prompt}",
                    "stream": False,
                    "options": {"temperature": 0.1},
                },
                timeout=self.timeout,
            )
            return data.get("response", "").strip()
        except Exception:
            return ""

    @staticmethod
    def _parse_json(text: str) -> Optional[dict]:
        """Extract and parse JSON from LLM response."""
        # Try to find a JSON block
        match = re.search(r'\{[^{}]+\}', text, re.DOTALL)
        if not match:
            return None
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            return None

    def _auto_finding(self, candidate: XssCandidate) -> Finding:
        """Fallback when LLM is unavailable — promote candidate directly."""
        self._id_counter += 1
        return Finding(
            id=f"XSS-{self._id_counter:03d}",
            type=FindingType.XSS_REFLECTED,
            severity=Severity.HIGH,
            url=candidate.url,
            parameter=candidate.parameter,
            payload=candidate.payload,
            evidence=candidate.evidence,
            description=(
                f"Reflected XSS in parameter '{candidate.parameter}'. "
                f"Payload was reflected unencoded in the response."
            ),
            remediation=(
                "Encode all user-supplied input before rendering in HTML context. "
                "Use a Content Security Policy to restrict script execution."
            ),
            llm_analysis="[LLM unavailable — automated detection]",
            request=candidate.request,
            response=candidate.response,
        )
