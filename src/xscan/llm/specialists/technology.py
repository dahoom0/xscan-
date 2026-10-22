"""TechnologySpecialist — identifies frameworks from HTTP evidence."""
from __future__ import annotations
from pydantic import Field
from xscan.llm.specialists.base import SpecialistBase
from xscan.schemas.llm import SpecialistInput, SpecialistOutput

_SYSTEM = "You are a web technology fingerprinting expert. Respond only with valid JSON."

_PROMPT = """\
Identify the technology stack from this HTTP evidence.

Server header: {server}
X-Powered-By: {powered_by}
Cookies: {cookies}
HTML snippet (first 800 chars): {html_snippet}

Respond with JSON only:
{{
  "frameworks": ["list", "of", "frameworks"],
  "server": "server software",
  "language": "backend language",
  "cms": "CMS if detected or null",
  "confidence": "high" | "medium" | "low",
  "reasoning": "brief explanation"
}}
"""


class TechInput(SpecialistInput):
    server: str = ""
    powered_by: str = ""
    cookies: str = ""
    html_snippet: str = ""


class TechOutput(SpecialistOutput):
    frameworks: list[str] = Field(default_factory=list)
    server: str = ""
    language: str = ""
    cms: str | None = None
    specialist: str = "technology"


class TechnologySpecialist(SpecialistBase[TechInput, TechOutput]):
    specialist_name = "technology"
    system_prompt = _SYSTEM
    default_timeout = 60

    def build_prompt(self, input_data: TechInput) -> str:
        return _PROMPT.format(
            server=input_data.server,
            powered_by=input_data.powered_by,
            cookies=input_data.cookies[:200],
            html_snippet=input_data.html_snippet[:800],
        )

    def parse_output(self, raw_text: str) -> TechOutput:
        data = self._extract_json(raw_text)
        return TechOutput(
            scan_id="-",
            frameworks=data.get("frameworks", []),
            server=data.get("server", ""),
            language=data.get("language", ""),
            cms=data.get("cms"),
            reasoning=data.get("reasoning", ""),
            confidence=float({"high": 0.9, "medium": 0.6, "low": 0.3}.get(
                data.get("confidence", "low"), 0.3
            )),
        )
