"""
SpecialistBase
==============
Base class for all LLM specialists.

Contract:
  - Receives a typed Input (Pydantic model)
  - Calls LLMGateway — never an LLM provider directly
  - Returns a typed Output (Pydantic model)
  - Parses and validates the LLM's JSON response
  - NEVER declares a finding confirmed — that requires deterministic evidence
  - NEVER issues network requests — uses only data passed in via Input

If the LLM returns invalid JSON or fails validation, SpecialistOutputError
is raised with the raw response preserved for debugging.
"""
from __future__ import annotations

import json
import logging
import re
from abc import ABC, abstractmethod
from typing import Generic, TypeVar

from pydantic import BaseModel, ValidationError

from xscan.config import get_settings
from xscan.errors import LLMError, SpecialistOutputError
from xscan.llm.gateway import get_gateway
from xscan.schemas.llm import LLMRequest, LLMResponse, SpecialistInput, SpecialistOutput

In = TypeVar("In", bound=SpecialistInput)
Out = TypeVar("Out", bound=SpecialistOutput)

logger = logging.getLogger(__name__)


def _balance_json(fragment: str) -> str:
    """
    Close a JSON object that was truncated mid-generation: track string
    literals and bracket depth, then append the missing closers. Dangling
    trailing commas are dropped because they are never legal at a truncation
    point that still parses.
    """
    out: list[str] = []
    stack: list[str] = []
    in_string = False
    escaped = False
    for ch in fragment:
        out.append(ch)
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "{[":
            stack.append(ch)
        elif ch in "}]":
            if stack:
                stack.pop()
    if in_string:
        if escaped:
            # Dangling backslash before the (missing) closing quote would
            # escape it — drop the backslash, then close the string.
            out.pop()
        out.append('"')
    while stack:
        out.append("}" if stack.pop() == "{" else "]")
    return re.sub(r",\s*([}\]]|$)", r"\1", "".join(out))


class SpecialistBase(ABC, Generic[In, Out]):
    """
    Abstract base for all LLM specialists.

    Subclasses must implement:
      specialist_name: str
      system_prompt: str
      build_prompt(input) -> str
      parse_output(raw_text) -> Out
    """

    specialist_name: str = "unnamed"
    system_prompt: str = "You are a web security expert. Respond only with valid JSON."
    default_timeout: int = 120
    # Subclasses can override max_tokens; None = use settings default
    default_max_tokens: int | None = None

    # One corrective follow-up is allowed when the model's reply is not
    # parseable JSON — a second chance costs one call and rescues models that
    # preface their JSON with prose, wrap it in fences, or truncate it.
    json_retries: int = 1

    def run(self, input_data: In) -> Out:
        """Execute the specialist. Called by DAG nodes."""
        settings = get_settings()
        model = settings.llm.model

        prompt = self.build_prompt(input_data)
        request = LLMRequest(
            model=model,
            system_prompt=self.system_prompt,
            user_prompt=prompt,
            temperature=settings.llm.temperature,
            max_tokens=self.default_max_tokens or settings.llm.max_tokens,
            timeout=self.default_timeout,
            specialist=self.specialist_name,
            scan_id=input_data.scan_id,
            node_id=input_data.node_id,
            json_mode=True,
        )

        gateway = get_gateway()
        response = gateway.complete(request)

        if not response.success:
            raise LLMError(
                f"Specialist '{self.specialist_name}' got empty response from LLM."
            )

        attempt_prompt = prompt
        parse_exc: Exception | None = None
        total_attempts = self.json_retries + 1
        for attempt in range(1, total_attempts + 1):
            logger.debug(
                "Specialist %s raw LLM response (first 500 chars): %r",
                self.specialist_name, response.raw_text[:500],
            )
            try:
                output = self.parse_output(response.raw_text)
                output.raw_response = response.raw_text
                output.llm_request_id = request.id
                return output
            except (SpecialistOutputError, ValidationError, json.JSONDecodeError,
                    TypeError, AttributeError) as exc:
                parse_exc = exc
                if attempt == total_attempts:
                    break
                # Corrective follow-up: show the model its own broken reply.
                attempt_prompt = (
                    "Your previous reply was not valid JSON, so it was rejected.\n"
                    "Reply again with ONLY a single valid JSON object — no prose, "
                    "no markdown fences, no code blocks — matching the requested schema.\n\n"
                    "Your previous reply was:\n"
                    f"{response.raw_text[:1000]}\n\n"
                    "Original task:\n" + prompt
                )
                request = request.model_copy(update={
                    "user_prompt": attempt_prompt, "temperature": 0.0,
                })
                response = gateway.complete(request)
                if not response.success:
                    raise LLMError(
                        f"Specialist '{self.specialist_name}' got empty response from LLM."
                    )

        raise SpecialistOutputError(
            f"Specialist '{self.specialist_name}' output failed validation: {parse_exc}",
            raw=response.raw_text,
            specialist=self.specialist_name,
        )

    @abstractmethod
    def build_prompt(self, input_data: In) -> str: ...

    @abstractmethod
    def parse_output(self, raw_text: str) -> Out: ...

    @staticmethod
    def _extract_json(text: str) -> dict:
        """
        Extract the first JSON object from a possibly-prose LLM response.

        Handles markdown code fences, leading/trailing prose, thinking tags,
        trailing commas, smart quotes, and output truncated mid-object
        (bracket balancing). Raises SpecialistOutputError when nothing parses.
        """
        def _loads(candidate: str) -> dict | None:
            if not candidate or not candidate.strip():
                return None
            try:
                data = json.loads(candidate)
                return data if isinstance(data, dict) else None
            except json.JSONDecodeError:
                return None

        # Strip <think>...</think> blocks (some models emit internal monologue)
        cleaned = re.sub(r"<think>[\s\S]*?</think>", "", text, flags=re.I).strip()

        # Strip markdown code fences: ```json ... ``` or ``` ... ```
        fenced = re.findall(r"```(?:json)?\s*([\s\S]*?)```", cleaned)
        cleaned = re.sub(r"```(?:json)?\s*([\s\S]*?)```", r"\1", cleaned).strip()

        for candidate in (cleaned, text, *fenced):
            data = _loads(candidate)
            if data is not None:
                return data

        # Common single-token mutations: trailing commas, smart quotes.
        repaired = cleaned.replace("\u201c", '"').replace("\u201d", '"') \
            .replace("\u2018", "'").replace("\u2019", "'")
        repaired = re.sub(r",\s*([}\]])", r"\1", repaired)
        data = _loads(repaired)
        if data is not None:
            return data

        # Prose-wrapped JSON: attempt a single-object decode from EVERY "{" —
        # braces inside prose ("the {short} version:") must not derail it.
        decoder = json.JSONDecoder()
        for idx in (m.start() for m in re.finditer(r"\{", text)):
            try:
                data, _ = decoder.raw_decode(text, idx)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict):
                return data

        # Truncated mid-object: balance brackets and strings from the first
        # and last "{" and drop dangling trailing commas.
        if "{" in text:
            for start in (text.find("{"), text.rfind("{")):
                data = _loads(_balance_json(text[start:]))
                if data is not None:
                    return data

        raise SpecialistOutputError(
            "No valid JSON found in LLM response",
            raw=text[:500],
        )
